package account

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/config"
	"github.com/marsolab/plainq/internal/server/middleware"
	"github.com/marsolab/servekit/logkit"
	"github.com/maxatome/go-testdeep/td"
)

// directoryStorage is a Storage that only answers the directory calls; every
// other method fails loudly so a test that reaches one is a test that is
// exercising something it did not mean to.
type directoryStorage struct {
	Storage

	page      *DirectoryPage
	pageErr   error
	lastQuery DirectoryQuery

	orgID  string
	orgErr error
}

func (s *directoryStorage) ListDirectory(_ context.Context, query DirectoryQuery) (*DirectoryPage, error) {
	s.lastQuery = query

	if s.pageErr != nil {
		return nil, s.pageErr
	}

	return s.page, nil
}

func (s *directoryStorage) GetAccountOrgID(_ context.Context, _ string) (string, error) {
	if s.orgErr != nil {
		return "", s.orgErr
	}

	return s.orgID, nil
}

func newDirectoryService(t *testing.T, cfg config.Config, storage Storage) *Service {
	t.Helper()

	return NewService(&cfg, logkit.NewNop(), nil, nil, storage)
}

func samplePage() *DirectoryPage {
	return &DirectoryPage{
		Users: []DirectoryEntry{
			{
				UserID:    "01K0Q6M4A1",
				Email:     "maya@acme.test",
				Verified:  true,
				CreatedAt: time.Unix(1_700_000_000, 0).UTC(),
				UpdatedAt: time.Unix(1_700_000_000, 0).UTC(),
				Roles:     []DirectoryRole{{RoleID: "role-1", RoleName: "admin"}},
				Teams:     []DirectoryTeam{},
			},
		},
		Total: 1,
	}
}

func TestDirectoryListsAccounts(t *testing.T) {
	storage := &directoryStorage{page: samplePage()}
	service := newDirectoryService(t, config.Config{}, storage)

	rec := httptest.NewRecorder()
	service.Directory().ServeHTTP(
		rec,
		httptest.NewRequest(http.MethodGet, "/users?limit=25&cursor=abc&search=maya", nil),
	)

	td.Require(t).Cmp(rec.Code, http.StatusOK)

	var got DirectoryPage
	td.Require(t).CmpNoError(json.NewDecoder(rec.Body).Decode(&got), "decode response")

	td.Cmp(t, got.Total, int64(1))
	td.Cmp(t, got.Users[0].Email, "maya@acme.test")
	td.Cmp(t, storage.lastQuery, DirectoryQuery{Search: "maya", Cursor: "abc", Limit: 25},
		"query parameters reach storage unchanged")
}

// The response is built from an explicit field list, so a password can only
// appear if somebody adds it on purpose. Serialising a full entry and checking
// the keys is what makes that a test rather than a claim.
func TestDirectoryResponseCarriesNoCredentialFields(t *testing.T) {
	storage := &directoryStorage{page: samplePage()}
	service := newDirectoryService(t, config.Config{}, storage)

	rec := httptest.NewRecorder()
	service.Directory().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/users", nil))

	var payload struct {
		Users []map[string]any `json:"users"`
	}

	td.Require(t).CmpNoError(json.Unmarshal(rec.Body.Bytes(), &payload), "decode response")
	td.Require(t).Cmp(len(payload.Users), 1)

	for _, forbidden := range []string{"password", "oauth_sub", "Password"} {
		_, present := payload.Users[0][forbidden]
		td.Cmp(t, present, false, "directory entry must not carry %q", forbidden)
	}
}

func TestDirectoryRejectsUnusableLimits(t *testing.T) {
	tests := map[string]string{
		"not a number": "limit=many",
		"zero":         "limit=0",
		"negative":     "limit=-1",
		"beyond cap":   "limit=201",
	}

	for name, query := range tests {
		t.Run(name, func(t *testing.T) {
			service := newDirectoryService(t, config.Config{}, &directoryStorage{page: samplePage()})

			rec := httptest.NewRecorder()
			service.Directory().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/users?"+query, nil))

			// Silently clamping would page through the directory wrongly, so
			// an unusable limit is refused rather than reinterpreted.
			td.Cmp(t, rec.Code, http.StatusBadRequest)
		})
	}
}

func TestDirectoryScopesToCallerOrganizationWhenMultiTenant(t *testing.T) {
	storage := &directoryStorage{page: samplePage(), orgID: "org-acme"}
	service := newDirectoryService(t, config.Config{MultiTenancyEnable: true}, storage)

	// The request asks for another tenant; the caller's own organization has to
	// win, or any account could page through a tenant it does not belong to.
	req := httptest.NewRequest(http.MethodGet, "/users?org_id=org-other", nil)
	req = req.WithContext(context.WithValue(
		req.Context(),
		middleware.UserContextKey,
		middleware.UserInfo{UserID: "user-1", Email: "maya@acme.test"},
	))

	rec := httptest.NewRecorder()
	service.Directory().ServeHTTP(rec, req)

	td.Require(t).Cmp(rec.Code, http.StatusOK)
	td.Cmp(t, storage.lastQuery.ScopeOrg, true)
	td.Cmp(t, storage.lastQuery.OrgID, "org-acme")
}

func TestDirectoryRefusesUnscopedMultiTenantRead(t *testing.T) {
	storage := &directoryStorage{page: samplePage()}
	service := newDirectoryService(t, config.Config{MultiTenancyEnable: true}, storage)

	rec := httptest.NewRecorder()
	service.Directory().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/users", nil))

	// No identity means no scope; listing every tenant would be worse than
	// refusing.
	td.Cmp(t, rec.Code, http.StatusForbidden)
}

func TestDirectoryReportsStorageFailure(t *testing.T) {
	storage := &directoryStorage{pageErr: errors.New("database unavailable")}
	service := newDirectoryService(t, config.Config{}, storage)

	rec := httptest.NewRecorder()
	service.Directory().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/users", nil))

	td.Cmp(t, rec.Code, http.StatusInternalServerError)
}

func TestBuildDirectoryPage(t *testing.T) {
	entries := []DirectoryEntry{
		{UserID: "a"},
		{UserID: "b"},
		{UserID: "c"},
	}

	t.Run("surplus row reports another page and is not returned", func(t *testing.T) {
		page := BuildDirectoryPage(entries, 2, 10)

		td.Cmp(t, len(page.Users), 2)
		td.Cmp(t, page.HasMore, true)
		td.Cmp(t, page.NextCursor, "b", "cursor is the last returned row, not the surplus one")
		td.Cmp(t, page.Total, int64(10))
	})

	t.Run("last page offers no cursor", func(t *testing.T) {
		page := BuildDirectoryPage(entries, 3, 3)

		td.Cmp(t, page.HasMore, false)
		td.Cmp(t, page.NextCursor, "", "a cursor past the last row invites a pointless request")
	})

	t.Run("empty page is not a position", func(t *testing.T) {
		page := BuildDirectoryPage(nil, 10, 0)

		td.Cmp(t, page.HasMore, false)
		td.Cmp(t, page.NextCursor, "")
		td.Cmp(t, page.Total, int64(0))
	})
}

func TestClampDirectoryLimit(t *testing.T) {
	td.Cmp(t, ClampDirectoryLimit(0), DirectoryDefaultLimit)
	td.Cmp(t, ClampDirectoryLimit(-5), DirectoryDefaultLimit)
	td.Cmp(t, ClampDirectoryLimit(10), 10)
	td.Cmp(t, ClampDirectoryLimit(5_000), DirectoryMaxLimit)
}
