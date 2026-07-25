package account

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/server/middleware"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/httpkit"
)

const (
	// DirectoryDefaultLimit is the page size used when the caller asks for none.
	DirectoryDefaultLimit = 50

	// DirectoryMaxLimit caps a page so one request cannot ask for the whole
	// table. A caller wanting more pages through the cursor.
	DirectoryMaxLimit = 200
)

// DirectoryRole is a role held by an account. It carries the identifier the
// RBAC routes key off, so the caller never has to match roles by name.
type DirectoryRole struct {
	RoleID   string `json:"role_id"`
	RoleName string `json:"role_name"`
}

// DirectoryTeam is a team an account belongs to.
type DirectoryTeam struct {
	TeamID   string `json:"team_id"`
	OrgID    string `json:"org_id"`
	TeamName string `json:"team_name"`
	TeamCode string `json:"team_code"`
}

// DirectoryEntry is one account as the directory reports it.
//
// The field set is the point of the type: it is built from an explicit list of
// safe columns rather than from the Account aggregate, so a password hash or an
// OAuth subject cannot reach an operator console by being added to storage
// later. Anything sensitive has to be added here on purpose.
type DirectoryEntry struct {
	UserID        string          `json:"user_id"`
	Email         string          `json:"email"`
	Verified      bool            `json:"verified"`
	OrgID         string          `json:"org_id,omitempty"`
	OrgCode       string          `json:"org_code,omitempty"`
	OrgName       string          `json:"org_name,omitempty"`
	OAuthProvider string          `json:"oauth_provider,omitempty"`
	IsOAuthUser   bool            `json:"is_oauth_user"`
	LastSyncAt    *time.Time      `json:"last_sync_at,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	Roles         []DirectoryRole `json:"roles"`
	Teams         []DirectoryTeam `json:"teams"`
}

// DirectoryQuery selects one page of the account directory.
type DirectoryQuery struct {
	// Search matches a substring of the email address, case-insensitively.
	// Empty matches everything.
	Search string

	// ScopeOrg restricts the page to OrgID. It is a separate flag because an
	// empty OrgID is a real scope — the accounts that belong to no
	// organization — and not the same as "no scoping".
	ScopeOrg bool
	OrgID    string

	// Cursor is the last user ID of the previous page. Accounts carry ULIDs,
	// which sort lexicographically by creation time, so a keyset scan is both
	// stable under concurrent writes and cheap.
	Cursor string

	// Limit is the page size. Storage clamps it to DirectoryMaxLimit.
	Limit int
}

// DirectoryPage is one page of the account directory.
type DirectoryPage struct {
	Users      []DirectoryEntry `json:"users"`
	NextCursor string           `json:"next_cursor"`
	HasMore    bool             `json:"has_more"`

	// Total counts every account matching the filter, not just this page. It
	// is a real count(*), so the UI never has to infer a total from a page.
	Total int64 `json:"total"`
}

// Directory returns the handler for the account directory subtree. It is kept
// off the account router on purpose: /account carries sign-in, sign-up and
// refresh, which have to stay public, whereas reading the directory must not.
// Mounting it separately lets the server put authentication in front of it.
func (s *Service) Directory() http.Handler {
	router := chi.NewRouter()
	router.Get("/users", s.listDirectoryHandler)

	return router
}

func (s *Service) listDirectoryHandler(w http.ResponseWriter, r *http.Request) {
	limit, err := directoryLimit(r.URL.Query().Get("limit"))
	if err != nil {
		httpkit.ErrorHTTP(w, r, err)

		return
	}

	query := DirectoryQuery{
		Search: r.URL.Query().Get("search"),
		Cursor: r.URL.Query().Get("cursor"),
		Limit:  limit,
	}

	// With multi-tenancy on, the caller's own organization is the scope, and it
	// is read from the server's record of them rather than from the request —
	// an org_id parameter would let any account page through another tenant.
	if s.cfg.MultiTenancyEnable {
		user, ok := middleware.GetUserFromContext(r.Context())
		if !ok {
			// Reachable only with authentication disabled, where the whole API
			// is open by configuration. Scoping to an unknown caller is not
			// possible, so say so instead of silently listing every tenant.
			httpkit.ErrorHTTP(w, r, fmt.Errorf(
				"%w: multi-tenancy requires authentication to scope the directory",
				errkit.ErrUnauthorized,
			))

			return
		}

		orgID, orgErr := s.storage.GetAccountOrgID(r.Context(), user.UserID)
		if orgErr != nil {
			httpkit.ErrorHTTP(w, r, fmt.Errorf("resolve caller organization: %w", orgErr))

			return
		}

		query.ScopeOrg = true
		query.OrgID = orgID
	}

	page, err := s.storage.ListDirectory(r.Context(), query)
	if err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("list account directory: %w", err))

		return
	}

	httpkit.JSON(w, r, page)
}

// directoryLimit parses the page size, rejecting values it cannot honor rather
// than quietly substituting one: a caller that asked for 1000 rows and received
// 200 without being told would page through the directory wrongly.
func directoryLimit(raw string) (int, error) {
	if raw == "" {
		return DirectoryDefaultLimit, nil
	}

	limit, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%w: limit must be an integer", errkit.ErrInvalidArgument)
	}

	if limit < 1 || limit > DirectoryMaxLimit {
		return 0, fmt.Errorf("%w: limit must be between 1 and %d", errkit.ErrInvalidArgument, DirectoryMaxLimit)
	}

	return limit, nil
}

// ClampDirectoryLimit returns the page size a storage implementation should use
// for the given query. It exists so every backend enforces the same ceiling.
func ClampDirectoryLimit(limit int) int {
	if limit < 1 {
		return DirectoryDefaultLimit
	}

	if limit > DirectoryMaxLimit {
		return DirectoryMaxLimit
	}

	return limit
}

// BuildDirectoryPage assembles a page from the rows a storage backend read.
// Both backends run the same three queries and differ only in their driver
// types, so the paging and grouping rules live here rather than twice.
//
// The rows slice may hold one extra entry beyond limit — that surplus is how a
// backend reports "there is more", and it is dropped here rather than returned.
func BuildDirectoryPage(entries []DirectoryEntry, limit int, total int64) *DirectoryPage {
	page := DirectoryPage{Users: entries, Total: total}

	if len(entries) > limit {
		page.Users = entries[:limit]
		page.HasMore = true
	}

	if len(page.Users) > 0 {
		page.NextCursor = page.Users[len(page.Users)-1].UserID
	}

	// A cursor pointing past the last row invites a pointless extra request,
	// and an empty page is not a position worth resuming from.
	if !page.HasMore {
		page.NextCursor = ""
	}

	return &page
}
