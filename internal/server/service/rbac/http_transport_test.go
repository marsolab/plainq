package rbac

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marsolab/plainq/internal/server/config"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/logkit"
	"github.com/maxatome/go-testdeep/td"
)

// fakeStorage records what the handlers asked for and answers from fields the
// test sets. Only the calls a test exercises are populated; anything else
// returns a not-found so an unexpected path fails visibly.
type fakeStorage struct {
	Storage

	roles          []Role
	counts         map[string]int64
	holders        map[string][]string
	permissions    map[string]*QueuePermission
	permissionErr  error
	rolePerms      []QueuePermission
	replaced       []QueuePermission
	replacedRoleID string
	replaceErr     error
	assignErr      error
	removed        [2]string
	deletedRole    string
}

func (s *fakeStorage) GetAllRoles(context.Context) ([]Role, error) { return s.roles, nil }

func (s *fakeStorage) GetRoleByID(_ context.Context, roleID string) (*Role, error) {
	for _, role := range s.roles {
		if role.RoleID == roleID {
			return &role, nil
		}
	}

	return nil, fmt.Errorf("role not found: %w", pqerr.ErrNotFound)
}

func (s *fakeStorage) CountUsersPerRole(context.Context) (map[string]int64, error) {
	if s.counts == nil {
		return map[string]int64{}, nil
	}

	return s.counts, nil
}

func (s *fakeStorage) CountUsersWithRole(_ context.Context, roleID string) (int64, error) {
	return s.counts[roleID], nil
}

func (s *fakeStorage) GetUsersWithRole(_ context.Context, roleID string) ([]string, error) {
	return s.holders[roleID], nil
}

func (s *fakeStorage) GetQueuePermissions(_ context.Context, queueID, roleID string) (*QueuePermission, error) {
	if s.permissionErr != nil {
		return nil, s.permissionErr
	}

	if perm, ok := s.permissions[queueID+"/"+roleID]; ok {
		return perm, nil
	}

	return nil, fmt.Errorf("queue permission not found: %w", pqerr.ErrNotFound)
}

func (s *fakeStorage) GetRoleQueuePermissions(context.Context, string) ([]QueuePermission, error) {
	return s.rolePerms, nil
}

func (s *fakeStorage) ReplaceRoleQueuePermissions(
	_ context.Context, roleID string, permissions []QueuePermission,
) error {
	if s.replaceErr != nil {
		return s.replaceErr
	}

	s.replacedRoleID = roleID
	s.replaced = permissions
	s.rolePerms = permissions

	return nil
}

func (s *fakeStorage) AssignRoleToUser(context.Context, string, string) error { return s.assignErr }

func (s *fakeStorage) RemoveRoleFromUser(_ context.Context, userID, roleID string) error {
	s.removed = [2]string{userID, roleID}

	return nil
}

func (s *fakeStorage) DeleteRole(_ context.Context, roleID string) error {
	s.deletedRole = roleID

	return nil
}

func newService(storage Storage) *Service {
	return NewService(&config.Config{}, logkit.NewNop(), storage)
}

func do(service *Service, method, target string, body string) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}

	rec := httptest.NewRecorder()
	service.ServeHTTP(rec, httptest.NewRequest(method, target, reader))

	return rec
}

func adminAndConsumer() []Role {
	return []Role{
		{RoleID: "role-admin", RoleName: AdminRoleName},
		{RoleID: "role-consumer", RoleName: "consumer"},
	}
}

func TestListRolesCarriesRealUserCounts(t *testing.T) {
	storage := &fakeStorage{
		roles:  adminAndConsumer(),
		counts: map[string]int64{"role-admin": 1, "role-consumer": 7},
	}

	rec := do(newService(storage), http.MethodGet, "/roles", "")
	td.Require(t).Cmp(rec.Code, http.StatusOK)

	var got []RoleWithUsage
	td.Require(t).CmpNoError(json.Unmarshal(rec.Body.Bytes(), &got), "decode roles")

	td.Cmp(t, got, []RoleWithUsage{
		{Role: storage.roles[0], UserCount: 1},
		{Role: storage.roles[1], UserCount: 7},
	})
}

func TestRemovingTheLastAdministratorIsRefused(t *testing.T) {
	storage := &fakeStorage{
		roles:   adminAndConsumer(),
		holders: map[string][]string{"role-admin": {"user-1"}},
	}
	service := newService(storage)

	rec := do(service, http.MethodDelete, "/users/user-1/roles/role-admin", "")

	td.Cmp(t, rec.Code, http.StatusConflict,
		"stripping the only administrator would lock everyone out")
	td.Cmp(t, storage.removed, [2]string{}, "and the write must not happen")
}

func TestRemovingOneOfSeveralAdministratorsIsAllowed(t *testing.T) {
	storage := &fakeStorage{
		roles:   adminAndConsumer(),
		holders: map[string][]string{"role-admin": {"user-1", "user-2"}},
	}
	service := newService(storage)

	rec := do(service, http.MethodDelete, "/users/user-1/roles/role-admin", "")

	td.Cmp(t, rec.Code, http.StatusNoContent)
	td.Cmp(t, storage.removed, [2]string{"user-1", "role-admin"})
}

func TestRemovingANonAdministratorRoleIsNotGuarded(t *testing.T) {
	storage := &fakeStorage{
		roles:   adminAndConsumer(),
		holders: map[string][]string{"role-consumer": {"user-1"}},
	}

	rec := do(newService(storage), http.MethodDelete, "/users/user-1/roles/role-consumer", "")

	td.Cmp(t, rec.Code, http.StatusNoContent)
}

func TestAssigningAHeldRoleIsAConflict(t *testing.T) {
	storage := &fakeStorage{roles: adminAndConsumer(), assignErr: ErrRoleAlreadyAssigned}

	rec := do(newService(storage), http.MethodPost, "/users/user-1/roles/role-consumer", "")

	// Answering 201 for a write that changed nothing would have the caller
	// report a change that never happened.
	td.Cmp(t, rec.Code, http.StatusConflict)
}

func TestAssigningAnUnknownRoleIsNotFound(t *testing.T) {
	storage := &fakeStorage{roles: adminAndConsumer()}

	rec := do(newService(storage), http.MethodPost, "/users/user-1/roles/role-ghost", "")

	td.Cmp(t, rec.Code, http.StatusNotFound)
}

func TestDeletingARoleInUseIsRefused(t *testing.T) {
	storage := &fakeStorage{
		roles:  adminAndConsumer(),
		counts: map[string]int64{"role-consumer": 3},
	}
	service := newService(storage)

	rec := do(service, http.MethodDelete, "/roles/role-consumer", "")

	td.Cmp(t, rec.Code, http.StatusConflict, "the cascade would silently strip three accounts")
	td.Cmp(t, storage.deletedRole, "")
}

func TestTheAdministratorRoleCannotBeDeletedOrRenamed(t *testing.T) {
	storage := &fakeStorage{roles: adminAndConsumer()}
	service := newService(storage)

	deleted := do(service, http.MethodDelete, "/roles/role-admin", "")
	td.Cmp(t, deleted.Code, http.StatusBadRequest)
	td.Cmp(t, storage.deletedRole, "")

	renamed := do(service, http.MethodPut, "/roles/role-admin", `{"role_name":"superuser"}`)
	td.Cmp(t, renamed.Code, http.StatusBadRequest,
		"authorization resolves this role by name, so a rename would disable it")
}

func TestUnusedRoleCanBeDeleted(t *testing.T) {
	storage := &fakeStorage{roles: adminAndConsumer(), counts: map[string]int64{}}
	service := newService(storage)

	rec := do(service, http.MethodDelete, "/roles/role-consumer", "")

	td.Cmp(t, rec.Code, http.StatusNoContent)
	td.Cmp(t, storage.deletedRole, "role-consumer")
}

func TestQueueMatrixMarksMissingRowsUngranted(t *testing.T) {
	storage := &fakeStorage{
		roles:  adminAndConsumer(),
		counts: map[string]int64{"role-admin": 1},
		permissions: map[string]*QueuePermission{
			"queue-1/role-consumer": {QueueID: "queue-1", RoleID: "role-consumer", CanReceive: true},
		},
	}

	rec := do(newService(storage), http.MethodGet, "/permissions/queues/queue-1", "")
	td.Require(t).Cmp(rec.Code, http.StatusOK)

	var got []QueueRolePermission
	td.Require(t).CmpNoError(json.Unmarshal(rec.Body.Bytes(), &got), "decode matrix")
	td.Require(t).Cmp(len(got), 2)

	td.Cmp(t, got[0].Granted, false, "no stored row is not an explicit deny")
	td.Cmp(t, got[0].UserCount, int64(1))
	td.Cmp(t, got[1].Granted, true)
	td.Cmp(t, got[1].Permission.CanReceive, true)
}

func TestQueueMatrixReportsStorageFailureInsteadOfEmptyGrants(t *testing.T) {
	storage := &fakeStorage{
		roles:         adminAndConsumer(),
		permissionErr: errors.New("database unavailable"),
	}

	rec := do(newService(storage), http.MethodGet, "/permissions/queues/queue-1", "")

	// Reporting "nothing granted" when the read failed is the one answer an
	// authorization view must never invent.
	td.Cmp(t, rec.Code, http.StatusInternalServerError)
}

func TestReplaceRolePermissionsStoresTheWholeMatrix(t *testing.T) {
	storage := &fakeStorage{roles: adminAndConsumer()}
	service := newService(storage)

	body := `{"grants":[
        {"queue_id":"queue-1","can_send":true,"can_receive":false,"can_purge":false,"can_delete":false},
        {"queue_id":"queue-2","can_send":false,"can_receive":true,"can_purge":false,"can_delete":false}
    ]}`

	rec := do(service, http.MethodPut, "/permissions/roles/role-consumer", body)
	td.Require(t).Cmp(rec.Code, http.StatusOK)

	td.Cmp(t, storage.replacedRoleID, "role-consumer")
	td.Cmp(t, len(storage.replaced), 2)
	td.Cmp(t, storage.replaced[0].QueueID, "queue-1")
	td.Cmp(t, storage.replaced[0].CanSend, true)
	td.Cmp(t, storage.replaced[1].CanReceive, true)

	var got RolePermissions
	td.Require(t).CmpNoError(json.Unmarshal(rec.Body.Bytes(), &got), "decode response")
	td.Cmp(t, len(got.Grants), 2, "the response is what was stored, not an echo of the request")
}

func TestReplaceRolePermissionsRejectsAmbiguousInput(t *testing.T) {
	tests := map[string]string{
		"missing queue id": `{"grants":[{"queue_id":"","can_send":true}]}`,
		"duplicate queue": `{"grants":[
            {"queue_id":"queue-1","can_send":true},
            {"queue_id":"queue-1","can_send":false}
        ]}`,
		"malformed body": `{"grants":`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			storage := &fakeStorage{roles: adminAndConsumer()}

			rec := do(newService(storage), http.MethodPut, "/permissions/roles/role-consumer", body)

			td.Cmp(t, rec.Code, http.StatusBadRequest)
			td.Cmp(t, storage.replacedRoleID, "", "nothing is written on a rejected request")
		})
	}
}

func TestReplaceRolePermissionsForAnUnknownRoleIsNotFound(t *testing.T) {
	storage := &fakeStorage{roles: adminAndConsumer()}

	rec := do(newService(storage), http.MethodPut, "/permissions/roles/role-ghost", `{"grants":[]}`)

	td.Cmp(t, rec.Code, http.StatusNotFound)
}

func TestReplaceRolePermissionsMapsAnUnknownQueueToBadRequest(t *testing.T) {
	storage := &fakeStorage{
		roles:      adminAndConsumer(),
		replaceErr: fmt.Errorf("%w: foreign key constraint failed", pqerr.ErrInvalidInput),
	}

	rec := do(newService(storage), http.MethodPut, "/permissions/roles/role-consumer",
		`{"grants":[{"queue_id":"queue-ghost","can_send":true}]}`)

	td.Cmp(t, rec.Code, http.StatusBadRequest,
		"a grant naming a queue that does not exist is the caller's mistake")
}

func TestGetRolePermissionsAnswersAnEmptyListNotNull(t *testing.T) {
	storage := &fakeStorage{roles: adminAndConsumer()}

	rec := do(newService(storage), http.MethodGet, "/permissions/roles/role-consumer", "")
	td.Require(t).Cmp(rec.Code, http.StatusOK)

	// A null would read as "unknown" in a client that has to tell it from
	// "this role holds no grants".
	td.Cmp(t, rec.Body.String(), td.Contains(`"grants":[]`))
}
