package litestore

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/marsolab/plainq/internal/server/service/rbac"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/maxatome/go-testdeep/td"
)

// permissionsSchema mirrors the tables the RBAC storage writes, including the
// foreign key from a grant to a queue — the constraint that turns a grant on a
// queue that does not exist into a rejected request rather than a stored row.
const permissionsSchema = `
create table if not exists organizations
(
    org_id text not null primary key
);

create table if not exists users
(
    user_id text not null primary key,
    org_id text not null,
    auth_version integer not null default 1,
    status text not null default 'active'
);

create table if not exists roles
(
    role_id    text      not null primary key,
    role_name  text      not null,
    created_at timestamp not null default current_timestamp
);

create table if not exists user_roles
(
    user_id    text      not null,
    role_id    text      not null,
    created_at timestamp not null default current_timestamp,
    primary key (user_id, role_id)
);

create table if not exists queue_properties
(
    queue_id   text not null primary key,
    queue_name text not null,
    tenant_id text not null,
    created_by_kind text not null,
    created_by_id text not null
);

create table if not exists security_principals
(
    tenant_id text not null,
    principal_kind text not null,
    principal_id text not null,
    status text not null,
    roles_json text not null,
    auth_version integer not null,
    updated_at_ns integer not null,
    primary key (tenant_id, principal_kind, principal_id)
);

create table if not exists queue_permissions
(
    queue_id    text      not null,
    role_id     text      not null,
    can_send    boolean   not null default false,
    can_receive boolean   not null default false,
    can_purge   boolean   not null default false,
    can_delete  boolean   not null default false,
    created_at  timestamp not null default current_timestamp,
    updated_at  timestamp not null default current_timestamp,
    primary key (queue_id, role_id),
    constraint queue_permissions_queue_fk
        foreign key (queue_id) references queue_properties (queue_id) on delete cascade,
    constraint queue_permissions_role_fk
        foreign key (role_id) references roles (role_id) on delete cascade
);
`

func newPermissionsStorage(t *testing.T) (*Storage, context.Context) {
	t.Helper()

	ctx := context.Background()

	conn, err := litekit.New(filepath.Join(t.TempDir(), "rbac.db"))
	td.Require(t).CmpNoError(err, "open database")
	t.Cleanup(func() { td.CmpNoError(t, conn.Close(), "close database") })

	// SQLite only honours foreign keys when the pragma is set, and it is set
	// per connection — so the pool is pinned to one. The mapping under test is
	// what a constraint failure becomes; whether a given deployment enforces
	// the constraint is a property of its connection, not of this code.
	conn.SetMaxOpenConns(1)

	_, err = conn.ExecContext(ctx, "PRAGMA foreign_keys = ON")
	td.Require(t).CmpNoError(err, "enable foreign keys")

	_, err = conn.ExecContext(ctx, permissionsSchema)
	td.Require(t).CmpNoError(err, "create schema")

	storage, err := NewStorage(conn, nil)
	td.Require(t).CmpNoError(err, "create storage")

	for _, statement := range []string{
		`insert into organizations (org_id) values ('tenant-1')`,
		`insert into users (user_id, org_id) values ('user-1', 'tenant-1')`,
		`insert into users (user_id, org_id) values ('user-2', 'tenant-1')`,
		`insert into roles (role_id, role_name) values ('role-consumer', 'consumer')`,
		`insert into queue_properties (queue_id, queue_name, tenant_id, created_by_kind, created_by_id) values ('queue-1', 'orders', 'tenant-1', 'system', 'migration')`,
		`insert into queue_properties (queue_id, queue_name, tenant_id, created_by_kind, created_by_id) values ('queue-2', 'billing', 'tenant-1', 'system', 'migration')`,
	} {
		_, err := conn.ExecContext(ctx, statement)
		td.Require(t).CmpNoError(err, "seed: %s", statement)
	}

	return storage, ctx
}

func TestRoleMutationBumpsAuthVersionAndProjectsPrincipal(t *testing.T) {
	storage, ctx := newPermissionsStorage(t)

	td.Require(t).CmpNoError(storage.AssignRoleToUser(ctx, "user-1", "role-consumer"), "assign role")
	assertHumanSecurityProjection(t, storage.db, 2, `["consumer"]`)

	td.Require(t).CmpNoError(storage.UpdateRole(ctx, rbac.Role{
		RoleID: "role-consumer", RoleName: "reader",
	}), "rename role")
	assertHumanSecurityProjection(t, storage.db, 3, `["reader"]`)

	td.Require(t).CmpNoError(storage.RemoveRoleFromUser(ctx, "user-1", "role-consumer"), "remove role")
	assertHumanSecurityProjection(t, storage.db, 4, `[]`)
}

func assertHumanSecurityProjection(t *testing.T, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, wantVersion int64, wantRoles string) {
	t.Helper()
	var userVersion, principalVersion int64
	var roles string
	if err := db.QueryRowContext(context.Background(), `
SELECT u.auth_version, sp.auth_version, sp.roles_json
FROM users u
JOIN security_principals sp
  ON sp.tenant_id = u.org_id AND sp.principal_kind = 'human' AND sp.principal_id = u.user_id
WHERE u.user_id = 'user-1'`).Scan(&userVersion, &principalVersion, &roles); err != nil {
		t.Fatalf("read human security projection: %v", err)
	}
	if userVersion != wantVersion || principalVersion != wantVersion || roles != wantRoles {
		t.Fatalf("security projection = user_version %d principal_version %d roles %s, want %d/%d/%s",
			userVersion, principalVersion, roles, wantVersion, wantVersion, wantRoles)
	}
}

func TestReplaceRoleQueuePermissionsStoresExactlyTheGivenSet(t *testing.T) {
	storage, ctx := newPermissionsStorage(t)

	td.Require(t).CmpNoError(storage.ReplaceRoleQueuePermissions(ctx, "role-consumer", []rbac.QueuePermission{
		{QueueID: "queue-1", CanSend: true},
		{QueueID: "queue-2", CanReceive: true},
	}), "first save")

	stored, err := storage.GetRoleQueuePermissions(ctx, "role-consumer")
	td.Require(t).CmpNoError(err, "read back")
	td.Cmp(t, len(stored), 2)

	// A save is the whole matrix: the row that is no longer sent has to be
	// gone, not merged with the previous state.
	td.Require(t).CmpNoError(storage.ReplaceRoleQueuePermissions(ctx, "role-consumer", []rbac.QueuePermission{
		{QueueID: "queue-2", CanReceive: true, CanPurge: true},
	}), "second save")

	stored, err = storage.GetRoleQueuePermissions(ctx, "role-consumer")
	td.Require(t).CmpNoError(err, "read back")
	td.Require(t).Cmp(len(stored), 1)
	td.Cmp(t, stored[0].QueueID, "queue-2")
	td.Cmp(t, stored[0].CanPurge, true)

	empty := storage.ReplaceRoleQueuePermissions(ctx, "role-consumer", nil)
	td.Require(t).CmpNoError(empty, "clearing every grant")

	stored, err = storage.GetRoleQueuePermissions(ctx, "role-consumer")
	td.Require(t).CmpNoError(err, "read back")
	td.Cmp(t, len(stored), 0)
}

func TestQueuePermissionsResolveAdminAndTenantInStorage(t *testing.T) {
	storage, ctx := newPermissionsStorage(t)

	for _, statement := range []string{
		`insert into organizations (org_id) values ('tenant-2')`,
		`insert into users (user_id, org_id) values ('admin-1', 'tenant-1')`,
		`insert into roles (role_id, role_name) values ('role-admin', 'admin')`,
		`insert into user_roles (user_id, role_id) values ('admin-1', 'role-admin')`,
		`insert into queue_properties (queue_id, queue_name, tenant_id, created_by_kind, created_by_id) values ('queue-other', 'private', 'tenant-2', 'human', 'other')`,
	} {
		if _, err := storage.db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("seed: %s: %v", statement, err)
		}
	}

	allowed, err := storage.HasQueuePermission(ctx, "admin-1", "queue-1", rbac.PermissionSend)
	if err != nil {
		t.Fatalf("check same-tenant admin: %v", err)
	}
	if !allowed {
		t.Fatal("same-tenant administrator was denied without an explicit queue grant")
	}

	allowed, err = storage.HasQueuePermission(ctx, "admin-1", "queue-other", rbac.PermissionSend)
	if err != nil {
		t.Fatalf("check cross-tenant admin: %v", err)
	}
	if allowed {
		t.Fatal("cross-tenant administrator was allowed")
	}
}

// A save that fails partway has to leave the previous matrix intact: a role
// that can receive but, for one rejected row, can no longer send is a state no
// operator asked for.
func TestReplaceRoleQueuePermissionsRollsBackOnRejectedRow(t *testing.T) {
	storage, ctx := newPermissionsStorage(t)

	td.Require(t).CmpNoError(storage.ReplaceRoleQueuePermissions(ctx, "role-consumer", []rbac.QueuePermission{
		{QueueID: "queue-1", CanSend: true, CanReceive: true},
	}), "seed grants")

	err := storage.ReplaceRoleQueuePermissions(ctx, "role-consumer", []rbac.QueuePermission{
		{QueueID: "queue-2", CanSend: true},
		{QueueID: "queue-ghost", CanSend: true},
	})

	td.Require(t).CmpError(err, "a grant on an unknown queue is rejected")
	td.Cmp(t, errors.Is(err, pqerr.ErrInvalidInput), true,
		"a foreign-key failure is the caller's mistake, not a server fault")

	stored, storeErr := storage.GetRoleQueuePermissions(ctx, "role-consumer")
	td.Require(t).CmpNoError(storeErr, "read back")
	td.Require(t).Cmp(len(stored), 1, "the previous matrix survives a failed save")
	td.Cmp(t, stored[0].QueueID, "queue-1")
	td.Cmp(t, stored[0].CanReceive, true)
}

func TestAssignRoleToUserReportsADuplicateRatherThanSucceeding(t *testing.T) {
	storage, ctx := newPermissionsStorage(t)

	td.Require(t).CmpNoError(storage.AssignRoleToUser(ctx, "user-1", "role-consumer"), "first assign")
	td.Cmp(t, storage.AssignRoleToUser(ctx, "user-1", "role-consumer"), rbac.ErrRoleAlreadyAssigned)
}

// The invariant lives in the delete's own WHERE clause, so it holds without a
// read-then-write window: an account can only lose the role while another
// account still holds it.
func TestRemoveRoleFromUserUnlessLastHolder(t *testing.T) {
	storage, ctx := newPermissionsStorage(t)

	td.Require(t).CmpNoError(storage.AssignRoleToUser(ctx, "user-1", "role-consumer"), "assign")
	td.Require(t).CmpNoError(storage.AssignRoleToUser(ctx, "user-2", "role-consumer"), "assign")

	td.Require(t).CmpNoError(
		storage.RemoveRoleFromUserUnlessLastHolder(ctx, "user-1", "role-consumer"),
		"one of two holders may lose the role",
	)

	// The second removal would empty the role, so the delete matches no row.
	td.Cmp(t,
		storage.RemoveRoleFromUserUnlessLastHolder(ctx, "user-2", "role-consumer"),
		rbac.ErrLastRoleHolder,
	)

	holders, err := storage.CountUsersWithRole(ctx, "role-consumer")
	td.Require(t).CmpNoError(err, "count holders")
	td.Cmp(t, holders, int64(1), "the last holder still holds it")
}

func TestRemoveRoleFromUserUnlessLastHolderReportsAMissingAssignment(t *testing.T) {
	storage, ctx := newPermissionsStorage(t)

	td.Require(t).CmpNoError(storage.AssignRoleToUser(ctx, "user-1", "role-consumer"), "assign")

	// An account that never held the role is a different answer from one the
	// guard refused, and the caller acts on each differently.
	err := storage.RemoveRoleFromUserUnlessLastHolder(ctx, "user-2", "role-consumer")

	td.Require(t).CmpError(err, "removing an assignment that does not exist")
	td.Cmp(t, errors.Is(err, pqerr.ErrNotFound), true)
	td.Cmp(t, errors.Is(err, rbac.ErrLastRoleHolder), false)
}

func TestCountUsersPerRole(t *testing.T) {
	storage, ctx := newPermissionsStorage(t)

	td.Require(t).CmpNoError(storage.AssignRoleToUser(ctx, "user-1", "role-consumer"), "assign")
	td.Require(t).CmpNoError(storage.AssignRoleToUser(ctx, "user-2", "role-consumer"), "assign")

	counts, err := storage.CountUsersPerRole(ctx)
	td.Require(t).CmpNoError(err, "count per role")
	td.Cmp(t, counts, map[string]int64{"role-consumer": 2})

	one, err := storage.CountUsersWithRole(ctx, "role-consumer")
	td.Require(t).CmpNoError(err, "count one role")
	td.Cmp(t, one, int64(2))
}
