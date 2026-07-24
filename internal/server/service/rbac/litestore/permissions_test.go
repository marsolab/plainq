package litestore

import (
	"context"
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
    queue_name text not null
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
		`insert into roles (role_id, role_name) values ('role-consumer', 'consumer')`,
		`insert into queue_properties (queue_id, queue_name) values ('queue-1', 'orders')`,
		`insert into queue_properties (queue_id, queue_name) values ('queue-2', 'billing')`,
	} {
		_, err := conn.ExecContext(ctx, statement)
		td.Require(t).CmpNoError(err, "seed: %s", statement)
	}

	return storage, ctx
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
