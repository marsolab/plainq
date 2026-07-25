package litestore

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/service/account"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/maxatome/go-testdeep/td"
)

// directorySchema mirrors the tables the directory reads from the migrations,
// so the joins and the paging predicate are exercised against real SQLite
// rather than against an interface that agrees with them.
const directorySchema = `
create table if not exists users
(
    user_id        text      not null primary key,
    email          text      not null,
    password       text      not null,
    verified       boolean   not null default false,
    created_at     timestamp not null default current_timestamp,
    updated_at     timestamp not null default current_timestamp,
    org_id         text,
    oauth_provider text,
    oauth_sub      text,
    last_sync_at   timestamp,
    is_oauth_user  boolean   not null default false
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

create table if not exists organizations
(
    org_id     text      not null primary key,
    org_code   text      not null,
    org_name   text      not null,
    org_domain text,
    is_active  boolean   not null default true,
    created_at timestamp not null default current_timestamp,
    updated_at timestamp not null default current_timestamp
);

create table if not exists teams
(
    team_id     text      not null primary key,
    org_id      text      not null,
    team_name   text      not null,
    team_code   text      not null,
    description text,
    is_active   boolean   not null default true,
    created_at  timestamp not null default current_timestamp,
    updated_at  timestamp not null default current_timestamp
);

create table if not exists user_teams
(
    user_id    text      not null,
    team_id    text      not null,
    created_at timestamp not null default current_timestamp,
    primary key (user_id, team_id)
);
`

func newDirectoryStorage(t *testing.T) (*Storage, context.Context) {
	t.Helper()

	ctx := context.Background()

	conn, err := litekit.New(filepath.Join(t.TempDir(), "directory.db"))
	td.Require(t).CmpNoError(err, "open database")
	t.Cleanup(func() { td.CmpNoError(t, conn.Close(), "close database") })

	_, err = conn.ExecContext(ctx, directorySchema)
	td.Require(t).CmpNoError(err, "create schema")

	storage, err := NewStorage(conn, nil)
	td.Require(t).CmpNoError(err, "create storage")

	return storage, ctx
}

// seedDirectory writes a fixed directory: three local accounts in the acme
// organization, one provider-backed account with no organization, one role and
// one team.
func seedDirectory(t *testing.T, storage *Storage, ctx context.Context) {
	t.Helper()

	now := time.Now().UTC().Truncate(time.Second)

	statements := []struct {
		query string
		args  []any
	}{
		{
			`insert into organizations (org_id, org_code, org_name) values (?, ?, ?)`,
			[]any{"org-acme", "acme", "Acme Corporation"},
		},
		{
			`insert into roles (role_id, role_name, created_at) values (?, ?, ?)`,
			[]any{"role-admin", "admin", now},
		},
		{
			`insert into teams (team_id, org_id, team_name, team_code) values (?, ?, ?, ?)`,
			[]any{"team-ops", "org-acme", "Operations", "ops"},
		},
	}

	for _, statement := range statements {
		_, err := storage.db.ExecContext(ctx, statement.query, statement.args...)
		td.Require(t).CmpNoError(err, "seed: %s", statement.query)
	}

	accounts := []struct {
		id       string
		email    string
		orgID    any
		provider any
		synced   any
	}{
		{"01AAA", "ana@acme.test", "org-acme", nil, nil},
		{"01BBB", "bo@acme.test", "org-acme", nil, nil},
		{"01CCC", "cara@acme.test", "org-acme", nil, nil},
		{"01DDD", "dev@partner.test", nil, "kinde", now},
	}

	for _, a := range accounts {
		_, err := storage.db.ExecContext(ctx,
			`insert into users (user_id, email, password, verified, created_at, updated_at,
                                org_id, oauth_provider, last_sync_at, is_oauth_user)
             values (?, ?, 'hashed-secret', true, ?, ?, ?, ?, ?, ?)`,
			a.id, a.email, now, now, a.orgID, a.provider, a.synced, a.provider != nil,
		)
		td.Require(t).CmpNoError(err, "seed account %s", a.id)
	}

	_, err := storage.db.ExecContext(ctx,
		`insert into user_roles (user_id, role_id, created_at) values (?, ?, ?)`,
		"01AAA", "role-admin", now)
	td.Require(t).CmpNoError(err, "seed role assignment")

	_, err = storage.db.ExecContext(ctx,
		`insert into user_teams (user_id, team_id, created_at) values (?, ?, ?)`,
		"01AAA", "team-ops", now)
	td.Require(t).CmpNoError(err, "seed team membership")
}

func TestListDirectoryReturnsRolesTeamsAndOrganization(t *testing.T) {
	storage, ctx := newDirectoryStorage(t)
	seedDirectory(t, storage, ctx)

	page, err := storage.ListDirectory(ctx, account.DirectoryQuery{Limit: 10})
	td.Require(t).CmpNoError(err, "list directory")

	td.Cmp(t, page.Total, int64(4), "total counts every match, not just the page")
	td.Require(t).Cmp(len(page.Users), 4)

	first := page.Users[0]
	td.Cmp(t, first.Email, "ana@acme.test")
	td.Cmp(t, first.OrgCode, "acme", "the organization is joined, not just its id")
	td.Cmp(t, first.OrgName, "Acme Corporation")
	td.Cmp(t, first.Roles, []account.DirectoryRole{{RoleID: "role-admin", RoleName: "admin"}})
	td.Cmp(t, len(first.Teams), 1)
	td.Cmp(t, first.Teams[0].TeamCode, "ops")

	// An account with no role and no team gets empty lists, never a nil the
	// JSON encoder would turn into null.
	td.Cmp(t, page.Users[1].Roles, []account.DirectoryRole{})
	td.Cmp(t, page.Users[1].Teams, []account.DirectoryTeam{})

	provider := page.Users[3]
	td.Cmp(t, provider.OAuthProvider, "kinde")
	td.Cmp(t, provider.IsOAuthUser, true)
	td.CmpNot(t, provider.LastSyncAt, td.Nil(), "a synchronized account reports when")
}

func TestListDirectoryPagesByCursor(t *testing.T) {
	storage, ctx := newDirectoryStorage(t)
	seedDirectory(t, storage, ctx)

	first, err := storage.ListDirectory(ctx, account.DirectoryQuery{Limit: 2})
	td.Require(t).CmpNoError(err, "first page")

	td.Cmp(t, len(first.Users), 2)
	td.Cmp(t, first.HasMore, true)
	td.Cmp(t, first.NextCursor, "01BBB")

	second, err := storage.ListDirectory(ctx, account.DirectoryQuery{Limit: 2, Cursor: first.NextCursor})
	td.Require(t).CmpNoError(err, "second page")

	td.Cmp(t, len(second.Users), 2)
	td.Cmp(t, second.Users[0].UserID, "01CCC", "the cursor row is not repeated")
	td.Cmp(t, second.HasMore, false)
	td.Cmp(t, second.NextCursor, "")
}

func TestListDirectorySearchesEmailCaseInsensitively(t *testing.T) {
	storage, ctx := newDirectoryStorage(t)
	seedDirectory(t, storage, ctx)

	page, err := storage.ListDirectory(ctx, account.DirectoryQuery{Limit: 10, Search: "ANA@"})
	td.Require(t).CmpNoError(err, "search directory")

	td.Cmp(t, len(page.Users), 1)
	td.Cmp(t, page.Users[0].Email, "ana@acme.test")
	td.Cmp(t, page.Total, int64(1), "the total counts the filtered set, not the table")
}

func TestListDirectoryScopesToOrganization(t *testing.T) {
	storage, ctx := newDirectoryStorage(t)
	seedDirectory(t, storage, ctx)

	scoped, err := storage.ListDirectory(ctx, account.DirectoryQuery{
		Limit: 10, ScopeOrg: true, OrgID: "org-acme",
	})
	td.Require(t).CmpNoError(err, "scoped list")

	td.Cmp(t, len(scoped.Users), 3)
	td.Cmp(t, scoped.Total, int64(3))

	// An empty organization is a real scope — the accounts belonging to none —
	// rather than a request for no scoping at all.
	orphans, err := storage.ListDirectory(ctx, account.DirectoryQuery{Limit: 10, ScopeOrg: true})
	td.Require(t).CmpNoError(err, "unscoped-organization list")

	td.Cmp(t, len(orphans.Users), 1)
	td.Cmp(t, orphans.Users[0].Email, "dev@partner.test")
}

func TestGetAccountOrgIDReportsNoOrganizationAsEmpty(t *testing.T) {
	storage, ctx := newDirectoryStorage(t)
	seedDirectory(t, storage, ctx)

	orgID, err := storage.GetAccountOrgID(ctx, "01DDD")
	td.Require(t).CmpNoError(err, "get org id")
	td.Cmp(t, orgID, "")

	orgID, err = storage.GetAccountOrgID(ctx, "01AAA")
	td.Require(t).CmpNoError(err, "get org id")
	td.Cmp(t, orgID, "org-acme")
}
