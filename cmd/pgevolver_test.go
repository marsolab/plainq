package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/marsolab/plainq/internal/server/mutations"
	"github.com/marsolab/plainq/internal/server/principal"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/account"
	accountpg "github.com/marsolab/plainq/internal/server/service/account/pgstore"
	"github.com/marsolab/plainq/internal/server/service/oauth"
	oauthpg "github.com/marsolab/plainq/internal/server/service/oauth/pgstore"
	"github.com/marsolab/plainq/internal/server/service/onboarding"
	onboardpg "github.com/marsolab/plainq/internal/server/service/onboarding/pgstore"
	queueservice "github.com/marsolab/plainq/internal/server/service/queue"
	queuepg "github.com/marsolab/plainq/internal/server/service/queue/pgstore"
	"github.com/marsolab/plainq/internal/server/service/rbac"
	rbacpg "github.com/marsolab/plainq/internal/server/service/rbac/pgstore"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

func openPGEvolverTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn := os.Getenv("PLAINQ_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PLAINQ_TEST_POSTGRES_DSN is not set")
	}

	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open postgres admin pool: %v", err)
	}
	t.Cleanup(admin.Close)

	schema := fmt.Sprintf("plainq_evolver_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatalf("create postgres schema: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Errorf("drop postgres schema: %v", err)
		}
	})

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse postgres DSN: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("open postgres fixture pool: %v", err)
	}
	t.Cleanup(pool.Close)

	return pool
}

func TestPGEvolverRollsBackMigrationAndVersionOnInjectedCrash(t *testing.T) {
	pool := openPGEvolverTestPool(t)
	migrations := fstest.MapFS{
		"001_committed.sql": &fstest.MapFile{Data: []byte(`
			CREATE TABLE committed (id integer PRIMARY KEY);
			INSERT INTO committed (id) VALUES (1);
		`)},
		"002_crash.sql": &fstest.MapFile{Data: []byte(`
			CREATE TABLE rolled_back (id integer PRIMARY KEY);
			INSERT INTO rolled_back (id) VALUES (2);
			DO $$ BEGIN RAISE EXCEPTION 'injected migration crash'; END $$;
		`)},
		"003_never.sql": &fstest.MapFile{Data: []byte(`CREATE TABLE never_applied (id integer PRIMARY KEY);`)},
	}

	err := newPgEvolver(pool, migrations).MutateSchema()
	if err == nil {
		t.Fatal("mutate schema: want injected crash, got nil")
	}

	ctx := context.Background()
	var version int
	if err := pool.QueryRow(ctx, `SELECT version FROM schema_version WHERE id = 0`).Scan(&version); err != nil {
		t.Fatalf("read schema version: %v", err)
	}
	if version != 1 {
		t.Fatalf("schema version = %d, want 1", version)
	}

	var committedCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM committed`).Scan(&committedCount); err != nil {
		t.Fatalf("read committed migration: %v", err)
	}
	if committedCount != 1 {
		t.Fatalf("committed row count = %d, want 1", committedCount)
	}

	for _, table := range []string{"rolled_back", "never_applied"} {
		var relation *string
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1)::text`, table).Scan(&relation); err != nil {
			t.Fatalf("look up %s: %v", table, err)
		}
		if relation != nil {
			t.Fatalf("table %s survived failed migration", table)
		}
	}
}

func TestPGEvolverAdvisoryLockSerializesConcurrentRunners(t *testing.T) {
	pool := openPGEvolverTestPool(t)
	migrations := fstest.MapFS{
		"001_race.sql": &fstest.MapFile{Data: []byte(`
			CREATE TABLE migration_race (id integer PRIMARY KEY);
			INSERT INTO migration_race (id) VALUES (1);
			SELECT pg_sleep(0.1);
		`)},
	}

	start := make(chan struct{})
	errorsByRunner := make(chan error, 2)
	var runners sync.WaitGroup
	for range 2 {
		runners.Add(1)
		go func() {
			defer runners.Done()
			<-start
			errorsByRunner <- newPgEvolver(pool, migrations).MutateSchema()
		}()
	}
	close(start)
	runners.Wait()
	close(errorsByRunner)

	for err := range errorsByRunner {
		if err != nil {
			t.Fatalf("concurrent schema mutation: %v", err)
		}
	}

	ctx := context.Background()
	var version, rows int
	if err := pool.QueryRow(ctx, `SELECT version FROM schema_version WHERE id = 0`).Scan(&version); err != nil {
		t.Fatalf("read schema version: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM migration_race`).Scan(&rows); err != nil {
		t.Fatalf("count migration rows: %v", err)
	}
	if version != 1 || rows != 1 {
		t.Fatalf("migration state = version %d rows %d, want version 1 rows 1", version, rows)
	}
}

func TestPGEvolverUpgradeFromVersionFourPreservesData(t *testing.T) {
	pool := openPGEvolverTestPool(t)
	allMutations := mutations.PostgresStorageMutations()
	versionFour := make(fstest.MapFS, 4)
	for _, name := range []string{
		"001_schema.sql",
		"002_user.sql",
		"003_organizations.sql",
		"004_pubsub.sql",
	} {
		data, err := fs.ReadFile(allMutations, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		versionFour[name] = &fstest.MapFile{Data: data}
	}

	if err := newPgEvolver(pool, versionFour).MutateSchema(); err != nil {
		t.Fatalf("apply version-four schema: %v", err)
	}

	const (
		orgID   = "01J00000000000000000000001"
		userID  = "01J00000000000000000000002"
		userID2 = "01J00000000000000000000007"
		queueID = "01J00000000000000000000003"
		topicID = "01J00000000000000000000004"
	)
	statements := []struct {
		query string
		args  []any
	}{
		{
			query: `INSERT INTO organizations (org_id, org_code, org_name) VALUES ($1, 'upgrade', 'Upgrade Tenant')`,
			args:  []any{orgID},
		},
		{
			query: `INSERT INTO users (user_id, email, password, org_id) VALUES ($1, 'upgrade@example.test', 'existing-hash', $2)`,
			args:  []any{userID, orgID},
		},
		{
			query: `INSERT INTO users (user_id, email, password) VALUES ($1, 'legacy@example.test', 'existing-hash-2')`,
			args:  []any{userID2},
		},
		{
			query: `INSERT INTO user_roles (user_id, role_id) VALUES ($1, '01HQ5RJNXS6TPXK89PQWY4N8JD')`,
			args:  []any{userID},
		},
		{
			query: `INSERT INTO user_teams (user_id, team_id) VALUES ($1, '01HQ5RJNXS6TPXK89PQWY4N8JI')`,
			args:  []any{userID},
		},
		{
			query: `INSERT INTO refresh_tokens (id, aid, token) VALUES ('01J00000000000000000000008', $1, 'clear-refresh')`,
			args:  []any{userID},
		},
		{
			query: `INSERT INTO denylist (token, denied_until) VALUES ('clear-access', 9999999999)`,
		},
		{
			query: `INSERT INTO queue_properties (queue_id, queue_name, retention_period_seconds, visibility_timeout_seconds, max_receive_attempts) VALUES ($1, 'upgrade-queue', 3600, 30, 5)`,
			args:  []any{queueID},
		},
		{
			query: `INSERT INTO topic_properties (topic_id, topic_name) VALUES ($1, 'upgrade-topic')`,
			args:  []any{topicID},
		},
		{
			query: `INSERT INTO topic_subscriptions (subscription_id, topic_id, queue_id) VALUES ('01J00000000000000000000005', $1, $2)`,
			args:  []any{topicID, queueID},
		},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatalf("seed version-four data: %v", err)
		}
	}

	if err := newPgEvolver(pool, allMutations).MutateSchema(); err != nil {
		t.Fatalf("upgrade version-four schema: %v", err)
	}

	ctx := context.Background()
	var version, users, subscriptions, roles, teams, sessions, denied, principals int
	if err := pool.QueryRow(ctx, `SELECT version FROM schema_version WHERE id = 0`).Scan(&version); err != nil {
		t.Fatalf("read upgraded schema version: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE user_id = $1 AND org_id = $2`, userID, orgID).Scan(&users); err != nil {
		t.Fatalf("read preserved user: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM topic_subscriptions WHERE topic_id = $1 AND queue_id = $2`, topicID, queueID).Scan(&subscriptions); err != nil {
		t.Fatalf("read preserved subscription: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_roles WHERE user_id = $1`, userID).Scan(&roles); err != nil {
		t.Fatalf("read preserved roles: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_teams WHERE user_id = $1`, userID).Scan(&teams); err != nil {
		t.Fatalf("read preserved teams: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens`).Scan(&sessions); err != nil {
		t.Fatalf("read revoked refresh sessions: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM denylist`).Scan(&denied); err != nil {
		t.Fatalf("read rebuilt denylist: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security_principals WHERE principal_kind = 'human'`).Scan(&principals); err != nil {
		t.Fatalf("read projected human principals: %v", err)
	}
	if version != 6 || users != 1 || subscriptions != 1 || roles != 1 || teams != 1 || sessions != 0 ||
		denied != 0 || principals != 2 {
		t.Fatalf("upgrade state = version %d users %d subscriptions %d roles %d teams %d sessions %d denied %d principals %d",
			version, users, subscriptions, roles, teams, sessions, denied, principals)
	}

	const legacyTenantID = "01HQ5RJNXS6TPXK89PQWY4N8JH"
	var legacyUserTenant, queueTenant, topicTenant string
	if err := pool.QueryRow(ctx, `SELECT org_id FROM users WHERE user_id = $1`, userID2).Scan(&legacyUserTenant); err != nil {
		t.Fatalf("read backfilled user tenant: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT tenant_id FROM queue_properties WHERE queue_id = $1`, queueID).Scan(&queueTenant); err != nil {
		t.Fatalf("read migrated queue tenant: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT tenant_id FROM topic_properties WHERE topic_id = $1`, topicID).Scan(&topicTenant); err != nil {
		t.Fatalf("read migrated topic tenant: %v", err)
	}
	if legacyUserTenant != legacyTenantID || queueTenant != legacyTenantID || topicTenant != legacyTenantID {
		t.Fatalf("backfilled tenants = user %q queue %q topic %q", legacyUserTenant, queueTenant, topicTenant)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (user_id, email, password, org_id) VALUES ('orphan-user', 'orphan@example.test', 'hash', 'missing-tenant')`); err == nil {
		t.Fatal("upgraded users accepted a missing organization")
	}

	if _, err := pool.Exec(ctx, `INSERT INTO agents (
		agent_id, tenant_id, agent_name, status, auth_version, created_by_kind,
		created_by_id, created_at_ns, updated_at_ns
	) VALUES ($1, $2, 'upgrade-agent', 1, 1, 'system', 'upgrade-test', 1, 1)`, "01J00000000000000000000006", orgID); err != nil {
		t.Fatalf("write new version-five table after upgrade: %v", err)
	}
}

func TestPGEvolverTenantSecurityRejectsConflictingDefaultTenant(t *testing.T) {
	pool := openPGEvolverTestPool(t)
	all := mutations.PostgresStorageMutations()
	versionFive := make(fstest.MapFS, 5)
	for _, name := range []string{
		"001_schema.sql", "002_user.sql", "003_organizations.sql", "004_pubsub.sql", "005_agent_messaging.sql",
	} {
		data, err := fs.ReadFile(all, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		versionFive[name] = &fstest.MapFile{Data: data}
	}
	if err := newPgEvolver(pool, versionFive).MutateSchema(); err != nil {
		t.Fatalf("apply version-five schema: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		UPDATE organizations SET org_code = 'occupied', org_name = 'Conflicting Tenant'
		WHERE org_id = '01HQ5RJNXS6TPXK89PQWY4N8JH'`); err != nil {
		t.Fatalf("create fixed tenant conflict: %v", err)
	}

	if err := newPgEvolver(pool, all).MutateSchema(); err == nil {
		t.Fatal("tenant security migration succeeded with a conflicting fixed tenant")
	}
	var version int
	if err := pool.QueryRow(context.Background(), `SELECT version FROM schema_version WHERE id = 0`).Scan(&version); err != nil {
		t.Fatalf("read schema version: %v", err)
	}
	if version != 5 {
		t.Fatalf("schema version after rejected conflict = %d, want 5", version)
	}
}

func TestPGEvolverTenantSecurityCreatesMissingDefaultTenant(t *testing.T) {
	pool := openPGEvolverTestPool(t)
	all := mutations.PostgresStorageMutations()
	versionFive := make(fstest.MapFS, 5)
	for _, name := range []string{
		"001_schema.sql", "002_user.sql", "003_organizations.sql", "004_pubsub.sql", "005_agent_messaging.sql",
	} {
		data, err := fs.ReadFile(all, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		versionFive[name] = &fstest.MapFile{Data: data}
	}
	if err := newPgEvolver(pool, versionFive).MutateSchema(); err != nil {
		t.Fatalf("apply version-five schema: %v", err)
	}

	const tenantID = "01HQ5RJNXS6TPXK89PQWY4N8JH"
	if _, err := pool.Exec(context.Background(), `DELETE FROM organizations WHERE org_id = $1`, tenantID); err != nil {
		t.Fatalf("delete default tenant: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO users (user_id, email, password) VALUES ('orphan-user', 'orphan@example.test', 'hash')`); err != nil {
		t.Fatalf("seed tenantless user: %v", err)
	}

	if err := newPgEvolver(pool, all).MutateSchema(); err != nil {
		t.Fatalf("apply tenant security migration: %v", err)
	}

	var organizations, users int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM organizations WHERE org_id = $1 AND org_code = 'default' AND org_name = 'Default Organization' AND org_domain IS NULL`, tenantID).Scan(&organizations); err != nil {
		t.Fatalf("read recreated default tenant: %v", err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE user_id = 'orphan-user' AND org_id = $1`, tenantID).Scan(&users); err != nil {
		t.Fatalf("read backfilled user tenant: %v", err)
	}
	if organizations != 1 || users != 1 {
		t.Fatalf("recreated migration state = organizations %d users %d", organizations, users)
	}
}

func TestPGEvolverTenantSecurityBackfillsExactUsageLedgers(t *testing.T) {
	pool := openPGEvolverTestPool(t)
	all := mutations.PostgresStorageMutations()
	versionFive := make(fstest.MapFS, 5)
	for _, name := range []string{
		"001_schema.sql", "002_user.sql", "003_organizations.sql", "004_pubsub.sql", "005_agent_messaging.sql",
	} {
		data, err := fs.ReadFile(all, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		versionFive[name] = &fstest.MapFile{Data: data}
	}
	if err := newPgEvolver(pool, versionFive).MutateSchema(); err != nil {
		t.Fatalf("apply version-five schema: %v", err)
	}

	const tenantID = "01HQ5RJNXS6TPXK89PQWY4N8JH"
	for _, statement := range []string{
		`INSERT INTO queue_properties (queue_id, queue_name, retention_period_seconds, visibility_timeout_seconds, max_receive_attempts) VALUES ('usage-queue', 'usage-queue', 3600, 30, 5)`,
		`INSERT INTO topic_properties (topic_id, topic_name) VALUES ('usage-topic', 'usage-topic')`,
		`INSERT INTO topic_subscriptions (subscription_id, topic_id, queue_id) VALUES ('usage-sub', 'usage-topic', 'usage-queue')`,
		`INSERT INTO agents (agent_id, tenant_id, agent_name, status, auth_version, created_by_kind, created_by_id, created_at_ns, updated_at_ns) VALUES ('usage-agent', '` + tenantID + `', 'usage-agent', 1, 1, 'system', 'test', 1, 1)`,
		`INSERT INTO security_principals (tenant_id, principal_kind, principal_id, status, roles_json, auth_version, updated_at_ns) VALUES ('` + tenantID + `', 'agent', 'usage-agent', 'active', '[]', 1, 1)`,
		`INSERT INTO agent_credentials (credential_id, tenant_id, agent_id, credential_name, credential_prefix, secret_hash, created_at_ns) VALUES ('active-credential', '` + tenantID + `', 'usage-agent', 'active', 'active-prefix', decode(repeat('00', 32), 'hex'), 1)`,
		`INSERT INTO agent_credentials (credential_id, tenant_id, agent_id, credential_name, credential_prefix, secret_hash, created_at_ns, revoked_at_ns) VALUES ('revoked-credential', '` + tenantID + `', 'usage-agent', 'revoked', 'revoked-prefix', decode(repeat('00', 32), 'hex'), 1, 2)`,
		`INSERT INTO direct_messages (message_id, tenant_id, sender_principal_kind, sender_principal_id, kind, schema_version, content_type, attributes_json, correlation_id, causation_id, conversation_id, reply_to_agent_id, body, stored_bytes, created_at_ns) VALUES ('usage-message', '` + tenantID + `', 'agent', 'usage-agent', 'test', 1, 'application/octet-stream', '{}', '', '', '', '', decode('0102', 'hex'), 7, 1)`,
		`INSERT INTO direct_deliveries (delivery_id, tenant_id, recipient_agent_id, message_id, state, available_at_ns) VALUES ('available-delivery', '` + tenantID + `', 'usage-agent', 'usage-message', 'available', 1)`,
		`INSERT INTO direct_deliveries (delivery_id, tenant_id, recipient_agent_id, message_id, state, available_at_ns) VALUES ('leased-delivery', '` + tenantID + `', 'usage-agent', 'usage-message', 'leased', 1)`,
		`INSERT INTO direct_deliveries (delivery_id, tenant_id, recipient_agent_id, message_id, state, available_at_ns, acked_at_ns) VALUES ('acked-delivery', '` + tenantID + `', 'usage-agent', 'usage-message', 'acked', 1, 2)`,
	} {
		if _, err := pool.Exec(context.Background(), statement); err != nil {
			t.Fatalf("seed version-five usage data: %v", err)
		}
	}

	if err := newPgEvolver(pool, all).MutateSchema(); err != nil {
		t.Fatalf("apply tenant security migration: %v", err)
	}

	var agents, topics, subscriptions, storedBytes int
	if err := pool.QueryRow(context.Background(), `SELECT agent_count, topic_count, subscription_count, stored_messaging_bytes FROM tenant_resource_usage WHERE tenant_id = $1`, tenantID).
		Scan(&agents, &topics, &subscriptions, &storedBytes); err != nil {
		t.Fatalf("read tenant usage ledger: %v", err)
	}
	if agents != 1 || topics != 1 || subscriptions != 1 || storedBytes != 7 {
		t.Fatalf("tenant usage = agents %d topics %d subscriptions %d bytes %d", agents, topics, subscriptions, storedBytes)
	}

	var pending, pendingBytes, agentSubscriptions, activeCredentials int
	if err := pool.QueryRow(context.Background(), `SELECT pending_direct_count, pending_direct_bytes, subscription_count, active_credential_count FROM agent_resource_usage WHERE tenant_id = $1 AND agent_id = 'usage-agent'`, tenantID).
		Scan(&pending, &pendingBytes, &agentSubscriptions, &activeCredentials); err != nil {
		t.Fatalf("read agent usage ledger: %v", err)
	}
	if pending != 2 || pendingBytes != 14 || agentSubscriptions != 0 || activeCredentials != 1 {
		t.Fatalf("agent usage = pending %d bytes %d subscriptions %d credentials %d", pending, pendingBytes, agentSubscriptions, activeCredentials)
	}
}

func TestPostgresConcurrentBootstrapCreatesExactlyOneAdmin(t *testing.T) {
	pool := openPGEvolverTestPool(t)
	if err := newPgEvolver(pool, mutations.PostgresStorageMutations()).MutateSchema(); err != nil {
		t.Fatalf("apply storage schema: %v", err)
	}
	storage, err := onboardpg.NewStorage(pool, nil)
	if err != nil {
		t.Fatalf("create onboarding storage: %v", err)
	}

	start := make(chan struct{})
	var successes atomic.Int32
	var group sync.WaitGroup
	for index := range 10 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start

			now := time.Now().UTC()
			id := fmt.Sprintf("bootstrap-%02d", index)
			record := onboarding.BootstrapRecord{
				Admin: onboarding.InitialAdmin{
					UserID: id, Email: id + "@example.test", Password: "password-hash", Verified: true,
					CreatedAt: now, TenantID: principal.LegacyTenantID, AuthVersion: 1, Status: "active",
				},
				RefreshToken: onboarding.RefreshTokenRecord{
					ID: id, AccountID: id, TokenHash: make([]byte, 32), CreatedAt: now,
					ExpiresAt: now.Add(time.Hour), LastUsedAt: now,
				},
				Audit: onboarding.AuditEvent{
					ID: id, TenantID: principal.LegacyTenantID, PrincipalKind: string(principal.KindHuman),
					PrincipalID: id, Action: "onboarding.bootstrap", ResourceKind: "tenant",
					ResourceID: principal.LegacyTenantID, Outcome: "success", MetadataJSON: []byte(`{}`),
					CreatedAt: now,
				},
			}
			record.RefreshToken.TokenHash[31] = byte(index + 1)
			if err := storage.Bootstrap(context.Background(), record); err == nil {
				successes.Add(1)
			}
		}()
	}
	close(start)
	group.Wait()

	if got := successes.Load(); got != 1 {
		t.Fatalf("successful bootstraps = %d, want 1", got)
	}
	var users, assignments, principals, sessions, audits int
	for query, destination := range map[string]*int{
		`SELECT count(*) FROM users`:                                                       &users,
		`SELECT count(*) FROM user_roles`:                                                  &assignments,
		`SELECT count(*) FROM security_principals WHERE principal_kind = 'human'`:          &principals,
		`SELECT count(*) FROM refresh_tokens`:                                              &sessions,
		`SELECT count(*) FROM security_audit_events WHERE action = 'onboarding.bootstrap'`: &audits,
	} {
		if err := pool.QueryRow(context.Background(), query).Scan(destination); err != nil {
			t.Fatalf("read bootstrap effects: %v", err)
		}
	}
	if users != 1 || assignments != 1 || principals != 1 || sessions != 1 || audits != 1 {
		t.Fatalf("bootstrap effects = users %d assignments %d principals %d sessions %d audits %d",
			users, assignments, principals, sessions, audits)
	}
}

func TestPostgresOAuthSyncUpsertsHumanSecurityPrincipal(t *testing.T) {
	pool := openPGEvolverTestPool(t)
	if err := newPgEvolver(pool, mutations.PostgresStorageMutations()).MutateSchema(); err != nil {
		t.Fatalf("apply storage schema: %v", err)
	}
	storage, err := oauthpg.NewStorage(pool, nil)
	if err != nil {
		t.Fatalf("create OAuth storage: %v", err)
	}

	ctx := context.Background()
	user := oauth.OAuthUser{Subject: "subject-1", Email: "oauth@example.test"}
	if err := storage.SyncOAuthUser(ctx, user, "example", principal.LegacyTenantID); err != nil {
		t.Fatalf("sync OAuth user: %v", err)
	}
	synced, err := storage.GetUserByOAuthSub(ctx, "example", user.Subject)
	if err != nil {
		t.Fatalf("get synchronized user: %v", err)
	}

	var tenantID, kind, status, rolesJSON string
	var authVersion int64
	if err := pool.QueryRow(ctx, `
		SELECT tenant_id, principal_kind, status, roles_json::text, auth_version
		FROM security_principals
		WHERE principal_id = $1`, synced.UserID,
	).Scan(&tenantID, &kind, &status, &rolesJSON, &authVersion); err != nil {
		t.Fatalf("get human security principal: %v", err)
	}
	if tenantID != principal.LegacyTenantID || kind != "human" || status != "active" ||
		rolesJSON != "[]" || authVersion != 1 {
		t.Fatalf(
			"security principal = (%q, %q, %q, %s, %d), want (%q, human, active, [], 1)",
			tenantID, kind, status, rolesJSON, authVersion, principal.LegacyTenantID,
		)
	}

	const tenantB = "01J0000000000000000000000B"
	if _, err := pool.Exec(ctx, `
		INSERT INTO organizations (org_id, org_code, org_name)
		VALUES ($1, 'tenant-b', 'Tenant B')`, tenantB); err != nil {
		t.Fatalf("create reassignment tenant: %v", err)
	}
	if err := storage.SyncOAuthUser(ctx, user, "example", tenantB); err != nil {
		t.Fatalf("reassign OAuth user: %v", err)
	}

	var currentTenant string
	var currentVersion, oldProjectionCount, newProjectionCount int64
	if err := pool.QueryRow(ctx, `SELECT org_id, auth_version FROM users WHERE user_id = $1`, synced.UserID).
		Scan(&currentTenant, &currentVersion); err != nil {
		t.Fatalf("get reassigned OAuth user: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM security_principals
		WHERE tenant_id = $1 AND principal_kind = 'human' AND principal_id = $2`,
		principal.LegacyTenantID, synced.UserID,
	).Scan(&oldProjectionCount); err != nil {
		t.Fatalf("count old human projection: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM security_principals
		WHERE tenant_id = $1 AND principal_kind = 'human' AND principal_id = $2 AND auth_version = 2`,
		tenantB, synced.UserID,
	).Scan(&newProjectionCount); err != nil {
		t.Fatalf("count new human projection: %v", err)
	}
	if currentTenant != tenantB || currentVersion != 2 || oldProjectionCount != 0 || newProjectionCount != 1 {
		t.Fatalf(
			"reassignment = tenant %q version %d old projections %d new projections %d, want %q/2/0/1",
			currentTenant, currentVersion, oldProjectionCount, newProjectionCount, tenantB,
		)
	}
}

func TestPostgresRevokeSessionRollsBackDenylistWhenRefreshDeleteFails(t *testing.T) {
	pool := openPGEvolverTestPool(t)
	if err := newPgEvolver(pool, mutations.PostgresStorageMutations()).MutateSchema(); err != nil {
		t.Fatalf("apply storage schema: %v", err)
	}
	storage, err := accountpg.NewStorage(pool, nil)
	if err != nil {
		t.Fatalf("create account storage: %v", err)
	}

	ctx := context.Background()
	now := time.Now().UTC()
	user := account.Account{
		ID: "logout-user", Email: "logout@example.test", Password: "password-hash", Verified: true,
		CreatedAt: now, UpdatedAt: now, TenantID: principal.LegacyTenantID,
		AuthVersion: 1, Status: account.AccountStatusActive,
	}
	if err := storage.CreateAccount(ctx, user); err != nil {
		t.Fatalf("create logout account: %v", err)
	}
	refresh := account.RefreshToken{
		ID: "logout-jti", AID: user.ID, TokenHash: make([]byte, 32),
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastUsedAt: now,
	}
	if err := storage.CreateRefreshToken(ctx, refresh); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE FUNCTION reject_refresh_delete() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'injected refresh delete failure';
		END
		$$;
		CREATE TRIGGER reject_refresh_delete
		BEFORE DELETE ON refresh_tokens
		FOR EACH ROW EXECUTE FUNCTION reject_refresh_delete()`); err != nil {
		t.Fatalf("install refresh deletion failure: %v", err)
	}

	err = storage.RevokeSession(ctx, account.DeniedToken{
		TokenID: refresh.ID, AID: user.ID, ExpiresAt: refresh.ExpiresAt,
		CreatedAt: now, Reason: "logout",
	})
	if err == nil {
		t.Fatal("RevokeSession() unexpectedly succeeded")
	}

	var denied, remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM denylist WHERE token_id = $1`, refresh.ID).Scan(&denied); err != nil {
		t.Fatalf("count denied access token: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE id = $1`, refresh.ID).Scan(&remaining); err != nil {
		t.Fatalf("count refresh token: %v", err)
	}
	if denied != 0 || remaining != 1 {
		t.Fatalf("partial revocation state = denied %d refresh %d, want 0/1", denied, remaining)
	}
}

func TestPostgresRoleDeleteRefusesAssignmentsAndDoesNotCascadeRaces(t *testing.T) {
	pool := openPGEvolverTestPool(t)
	if err := newPgEvolver(pool, mutations.PostgresStorageMutations()).MutateSchema(); err != nil {
		t.Fatalf("apply storage schema: %v", err)
	}
	accounts, err := accountpg.NewStorage(pool, nil)
	if err != nil {
		t.Fatalf("create account storage: %v", err)
	}
	roles, err := rbacpg.NewStorage(pool, nil)
	if err != nil {
		t.Fatalf("create RBAC storage: %v", err)
	}

	ctx := context.Background()
	now := time.Now().UTC()
	for _, id := range []string{"role-user-1", "role-user-2"} {
		if err := accounts.CreateAccount(ctx, account.Account{
			ID: id, Email: id + "@example.test", Password: "password-hash", Verified: true,
			CreatedAt: now, UpdatedAt: now, TenantID: principal.LegacyTenantID,
			AuthVersion: 1, Status: account.AccountStatusActive,
		}); err != nil {
			t.Fatalf("create role account %s: %v", id, err)
		}
	}

	if err := roles.CreateRole(ctx, rbac.Role{RoleID: "role-in-use", RoleName: "role-in-use"}); err != nil {
		t.Fatalf("create in-use role: %v", err)
	}
	if err := roles.AssignRoleToUser(ctx, "role-user-1", "role-in-use"); err != nil {
		t.Fatalf("assign in-use role: %v", err)
	}
	if err := roles.DeleteRole(ctx, "role-in-use"); !errors.Is(err, rbac.ErrRoleInUse) {
		t.Fatalf("DeleteRole() error = %v, want ErrRoleInUse", err)
	}
	var roleCount, assignmentCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM roles WHERE role_id = 'role-in-use'`).Scan(&roleCount); err != nil {
		t.Fatalf("count preserved role: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_roles WHERE role_id = 'role-in-use'`).Scan(&assignmentCount); err != nil {
		t.Fatalf("count preserved assignment: %v", err)
	}
	if roleCount != 1 || assignmentCount != 1 {
		t.Fatalf("in-use delete state = role %d assignment %d, want 1/1", roleCount, assignmentCount)
	}

	for index := range 10 {
		roleID := fmt.Sprintf("role-race-%02d", index)
		if err := roles.CreateRole(ctx, rbac.Role{RoleID: roleID, RoleName: roleID}); err != nil {
			t.Fatalf("create raced role: %v", err)
		}

		start := make(chan struct{})
		var assignErr, deleteErr error
		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			<-start
			assignErr = roles.AssignRoleToUser(ctx, "role-user-2", roleID)
		}()
		go func() {
			defer group.Done()
			<-start
			deleteErr = roles.DeleteRole(ctx, roleID)
		}()
		close(start)
		group.Wait()

		if err := pool.QueryRow(ctx, `SELECT count(*) FROM roles WHERE role_id = $1`, roleID).Scan(&roleCount); err != nil {
			t.Fatalf("count raced role: %v", err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_roles WHERE user_id = 'role-user-2' AND role_id = $1`, roleID).Scan(&assignmentCount); err != nil {
			t.Fatalf("count raced assignment: %v", err)
		}

		switch {
		case roleCount == 1 && assignmentCount == 1:
			if assignErr != nil || deleteErr == nil {
				t.Fatalf("assignment winner %s = assign %v delete %v", roleID, assignErr, deleteErr)
			}
		case roleCount == 0 && assignmentCount == 0:
			if deleteErr != nil || assignErr == nil {
				t.Fatalf("deletion winner %s = assign %v delete %v", roleID, assignErr, deleteErr)
			}
		default:
			t.Fatalf(
				"unsafe role race %s = assign %v delete %v role %d assignment %d",
				roleID, assignErr, deleteErr, roleCount, assignmentCount,
			)
		}
	}
}

func TestPostgresLegacyQueueAndTopicTenantIsolation(t *testing.T) {
	pool := openPGEvolverTestPool(t)
	if err := newPgEvolver(pool, mutations.PostgresStorageMutations()).MutateSchema(); err != nil {
		t.Fatalf("apply storage schema: %v", err)
	}
	store, err := queuepg.New(pool, queuepg.WithGCTimeout(time.Hour))
	if err != nil {
		t.Fatalf("create queue storage: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO organizations (org_id, org_code, org_name)
		VALUES ('tenant-b', 'tenant-b', 'Tenant B')`); err != nil {
		t.Fatalf("seed tenant B: %v", err)
	}

	legacyCtx := principal.With(context.Background(), principal.Principal{
		Kind: principal.KindSystem, ID: principal.LegacyPrincipalID, TenantID: principal.LegacyTenantID,
	})
	humanACtx := principal.With(context.Background(), principal.Principal{
		Kind: principal.KindHuman, ID: "human-a", TenantID: principal.LegacyTenantID,
	})
	humanBCtx := principal.With(context.Background(), principal.Principal{
		Kind: principal.KindHuman, ID: "human-b", TenantID: "tenant-b",
	})

	legacyQueue, err := store.CreateQueue(legacyCtx, &v1.CreateQueueRequest{QueueName: "shared"})
	if err != nil {
		t.Fatalf("create legacy queue: %v", err)
	}
	privateQueue, err := store.CreateQueue(humanACtx, &v1.CreateQueueRequest{QueueName: "private-a"})
	if err != nil {
		t.Fatalf("create tenant-A queue: %v", err)
	}
	if _, err := store.CreateQueue(humanBCtx, &v1.CreateQueueRequest{QueueName: "shared"}); err != nil {
		t.Fatalf("create same-name tenant-B queue: %v", err)
	}
	legacyList, err := store.ListQueues(legacyCtx, &v1.ListQueuesRequest{Limit: 10})
	if err != nil {
		t.Fatalf("list legacy queues: %v", err)
	}
	if len(legacyList.GetQueues()) != 1 || legacyList.GetQueues()[0].GetQueueId() != legacyQueue.GetQueueId() {
		t.Fatalf("legacy queues = %#v", legacyList.GetQueues())
	}
	if _, err := store.Send(humanBCtx, &v1.SendRequest{
		QueueId: privateQueue.GetQueueId(), Messages: []*v1.SendMessage{{Body: []byte("cross-tenant")}},
	}); !errors.Is(err, pqerr.ErrNotFound) {
		t.Fatalf("cross-tenant send error = %v, want not found", err)
	}

	legacyTopic, err := store.CreateTopic(legacyCtx, &queueservice.CreateTopicRequest{TopicName: "shared"})
	if err != nil {
		t.Fatalf("create legacy topic: %v", err)
	}
	privateTopic, err := store.CreateTopic(humanACtx, &queueservice.CreateTopicRequest{TopicName: "private-a"})
	if err != nil {
		t.Fatalf("create tenant-A topic: %v", err)
	}
	if _, err := store.CreateTopic(humanBCtx, &queueservice.CreateTopicRequest{TopicName: "shared"}); err != nil {
		t.Fatalf("create same-name tenant-B topic: %v", err)
	}
	legacyTopics, err := store.ListTopics(legacyCtx)
	if err != nil {
		t.Fatalf("list legacy topics: %v", err)
	}
	if len(legacyTopics.Topics) != 1 || legacyTopics.Topics[0].TopicID != legacyTopic.TopicID {
		t.Fatalf("legacy topics = %#v", legacyTopics.Topics)
	}
	if _, err := store.Publish(humanBCtx, privateTopic.TopicID, &queueservice.PublishRequest{
		Messages: []queueservice.PublishMessage{{Body: []byte("cross-tenant")}},
	}); err == nil {
		t.Fatal("cross-tenant publish unexpectedly succeeded")
	}
}
