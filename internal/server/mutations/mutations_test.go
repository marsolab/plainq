package mutations

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/marsolab/servekit/dbkit/litekit"
)

func TestSQLiteMutationsApplyOnFreshDatabase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mutations fs.FS
	}{
		{
			name:      "storage",
			mutations: SqliteStorageMutations(),
		},
		{
			name:      "telemetry",
			mutations: TelemetryMutation(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			validated, err := ValidatedStorageFS(tt.mutations)
			if err != nil {
				t.Fatalf("validate mutations: %v", err)
			}

			conn, err := litekit.New(filepath.Join(t.TempDir(), "plainq.db"))
			if err != nil {
				t.Fatalf("new sqlite connection: %v", err)
			}

			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Errorf("close sqlite connection: %v", err)
				}
			})

			evolver, err := litekit.NewEvolver(conn, validated)
			if err != nil {
				t.Fatalf("new evolver: %v", err)
			}

			if err := evolver.MutateSchema(); err != nil {
				t.Fatalf("mutate schema: %v", err)
			}

			if err := evolver.MutateSchema(); err != nil {
				t.Fatalf("mutate schema again: %v", err)
			}

			wantVersion := countSQLMutations(t, validated)
			var gotVersion int
			if err := conn.QueryRow("select version from schema_version where id = 0").Scan(&gotVersion); err != nil {
				t.Fatalf("query schema version: %v", err)
			}
			if gotVersion != wantVersion {
				t.Fatalf("schema version = %d, want %d", gotVersion, wantVersion)
			}
		})
	}
}

func TestSQLiteStorageUpgradeFromVersionFourPreservesData(t *testing.T) {
	allMutations := SqliteStorageMutations()
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

	validatedV4, err := ValidatedStorageFS(versionFour)
	if err != nil {
		t.Fatalf("validate version-four mutations: %v", err)
	}

	conn, err := litekit.New(filepath.Join(t.TempDir(), "upgrade.db"))
	if err != nil {
		t.Fatalf("new sqlite connection: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close sqlite connection: %v", err)
		}
	})

	v4Evolver, err := litekit.NewEvolver(conn, validatedV4)
	if err != nil {
		t.Fatalf("new version-four evolver: %v", err)
	}
	if err := v4Evolver.MutateSchema(); err != nil {
		t.Fatalf("apply version-four schema: %v", err)
	}

	const (
		orgID   = "01J00000000000000000000001"
		userID  = "01J00000000000000000000002"
		userID2 = "01J00000000000000000000007"
		queueID = "01J00000000000000000000003"
		topicID = "01J00000000000000000000004"
	)
	statements := []string{
		`INSERT INTO organizations (org_id, org_code, org_name) VALUES ('` + orgID + `', 'upgrade', 'Upgrade Tenant')`,
		`INSERT INTO users (user_id, email, password, org_id) VALUES ('` + userID + `', 'upgrade@example.test', 'existing-hash', '` + orgID + `')`,
		`INSERT INTO users (user_id, email, password) VALUES ('` + userID2 + `', 'legacy@example.test', 'existing-hash-2')`,
		`INSERT INTO user_roles (user_id, role_id) VALUES ('` + userID + `', '01HQ5RJNXS6TPXK89PQWY4N8JD')`,
		`INSERT INTO user_teams (user_id, team_id) VALUES ('` + userID + `', '01HQ5RJNXS6TPXK89PQWY4N8JI')`,
		`INSERT INTO refresh_tokens (id, aid, token) VALUES ('01J00000000000000000000008', '` + userID + `', 'clear-refresh')`,
		`INSERT INTO denylist (token, denied_until) VALUES ('clear-access', 9999999999)`,
		`INSERT INTO queue_properties (queue_id, queue_name, retention_period_seconds, visibility_timeout_seconds, max_receive_attempts) VALUES ('` + queueID + `', 'upgrade-queue', 3600, 30, 5)`,
		`INSERT INTO topic_properties (topic_id, topic_name) VALUES ('` + topicID + `', 'upgrade-topic')`,
		`INSERT INTO topic_subscriptions (subscription_id, topic_id, queue_id) VALUES ('01J00000000000000000000005', '` + topicID + `', '` + queueID + `')`,
	}
	for _, statement := range statements {
		if _, err := conn.Exec(statement); err != nil {
			t.Fatalf("seed version-four data: %v", err)
		}
	}

	if err := ApplySQLiteStorage(context.Background(), conn); err != nil {
		t.Fatalf("upgrade version-four schema: %v", err)
	}

	var version, users, subscriptions, roles, teams, sessions, denied, principals int
	if err := conn.QueryRow(`SELECT version FROM schema_version WHERE id = 0`).Scan(&version); err != nil {
		t.Fatalf("read upgraded schema version: %v", err)
	}
	if err := conn.QueryRow(`SELECT count(*) FROM users WHERE user_id = ? AND org_id = ?`, userID, orgID).Scan(&users); err != nil {
		t.Fatalf("read preserved user: %v", err)
	}
	if err := conn.QueryRow(`SELECT count(*) FROM topic_subscriptions WHERE topic_id = ? AND queue_id = ?`, topicID, queueID).Scan(&subscriptions); err != nil {
		t.Fatalf("read preserved subscription: %v", err)
	}
	if err := conn.QueryRow(`SELECT count(*) FROM user_roles WHERE user_id = ?`, userID).Scan(&roles); err != nil {
		t.Fatalf("read preserved user role: %v", err)
	}
	if err := conn.QueryRow(`SELECT count(*) FROM user_teams WHERE user_id = ?`, userID).Scan(&teams); err != nil {
		t.Fatalf("read preserved user team: %v", err)
	}
	if err := conn.QueryRow(`SELECT count(*) FROM refresh_tokens`).Scan(&sessions); err != nil {
		t.Fatalf("read revoked refresh sessions: %v", err)
	}
	if err := conn.QueryRow(`SELECT count(*) FROM denylist`).Scan(&denied); err != nil {
		t.Fatalf("read rebuilt denylist: %v", err)
	}
	if err := conn.QueryRow(`SELECT count(*) FROM security_principals WHERE principal_kind = 'human'`).Scan(&principals); err != nil {
		t.Fatalf("read human principal projections: %v", err)
	}
	if version != 6 || users != 1 || subscriptions != 1 || roles != 1 || teams != 1 || sessions != 0 || denied != 0 || principals != 2 {
		t.Fatalf("upgrade state = version %d users %d subscriptions %d roles %d teams %d sessions %d denied %d principals %d", version, users, subscriptions, roles, teams, sessions, denied, principals)
	}

	var legacyUserTenant, queueTenant, topicTenant string
	if err := conn.QueryRow(`SELECT org_id FROM users WHERE user_id = ?`, userID2).Scan(&legacyUserTenant); err != nil {
		t.Fatalf("read backfilled user tenant: %v", err)
	}
	if err := conn.QueryRow(`SELECT tenant_id FROM queue_properties WHERE queue_id = ?`, queueID).Scan(&queueTenant); err != nil {
		t.Fatalf("read queue tenant: %v", err)
	}
	if err := conn.QueryRow(`SELECT tenant_id FROM topic_properties WHERE topic_id = ?`, topicID).Scan(&topicTenant); err != nil {
		t.Fatalf("read topic tenant: %v", err)
	}
	const legacyTenantID = "01HQ5RJNXS6TPXK89PQWY4N8JH"
	if legacyUserTenant != legacyTenantID || queueTenant != legacyTenantID || topicTenant != legacyTenantID {
		t.Fatalf("backfill tenants = user %q queue %q topic %q, want %q", legacyUserTenant, queueTenant, topicTenant, legacyTenantID)
	}

	var orgNotNull int
	rows, err := conn.Query(`PRAGMA table_info(users)`)
	if err != nil {
		t.Fatalf("read users schema: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, pk int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &pk); err != nil {
			t.Fatalf("scan users schema: %v", err)
		}
		if name == "org_id" {
			orgNotNull = notNull
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate users schema: %v", err)
	}
	if orgNotNull != 1 {
		t.Fatalf("users.org_id notnull = %d, want 1", orgNotNull)
	}

	if _, err := conn.Exec(`INSERT INTO agents (
		agent_id, tenant_id, agent_name, status, auth_version, created_by_kind,
		created_by_id, created_at_ns, updated_at_ns
	) VALUES (?, ?, 'upgrade-agent', 1, 1, 'system', 'upgrade-test', 1, 1)`, "01J00000000000000000000006", orgID); err != nil {
		t.Fatalf("write new version-five table after upgrade: %v", err)
	}
}

func TestSQLiteTenantSecurityMigrationRejectsConflictingDefaultTenant(t *testing.T) {
	allMutations := SqliteStorageMutations()
	versionFive := make(fstest.MapFS, 5)
	for _, name := range []string{
		"001_schema.sql", "002_user.sql", "003_organizations.sql", "004_pubsub.sql", "005_agent_messaging.sql",
	} {
		data, err := fs.ReadFile(allMutations, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		versionFive[name] = &fstest.MapFile{Data: data}
	}

	validatedV5, err := ValidatedStorageFS(versionFive)
	if err != nil {
		t.Fatalf("validate version-five migrations: %v", err)
	}
	conn, err := litekit.New(filepath.Join(t.TempDir(), "conflict.db"))
	if err != nil {
		t.Fatalf("new sqlite connection: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	v5, err := litekit.NewEvolver(conn, validatedV5)
	if err != nil {
		t.Fatalf("new v5 evolver: %v", err)
	}
	if err := v5.MutateSchema(); err != nil {
		t.Fatalf("apply v5: %v", err)
	}
	if _, err := conn.Exec(`UPDATE organizations SET org_code = 'occupied', org_name = 'Conflicting Tenant' WHERE org_id = '01HQ5RJNXS6TPXK89PQWY4N8JH'`); err != nil {
		t.Fatalf("create conflict: %v", err)
	}

	if err := ApplySQLiteStorage(context.Background(), conn); err == nil {
		t.Fatal("tenant security migration succeeded with a conflicting fixed tenant")
	}

	var version int
	if err := conn.QueryRow(`SELECT version FROM schema_version WHERE id = 0`).Scan(&version); err != nil {
		t.Fatalf("read schema version: %v", err)
	}
	if version != 5 {
		t.Fatalf("schema version = %d, want rollback at 5", version)
	}
}

func TestSQLiteTenantSecurityMigrationCreatesMissingDefaultTenant(t *testing.T) {
	allMutations := SqliteStorageMutations()
	versionFive := make(fstest.MapFS, 5)
	for _, name := range []string{
		"001_schema.sql", "002_user.sql", "003_organizations.sql", "004_pubsub.sql", "005_agent_messaging.sql",
	} {
		data, err := fs.ReadFile(allMutations, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		versionFive[name] = &fstest.MapFile{Data: data}
	}

	validatedV5, err := ValidatedStorageFS(versionFive)
	if err != nil {
		t.Fatalf("validate version-five migrations: %v", err)
	}
	conn, err := litekit.New(filepath.Join(t.TempDir(), "missing-default.db"))
	if err != nil {
		t.Fatalf("new sqlite connection: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	v5, err := litekit.NewEvolver(conn, validatedV5)
	if err != nil {
		t.Fatalf("new v5 evolver: %v", err)
	}
	if err := v5.MutateSchema(); err != nil {
		t.Fatalf("apply v5: %v", err)
	}

	const tenantID = "01HQ5RJNXS6TPXK89PQWY4N8JH"
	if _, err := conn.Exec(`DELETE FROM organizations WHERE org_id = ?`, tenantID); err != nil {
		t.Fatalf("delete default tenant: %v", err)
	}
	if _, err := conn.Exec(`INSERT INTO users (user_id, email, password) VALUES ('orphan-user', 'orphan@example.test', 'hash')`); err != nil {
		t.Fatalf("seed tenantless user: %v", err)
	}

	if err := ApplySQLiteStorage(context.Background(), conn); err != nil {
		t.Fatalf("apply tenant security migration: %v", err)
	}

	var organizations, users int
	if err := conn.QueryRow(`SELECT count(*) FROM organizations WHERE org_id = ? AND org_code = 'default' AND org_name = 'Default Organization' AND org_domain IS NULL`, tenantID).Scan(&organizations); err != nil {
		t.Fatalf("read recreated default tenant: %v", err)
	}
	if err := conn.QueryRow(`SELECT count(*) FROM users WHERE user_id = 'orphan-user' AND org_id = ?`, tenantID).Scan(&users); err != nil {
		t.Fatalf("read backfilled user tenant: %v", err)
	}
	if organizations != 1 || users != 1 {
		t.Fatalf("recreated migration state = organizations %d users %d", organizations, users)
	}
}

func TestSQLiteTenantSecurityBackfillsExactUsageLedgers(t *testing.T) {
	allMutations := SqliteStorageMutations()
	versionFive := make(fstest.MapFS, 5)
	for _, name := range []string{
		"001_schema.sql", "002_user.sql", "003_organizations.sql", "004_pubsub.sql", "005_agent_messaging.sql",
	} {
		data, err := fs.ReadFile(allMutations, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		versionFive[name] = &fstest.MapFile{Data: data}
	}

	validatedV5, err := ValidatedStorageFS(versionFive)
	if err != nil {
		t.Fatalf("validate version-five migrations: %v", err)
	}
	conn, err := litekit.New(filepath.Join(t.TempDir(), "usage.db"))
	if err != nil {
		t.Fatalf("new sqlite connection: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	v5, err := litekit.NewEvolver(conn, validatedV5)
	if err != nil {
		t.Fatalf("new v5 evolver: %v", err)
	}
	if err := v5.MutateSchema(); err != nil {
		t.Fatalf("apply v5: %v", err)
	}

	const tenantID = "01HQ5RJNXS6TPXK89PQWY4N8JH"
	for _, statement := range []string{
		`INSERT INTO queue_properties (queue_id, queue_name, retention_period_seconds, visibility_timeout_seconds, max_receive_attempts) VALUES ('usage-queue', 'usage-queue', 3600, 30, 5)`,
		`INSERT INTO topic_properties (topic_id, topic_name) VALUES ('usage-topic', 'usage-topic')`,
		`INSERT INTO topic_subscriptions (subscription_id, topic_id, queue_id) VALUES ('usage-sub', 'usage-topic', 'usage-queue')`,
		`INSERT INTO agents (agent_id, tenant_id, agent_name, status, auth_version, created_by_kind, created_by_id, created_at_ns, updated_at_ns) VALUES ('usage-agent', '` + tenantID + `', 'usage-agent', 1, 1, 'system', 'test', 1, 1)`,
		`INSERT INTO security_principals (tenant_id, principal_kind, principal_id, status, roles_json, auth_version, updated_at_ns) VALUES ('` + tenantID + `', 'agent', 'usage-agent', 'active', '[]', 1, 1)`,
		`INSERT INTO agent_credentials (credential_id, tenant_id, agent_id, credential_name, credential_prefix, secret_hash, created_at_ns) VALUES ('active-credential', '` + tenantID + `', 'usage-agent', 'active', 'active-prefix', zeroblob(32), 1)`,
		`INSERT INTO agent_credentials (credential_id, tenant_id, agent_id, credential_name, credential_prefix, secret_hash, created_at_ns, revoked_at_ns) VALUES ('revoked-credential', '` + tenantID + `', 'usage-agent', 'revoked', 'revoked-prefix', zeroblob(32), 1, 2)`,
		`INSERT INTO direct_messages (message_id, tenant_id, sender_principal_kind, sender_principal_id, kind, schema_version, content_type, attributes_json, correlation_id, causation_id, conversation_id, reply_to_agent_id, body, stored_bytes, created_at_ns) VALUES ('usage-message', '` + tenantID + `', 'agent', 'usage-agent', 'test', 1, 'application/octet-stream', '{}', '', '', '', '', x'0102', 7, 1)`,
		`INSERT INTO direct_deliveries (delivery_id, tenant_id, recipient_agent_id, message_id, state, available_at_ns) VALUES ('available-delivery', '` + tenantID + `', 'usage-agent', 'usage-message', 'available', 1)`,
		`INSERT INTO direct_deliveries (delivery_id, tenant_id, recipient_agent_id, message_id, state, available_at_ns) VALUES ('leased-delivery', '` + tenantID + `', 'usage-agent', 'usage-message', 'leased', 1)`,
		`INSERT INTO direct_deliveries (delivery_id, tenant_id, recipient_agent_id, message_id, state, available_at_ns, acked_at_ns) VALUES ('acked-delivery', '` + tenantID + `', 'usage-agent', 'usage-message', 'acked', 1, 2)`,
	} {
		if _, err := conn.Exec(statement); err != nil {
			t.Fatalf("seed version-five usage data: %v", err)
		}
	}

	if err := ApplySQLiteStorage(context.Background(), conn); err != nil {
		t.Fatalf("apply tenant security migration: %v", err)
	}

	var agents, topics, subscriptions, storedBytes int
	if err := conn.QueryRow(`SELECT agent_count, topic_count, subscription_count, stored_messaging_bytes FROM tenant_resource_usage WHERE tenant_id = ?`, tenantID).
		Scan(&agents, &topics, &subscriptions, &storedBytes); err != nil {
		t.Fatalf("read tenant usage ledger: %v", err)
	}
	if agents != 1 || topics != 1 || subscriptions != 1 || storedBytes != 7 {
		t.Fatalf("tenant usage = agents %d topics %d subscriptions %d bytes %d", agents, topics, subscriptions, storedBytes)
	}

	var pending, pendingBytes, agentSubscriptions, activeCredentials int
	if err := conn.QueryRow(`SELECT pending_direct_count, pending_direct_bytes, subscription_count, active_credential_count FROM agent_resource_usage WHERE tenant_id = ? AND agent_id = 'usage-agent'`, tenantID).
		Scan(&pending, &pendingBytes, &agentSubscriptions, &activeCredentials); err != nil {
		t.Fatalf("read agent usage ledger: %v", err)
	}
	if pending != 2 || pendingBytes != 14 || agentSubscriptions != 0 || activeCredentials != 1 {
		t.Fatalf("agent usage = pending %d bytes %d subscriptions %d credentials %d", pending, pendingBytes, agentSubscriptions, activeCredentials)
	}
}

func TestValidatedStorageFSSortsNumericVersionsThroughTen(t *testing.T) {
	t.Parallel()

	input := make(fstest.MapFS, 10)
	for version := 1; version <= 10; version++ {
		name := fmt.Sprintf("%03d_migration.sql", version)
		if version == 10 {
			name = "010_future.sql"
		}
		input[name] = &fstest.MapFile{Data: []byte("SELECT 1;")}
	}

	validated, err := ValidatedStorageFS(input)
	if err != nil {
		t.Fatalf("validate mutations: %v", err)
	}

	entries, err := fs.ReadDir(validated, ".")
	if err != nil {
		t.Fatalf("read validated mutations: %v", err)
	}
	if got, want := entries[8].Name(), "009_migration.sql"; got != want {
		t.Fatalf("ninth migration = %q, want %q", got, want)
	}
	if got, want := entries[9].Name(), "010_future.sql"; got != want {
		t.Fatalf("tenth migration = %q, want %q", got, want)
	}
}

func TestValidatedStorageFSRejectsUnsafeVersionSets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   fstest.MapFS
		wantErr string
	}{
		{
			name: "duplicate",
			input: fstest.MapFS{
				"001_first.sql":  &fstest.MapFile{Data: []byte("SELECT 1;")},
				"001_second.sql": &fstest.MapFile{Data: []byte("SELECT 2;")},
			},
			wantErr: "duplicate migration version 1",
		},
		{
			name: "missing",
			input: fstest.MapFS{
				"001_first.sql": &fstest.MapFile{Data: []byte("SELECT 1;")},
				"003_third.sql": &fstest.MapFile{Data: []byte("SELECT 3;")},
			},
			wantErr: "missing migration version 2",
		},
		{
			name: "non-numeric",
			input: fstest.MapFS{
				"001_first.sql": &fstest.MapFile{Data: []byte("SELECT 1;")},
				"future.sql":    &fstest.MapFile{Data: []byte("SELECT 2;")},
			},
			wantErr: "non-numeric migration version",
		},
		{
			name: "non-monotonic",
			input: fstest.MapFS{
				"1_first.sql":  &fstest.MapFile{Data: []byte("SELECT 1;")},
				"2_second.sql": &fstest.MapFile{Data: []byte("SELECT 2;")},
				"10_tenth.sql": &fstest.MapFile{Data: []byte("SELECT 10;")},
			},
			wantErr: "non-monotonic migration versions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := ValidatedStorageFS(tt.input)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidatedStorageFS error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func countSQLMutations(t *testing.T, mutations fs.FS) int {
	t.Helper()

	entries, err := fs.ReadDir(mutations, ".")
	if err != nil {
		t.Fatalf("read mutations: %v", err)
	}

	var count int
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".sql") {
			count++
		}
	}

	return count
}
