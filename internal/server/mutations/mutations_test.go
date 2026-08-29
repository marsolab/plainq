package mutations

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/marsolab/servekit/dbkit/litekit"
)

func TestTelemetryMigration4UpgradesSeededVersion3Database(t *testing.T) {
	t.Parallel()

	conn, err := litekit.New(filepath.Join(t.TempDir(), "plainq.db"))
	if err != nil {
		t.Fatalf("new sqlite connection: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	legacy := mutationPrefix(t, TelemetryMutation(), "4_", "5_")
	legacyEvolver, err := litekit.NewEvolver(conn, legacy)
	if err != nil {
		t.Fatalf("new legacy evolver: %v", err)
	}
	if err := legacyEvolver.MutateSchema(); err != nil {
		t.Fatalf("apply telemetry version 3: %v", err)
	}
	if _, err := conn.Exec(`
INSERT INTO metrics_raw (timestamp, queue_id, metric_name, metric_value, labels)
VALUES (1000, 'queue-1', 'depth', 7, '{"partition":"a"}');
INSERT INTO metrics_1m
    (bucket_start, queue_id, metric_name, min_value, max_value, avg_value, sum_value, count, labels)
VALUES (0, 'queue-1', 'depth', 1, 9, 5, 15, 3, '{"partition":"a"}');
INSERT INTO rate_snapshots
    (timestamp, queue_id, metric_name, rate_per_second, window_seconds)
VALUES (1000, 'queue-1', 'send_rate', 2.5, 2);`); err != nil {
		t.Fatalf("seed telemetry version 3: %v", err)
	}

	current, err := litekit.NewEvolver(conn, TelemetryMutation())
	if err != nil {
		t.Fatalf("new current evolver: %v", err)
	}
	if err := current.MutateSchema(); err != nil {
		t.Fatalf("upgrade telemetry schema: %v", err)
	}
	assertSQLiteSchemaVersion(t, conn, 5)

	var rawKind string
	var rawWindow int64
	if err := conn.QueryRow(`SELECT metric_kind, window_ms FROM metrics_raw WHERE timestamp = 1000`).
		Scan(&rawKind, &rawWindow); err != nil {
		t.Fatalf("query upgraded raw row: %v", err)
	}
	if rawKind != "gauge" || rawWindow != 0 {
		t.Fatalf("upgraded raw kind/window = %q/%d, want gauge/0", rawKind, rawWindow)
	}

	var first, last, increase sql.NullFloat64
	var aggregateKind string
	if err := conn.QueryRow(`
SELECT metric_kind, first_value, last_value, increase_value
FROM metrics_1m WHERE bucket_start = 0`).Scan(&aggregateKind, &first, &last, &increase); err != nil {
		t.Fatalf("query upgraded aggregate row: %v", err)
	}
	if aggregateKind != "gauge" || first.Valid || last.Valid || increase.Valid {
		t.Fatalf(
			"upgraded aggregate = kind %q first %v last %v increase %v, want legacy nullable values",
			aggregateKind,
			first,
			last,
			increase,
		)
	}

	var compatibilitySeconds int
	var exactWindowMS int64
	if err := conn.QueryRow(`SELECT window_seconds, window_ms FROM rate_snapshots WHERE timestamp = 1000`).
		Scan(&compatibilitySeconds, &exactWindowMS); err != nil {
		t.Fatalf("query upgraded rate snapshot: %v", err)
	}
	if compatibilitySeconds != 2 || exactWindowMS != 2000 {
		t.Fatalf("upgraded rate window = %ds/%dms, want 2s/2000ms", compatibilitySeconds, exactWindowMS)
	}

	for _, table := range []string{
		"telemetry_rollup_state",
		"telemetry_collection_state",
		"telemetry_coverage",
		"telemetry_terminal_state",
		"telemetry_collection_commits",
	} {
		var count int
		if err := conn.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&count); err != nil {
			t.Fatalf("find table %q: %v", table, err)
		}
		if count != 1 {
			t.Fatalf("table %q count = %d, want 1", table, count)
		}
	}
}

func TestTelemetryMigration5PreservesAssignedTerminalStateWithGeneration(t *testing.T) {
	t.Parallel()

	conn, err := litekit.New(filepath.Join(t.TempDir(), "plainq.db"))
	if err != nil {
		t.Fatalf("new sqlite connection: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	version4 := mutationPrefix(t, TelemetryMutation(), "5_")
	evolver, err := litekit.NewEvolver(conn, version4)
	if err != nil {
		t.Fatalf("new version 4 evolver: %v", err)
	}
	if err := evolver.MutateSchema(); err != nil {
		t.Fatalf("apply telemetry version 4: %v", err)
	}
	if _, err := conn.Exec(`INSERT INTO telemetry_terminal_state
    (subject_id, observed_at, target_bucket, sample_interval_ms)
VALUES ('topic-1', 59500, 59000, 1000)`); err != nil {
		t.Fatalf("seed assigned terminal: %v", err)
	}

	evolver, err = litekit.NewEvolver(conn, TelemetryMutation())
	if err != nil {
		t.Fatalf("new current evolver: %v", err)
	}
	if err := evolver.MutateSchema(); err != nil {
		t.Fatalf("upgrade telemetry schema: %v", err)
	}
	assertSQLiteSchemaVersion(t, conn, 5)

	var generation, observedAt, target, interval int64
	if err := conn.QueryRow(`SELECT generation, observed_at, target_bucket, sample_interval_ms
FROM telemetry_terminal_state WHERE subject_id = 'topic-1'`).
		Scan(&generation, &observedAt, &target, &interval); err != nil {
		t.Fatalf("query upgraded terminal: %v", err)
	}
	if generation != 1 || observedAt != 59_500 || target != 59_000 || interval != 1_000 {
		t.Fatalf("upgraded terminal = generation %d observed %d target %d interval %d", generation, observedAt, target, interval)
	}
}

func TestTelemetryMigration4IsSkippedAfterVersionAdvance(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "plainq.db")
	conn, err := litekit.New(databasePath)
	if err != nil {
		t.Fatalf("new sqlite connection: %v", err)
	}

	evolver, err := litekit.NewEvolver(conn, TelemetryMutation())
	if err != nil {
		t.Fatalf("new telemetry evolver: %v", err)
	}
	if err := evolver.MutateSchema(); err != nil {
		t.Fatalf("apply telemetry schema: %v", err)
	}
	if _, err := conn.Exec(`INSERT INTO telemetry_collection_state (singleton, raw_sample_interval_ms) VALUES (1, 1500)`); err != nil {
		t.Fatalf("seed version 4 state: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close first connection: %v", err)
	}

	conn, err = litekit.New(databasePath)
	if err != nil {
		t.Fatalf("reopen sqlite connection: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	evolver, err = litekit.NewEvolver(conn, TelemetryMutation())
	if err != nil {
		t.Fatalf("new repeat telemetry evolver: %v", err)
	}
	if err := evolver.MutateSchema(); err != nil {
		t.Fatalf("repeat telemetry migration: %v", err)
	}
	assertSQLiteSchemaVersion(t, conn, 5)

	var interval int64
	if err := conn.QueryRow(`SELECT raw_sample_interval_ms FROM telemetry_collection_state WHERE singleton = 1`).
		Scan(&interval); err != nil {
		t.Fatalf("query preserved collection state: %v", err)
	}
	if interval != 1500 {
		t.Fatalf("preserved interval = %d, want 1500", interval)
	}
}

func mutationPrefix(t *testing.T, all fs.FS, excludePrefixes ...string) fstest.MapFS {
	t.Helper()

	selected := fstest.MapFS{}
	entries, err := fs.ReadDir(all, ".")
	if err != nil {
		t.Fatalf("read mutations: %v", err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sql") || slices.ContainsFunc(excludePrefixes, func(prefix string) bool {
			return strings.HasPrefix(entry.Name(), prefix)
		}) {
			continue
		}
		data, err := fs.ReadFile(all, entry.Name())
		if err != nil {
			t.Fatalf("read mutation %q: %v", entry.Name(), err)
		}
		selected[entry.Name()] = &fstest.MapFile{Data: data}
	}

	return selected
}

func TestStorageMigrationVersionsAreContiguous(t *testing.T) {
	t.Parallel()

	for name, migrationFS := range map[string]fs.FS{
		"sqlite":   SqliteStorageMutations(),
		"postgres": PostgresStorageMutations(),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			records, err := ValidatedStorageMutations(migrationFS)
			if err != nil {
				t.Fatalf("validate storage migrations: %v", err)
			}
			if len(records) != 7 {
				t.Fatalf("migration count = %d, want 7", len(records))
			}
			for index, record := range records {
				if record.Version != index+1 {
					t.Fatalf("migration %q version = %d, want %d", record.Name, record.Version, index+1)
				}
			}
			if got := records[len(records)-1].Name; got != "007_pubsub_queue_index.sql" {
				t.Fatalf("last migration = %q, want 007_pubsub_queue_index.sql", got)
			}
		})
	}
}

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

func TestSQLiteStorageMutationsCreateQueueLeadingSubscriptionIndex(t *testing.T) {
	conn, err := litekit.New(filepath.Join(t.TempDir(), "plainq.db"))
	if err != nil {
		t.Fatalf("new sqlite connection: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close sqlite connection: %v", err)
		}
	})

	evolver, err := litekit.NewEvolver(conn, SqliteStorageMutations())
	if err != nil {
		t.Fatalf("new storage evolver: %v", err)
	}
	if err := evolver.MutateSchema(); err != nil {
		t.Fatalf("mutate storage schema: %v", err)
	}

	var indexName string
	if err := conn.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'topic_subscriptions_queue_id_index';`).
		Scan(&indexName); err != nil {
		t.Fatalf("find queue-leading subscription index: %v", err)
	}
	if indexName != "topic_subscriptions_queue_id_index" {
		t.Fatalf("subscription index = %q, want topic_subscriptions_queue_id_index", indexName)
	}
}

func TestSQLiteStorageMigrationSevenUpgradesVersionSixWithExistingSubscriptions(t *testing.T) {
	conn, err := litekit.New(filepath.Join(t.TempDir(), "plainq.db"))
	if err != nil {
		t.Fatalf("new sqlite connection: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close sqlite connection: %v", err)
		}
	})

	all := SqliteStorageMutations()
	versionSix := make(fstest.MapFS, 6)
	for _, name := range []string{
		"001_schema.sql",
		"002_user.sql",
		"003_organizations.sql",
		"004_pubsub.sql",
		"005_agent_messaging.sql",
		"006_tenant_security.sql",
	} {
		data, err := fs.ReadFile(all, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		versionSix[name] = &fstest.MapFile{Data: data}
	}

	validatedV6, err := ValidatedStorageFS(versionSix)
	if err != nil {
		t.Fatalf("validate version-six migrations: %v", err)
	}

	legacyEvolver, err := litekit.NewEvolver(conn, validatedV6)
	if err != nil {
		t.Fatalf("new version-six evolver: %v", err)
	}
	if err := legacyEvolver.MutateSchema(); err != nil {
		t.Fatalf("apply version-six schema: %v", err)
	}
	if _, err := conn.Exec(`
INSERT INTO queue_properties (queue_id, queue_name, retention_period_seconds, visibility_timeout_seconds, max_receive_attempts)
VALUES ('queue-1', 'existing', 60, 30, 5);
INSERT INTO topic_properties (topic_id, topic_name) VALUES ('topic-1', 'existing');
INSERT INTO topic_subscriptions (subscription_id, topic_id, queue_id) VALUES ('subscription-1', 'topic-1', 'queue-1');`); err != nil {
		t.Fatalf("seed version-six subscription: %v", err)
	}
	assertSQLiteSchemaVersion(t, conn, 6)
	assertSQLiteIndexCount(t, conn, "topic_subscriptions_queue_id_index", 0)

	validatedCurrent, err := ValidatedStorageFS(all)
	if err != nil {
		t.Fatalf("validate current migrations: %v", err)
	}

	currentEvolver, err := litekit.NewEvolver(conn, validatedCurrent)
	if err != nil {
		t.Fatalf("new current evolver: %v", err)
	}
	if err := currentEvolver.MutateSchema(); err != nil {
		t.Fatalf("upgrade version-six schema: %v", err)
	}
	assertSQLiteSchemaVersion(t, conn, 7)
	assertSQLiteIndexCount(t, conn, "topic_subscriptions_queue_id_index", 1)

	var subscriptionCount int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM topic_subscriptions WHERE subscription_id = 'subscription-1';`).
		Scan(&subscriptionCount); err != nil {
		t.Fatalf("count preserved subscription: %v", err)
	}
	if subscriptionCount != 1 {
		t.Fatalf("preserved subscriptions = %d, want one", subscriptionCount)
	}
}

func assertSQLiteSchemaVersion(t *testing.T, conn *litekit.Conn, want int) {
	t.Helper()
	var got int
	if err := conn.QueryRow(`SELECT version FROM schema_version WHERE id = 0;`).Scan(&got); err != nil {
		t.Fatalf("read schema version: %v", err)
	}
	if got != want {
		t.Fatalf("schema version = %d, want %d", got, want)
	}
}

func assertSQLiteIndexCount(t *testing.T, conn *litekit.Conn, name string, want int) {
	t.Helper()
	var got int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?;`, name).Scan(&got); err != nil {
		t.Fatalf("count index %q: %v", name, err)
	}
	if got != want {
		t.Fatalf("index %q count = %d, want %d", name, got, want)
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
	if version != 7 || users != 1 || subscriptions != 1 || roles != 1 || teams != 1 || sessions != 0 || denied != 0 || principals != 2 {
		t.Fatalf("upgrade state = version %d users %d subscriptions %d roles %d teams %d sessions %d denied %d principals %d", version, users, subscriptions, roles, teams, sessions, denied, principals)
	}
	assertSQLiteIndexCount(t, conn, "topic_subscriptions_queue_id_index", 1)

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
