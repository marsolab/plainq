package mutations

import (
	"database/sql"
	"io/fs"
	"path/filepath"
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

	legacy := mutationPrefix(t, TelemetryMutation(), "4_")
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
	assertSQLiteSchemaVersion(t, conn, 4)

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
	assertSQLiteSchemaVersion(t, conn, 4)

	var interval int64
	if err := conn.QueryRow(`SELECT raw_sample_interval_ms FROM telemetry_collection_state WHERE singleton = 1`).
		Scan(&interval); err != nil {
		t.Fatalf("query preserved collection state: %v", err)
	}
	if interval != 1500 {
		t.Fatalf("preserved interval = %d, want 1500", interval)
	}
}

func mutationPrefix(t *testing.T, all fs.FS, excludePrefix string) fstest.MapFS {
	t.Helper()

	selected := fstest.MapFS{}
	entries, err := fs.ReadDir(all, ".")
	if err != nil {
		t.Fatalf("read mutations: %v", err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sql") || strings.HasPrefix(entry.Name(), excludePrefix) {
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

			conn, err := litekit.New(filepath.Join(t.TempDir(), "plainq.db"))
			if err != nil {
				t.Fatalf("new sqlite connection: %v", err)
			}

			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Errorf("close sqlite connection: %v", err)
				}
			})

			evolver, err := litekit.NewEvolver(conn, tt.mutations)
			if err != nil {
				t.Fatalf("new evolver: %v", err)
			}

			if err := evolver.MutateSchema(); err != nil {
				t.Fatalf("mutate schema: %v", err)
			}

			if err := evolver.MutateSchema(); err != nil {
				t.Fatalf("mutate schema again: %v", err)
			}

			wantVersion := countSQLMutations(t, tt.mutations)
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

func TestSQLiteStorageMutationUpgradesVersionFourWithExistingSubscriptions(t *testing.T) {
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
	legacy := fstest.MapFS{}
	entries, err := fs.ReadDir(all, ".")
	if err != nil {
		t.Fatalf("read storage mutations: %v", err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sql") || strings.HasPrefix(entry.Name(), "5_") {
			continue
		}
		data, err := fs.ReadFile(all, entry.Name())
		if err != nil {
			t.Fatalf("read legacy mutation %q: %v", entry.Name(), err)
		}
		legacy[entry.Name()] = &fstest.MapFile{Data: data}
	}

	legacyEvolver, err := litekit.NewEvolver(conn, legacy)
	if err != nil {
		t.Fatalf("new version-four evolver: %v", err)
	}
	if err := legacyEvolver.MutateSchema(); err != nil {
		t.Fatalf("apply version-four schema: %v", err)
	}
	if _, err := conn.Exec(`
INSERT INTO queue_properties (queue_id, queue_name, retention_period_seconds, visibility_timeout_seconds, max_receive_attempts)
VALUES ('queue-1', 'existing', 60, 30, 5);
INSERT INTO topic_properties (topic_id, topic_name) VALUES ('topic-1', 'existing');
INSERT INTO topic_subscriptions (subscription_id, topic_id, queue_id) VALUES ('subscription-1', 'topic-1', 'queue-1');`); err != nil {
		t.Fatalf("seed version-four subscription: %v", err)
	}
	assertSQLiteSchemaVersion(t, conn, 4)
	assertSQLiteIndexCount(t, conn, "topic_subscriptions_queue_id_index", 0)

	currentEvolver, err := litekit.NewEvolver(conn, all)
	if err != nil {
		t.Fatalf("new current evolver: %v", err)
	}
	if err := currentEvolver.MutateSchema(); err != nil {
		t.Fatalf("upgrade version-four schema: %v", err)
	}
	assertSQLiteSchemaVersion(t, conn, 5)
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
