package mutations

import (
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
	if err := conn.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'topic_subscriptions_queue_id_index';`).Scan(&indexName); err != nil {
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
	if err := conn.QueryRow(`SELECT COUNT(*) FROM topic_subscriptions WHERE subscription_id = 'subscription-1';`).Scan(&subscriptionCount); err != nil {
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
