package mutations

import (
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
	validatedAll, err := ValidatedStorageFS(allMutations)
	if err != nil {
		t.Fatalf("validate all mutations: %v", err)
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
		queueID = "01J00000000000000000000003"
		topicID = "01J00000000000000000000004"
	)
	statements := []string{
		`INSERT INTO organizations (org_id, org_code, org_name) VALUES ('` + orgID + `', 'upgrade', 'Upgrade Tenant')`,
		`INSERT INTO users (user_id, email, password, org_id) VALUES ('` + userID + `', 'upgrade@example.test', 'existing-hash', '` + orgID + `')`,
		`INSERT INTO queue_properties (queue_id, queue_name, retention_period_seconds, visibility_timeout_seconds, max_receive_attempts) VALUES ('` + queueID + `', 'upgrade-queue', 3600, 30, 5)`,
		`INSERT INTO topic_properties (topic_id, topic_name) VALUES ('` + topicID + `', 'upgrade-topic')`,
		`INSERT INTO topic_subscriptions (subscription_id, topic_id, queue_id) VALUES ('01J00000000000000000000005', '` + topicID + `', '` + queueID + `')`,
	}
	for _, statement := range statements {
		if _, err := conn.Exec(statement); err != nil {
			t.Fatalf("seed version-four data: %v", err)
		}
	}

	allEvolver, err := litekit.NewEvolver(conn, validatedAll)
	if err != nil {
		t.Fatalf("new current evolver: %v", err)
	}
	if err := allEvolver.MutateSchema(); err != nil {
		t.Fatalf("upgrade version-four schema: %v", err)
	}

	var version, users, subscriptions int
	if err := conn.QueryRow(`SELECT version FROM schema_version WHERE id = 0`).Scan(&version); err != nil {
		t.Fatalf("read upgraded schema version: %v", err)
	}
	if err := conn.QueryRow(`SELECT count(*) FROM users WHERE user_id = ? AND org_id = ?`, userID, orgID).Scan(&users); err != nil {
		t.Fatalf("read preserved user: %v", err)
	}
	if err := conn.QueryRow(`SELECT count(*) FROM topic_subscriptions WHERE topic_id = ? AND queue_id = ?`, topicID, queueID).Scan(&subscriptions); err != nil {
		t.Fatalf("read preserved subscription: %v", err)
	}
	if version != 5 || users != 1 || subscriptions != 1 {
		t.Fatalf("upgrade state = version %d users %d subscriptions %d, want version 5 users 1 subscriptions 1", version, users, subscriptions)
	}

	if _, err := conn.Exec(`INSERT INTO agents (
		agent_id, tenant_id, agent_name, status, auth_version, created_by_kind,
		created_by_id, created_at_ns, updated_at_ns
	) VALUES (?, ?, 'upgrade-agent', 1, 1, 'system', 'upgrade-test', 1, 1)`, "01J00000000000000000000006", orgID); err != nil {
		t.Fatalf("write new version-five table after upgrade: %v", err)
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
