package mutations

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

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
