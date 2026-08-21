package main

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/marsolab/plainq/internal/server/mutations"
	"github.com/marsolab/servekit/dbkit/litekit"
)

// openLocalSQLite opens a plain database/sql handle to a temporary SQLite
// file. The tursoEvolver targets libSQL, which shares SQLite's dialect, so the
// migration SQL and the bookkeeping it does can be exercised locally without a
// remote database.
func openLocalSQLite(t *testing.T) *sql.DB {
	t.Helper()

	// litekit registers the sqlite3 driver by importing mattn/go-sqlite3.
	conn, err := litekit.New(filepath.Join(t.TempDir(), "plainq.db"))
	if err != nil {
		t.Fatalf("new sqlite connection: %v", err)
	}

	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close sqlite connection: %v", err)
		}
	})

	return conn.DB
}

// lastMutationVersion is the version a fully migrated storage database lands on.
func lastMutationVersion(t *testing.T) int {
	t.Helper()

	applied, err := loadSQLMutations(mutations.SqliteStorageMutations())
	if err != nil {
		t.Fatalf("load mutations: %v", err)
	}

	return applied[len(applied)-1].version
}

func schemaVersion(t *testing.T, db *sql.DB) int {
	t.Helper()

	var version int

	if err := db.QueryRowContext(context.Background(),
		`SELECT version FROM schema_version WHERE id = 0`,
	).Scan(&version); err != nil {
		t.Fatalf("read schema version: %v", err)
	}

	return version
}

func TestTursoEvolverAppliesMutations(t *testing.T) {
	t.Parallel()

	db := openLocalSQLite(t)

	if err := newTursoEvolver(db, mutations.SqliteStorageMutations()).MutateSchema(); err != nil {
		t.Fatalf("mutate schema: %v", err)
	}

	if got, want := schemaVersion(t, db), lastMutationVersion(t); got != want {
		t.Errorf("schema version: got %d, want %d", got, want)
	}

	// The queue_properties table is created by the storage mutations; querying
	// it proves the migration SQL actually landed.
	var count int

	if err := db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM queue_properties`,
	).Scan(&count); err != nil {
		t.Fatalf("query migrated table: %v", err)
	}
}

func TestTursoEvolverIsIdempotent(t *testing.T) {
	t.Parallel()

	db := openLocalSQLite(t)
	evolver := newTursoEvolver(db, mutations.SqliteStorageMutations())

	if err := evolver.MutateSchema(); err != nil {
		t.Fatalf("first mutate schema: %v", err)
	}

	first := schemaVersion(t, db)

	if err := evolver.MutateSchema(); err != nil {
		t.Fatalf("second mutate schema: %v", err)
	}

	if second := schemaVersion(t, db); second != first {
		t.Errorf("schema version changed on re-run: got %d, want %d", second, first)
	}
}

func TestTursoEvolverUpgradePreservesPopulatedUserChildren(t *testing.T) {
	all := mutations.SqliteStorageMutations()
	versionFour := make(fstest.MapFS, 4)
	for _, name := range []string{"001_schema.sql", "002_user.sql", "003_organizations.sql", "004_pubsub.sql"} {
		data, err := fs.ReadFile(all, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		versionFour[name] = &fstest.MapFile{Data: data}
	}

	db := openLocalSQLite(t)
	if err := newTursoEvolver(db, versionFour).MutateSchema(); err != nil {
		t.Fatalf("apply v4: %v", err)
	}

	for _, statement := range []string{
		`INSERT INTO users (user_id, email, password) VALUES ('upgrade-user', 'upgrade@example.test', 'hash')`,
		`INSERT INTO user_roles (user_id, role_id) VALUES ('upgrade-user', '01HQ5RJNXS6TPXK89PQWY4N8JD')`,
		`INSERT INTO user_teams (user_id, team_id) VALUES ('upgrade-user', '01HQ5RJNXS6TPXK89PQWY4N8JI')`,
		`INSERT INTO queue_properties (queue_id, queue_name, retention_period_seconds, visibility_timeout_seconds, max_receive_attempts) VALUES ('upgrade-queue', 'upgrade-queue', 60, 30, 5)`,
		`INSERT INTO topic_properties (topic_id, topic_name) VALUES ('upgrade-topic', 'upgrade-topic')`,
		`INSERT INTO topic_subscriptions (subscription_id, topic_id, queue_id) VALUES ('upgrade-sub', 'upgrade-topic', 'upgrade-queue')`,
	} {
		if _, err := db.ExecContext(context.Background(), statement); err != nil {
			t.Fatalf("seed v4: %v", err)
		}
	}

	if err := newTursoEvolver(db, all).MutateSchema(); err != nil {
		t.Fatalf("upgrade through tenant security: %v", err)
	}

	var roles, teams, subscriptions int
	if err := db.QueryRow(`SELECT count(*) FROM user_roles WHERE user_id = 'upgrade-user'`).Scan(&roles); err != nil {
		t.Fatalf("count roles: %v", err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM user_teams WHERE user_id = 'upgrade-user'`).Scan(&teams); err != nil {
		t.Fatalf("count teams: %v", err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM topic_subscriptions WHERE subscription_id = 'upgrade-sub'`).Scan(&subscriptions); err != nil {
		t.Fatalf("count subscriptions: %v", err)
	}
	if roles != 1 || teams != 1 || subscriptions != 1 {
		t.Fatalf("preserved children = roles %d teams %d subscriptions %d", roles, teams, subscriptions)
	}
}

// TestTursoEvolverMatchesLitekitVersions guards the property that lets a
// database move between the sqlite and turso drivers: both evolvers must end
// up on the same schema_version for the same set of migration files.
func TestTursoEvolverMatchesLitekitVersions(t *testing.T) {
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

	litekitEvolver, err := litekit.NewEvolver(conn, mutations.SqliteStorageMutations())
	if err != nil {
		t.Fatalf("new litekit evolver: %v", err)
	}

	if err := litekitEvolver.MutateSchema(); err != nil {
		t.Fatalf("litekit mutate schema: %v", err)
	}

	litekitVersion := schemaVersion(t, conn.DB)

	tursoDB := openLocalSQLite(t)

	if err := newTursoEvolver(tursoDB, mutations.SqliteStorageMutations()).MutateSchema(); err != nil {
		t.Fatalf("turso mutate schema: %v", err)
	}

	if tursoVersion := schemaVersion(t, tursoDB); tursoVersion != litekitVersion {
		t.Errorf("schema version mismatch: turso %d, litekit %d", tursoVersion, litekitVersion)
	}
}

// TestTursoEvolverStopsOnFailedMutation checks that a broken mutation neither
// records itself nor lets later mutations run. The migration files seed rows as
// well as creating tables, so a version recorded for SQL that did not fully
// apply would wedge the next start.
func TestTursoEvolverStopsOnFailedMutation(t *testing.T) {
	t.Parallel()

	broken := fstest.MapFS{
		"001_ok.sql":     &fstest.MapFile{Data: []byte(`CREATE TABLE IF NOT EXISTS first (id TEXT NOT NULL);`)},
		"002_broken.sql": &fstest.MapFile{Data: []byte(`CREATE TABLE second (;`)},
		"003_never.sql":  &fstest.MapFile{Data: []byte(`CREATE TABLE IF NOT EXISTS third (id TEXT NOT NULL);`)},
	}

	db := openLocalSQLite(t)

	err := newTursoEvolver(db, broken).MutateSchema()
	if err == nil {
		t.Fatal("mutate schema: want error from broken mutation, got nil")
	}

	if got, want := schemaVersion(t, db), 1; got != want {
		t.Errorf("schema version: got %d, want %d", got, want)
	}

	var name string

	if err := db.QueryRowContext(context.Background(),
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'third'`,
	).Scan(&name); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("mutation after the failed one applied: %q (err: %v)", name, err)
	}
}
