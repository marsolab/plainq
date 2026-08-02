package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"time"
)

// tursoEvolver applies the embedded SQLite migrations against a Turso/libSQL
// database. It mirrors the contract of litekit.Evolver so callers see parallel
// behavior: filenames are sorted lexicographically, each file is one versioned
// "mutation", and a schema_version table tracks which mutations have been
// applied.
//
// litekit.Evolver cannot be reused here because it is bound to *litekit.Conn,
// which always opens a local SQLite file. The SQL itself is identical — libSQL
// is a fork of SQLite and shares its dialect.
type tursoEvolver struct {
	db        *sql.DB
	mutations fs.FS
	timeout   time.Duration
}

const (
	// tursoSchemaVersionDDL matches the schema_version table litekit creates,
	// so a database can be moved between the sqlite and turso drivers without
	// replaying migrations.
	tursoSchemaVersionDDL = `
CREATE TABLE IF NOT EXISTS schema_version
(
    id         int       DEFAULT 0                 NOT NULL,
    version    int       DEFAULT 0                 NOT NULL,
    created_at timestamp DEFAULT current_timestamp NOT NULL,
    updated_at timestamp DEFAULT current_timestamp NOT NULL,
    CONSTRAINT schema_version_pk PRIMARY KEY (id)
);
CREATE UNIQUE INDEX IF NOT EXISTS id_uindex ON schema_version (id);
`

	tursoSchemaVersionSeed = `INSERT OR IGNORE INTO schema_version (id, version) VALUES (0, 0);`

	// tursoSchemaVersionBump is appended to each mutation script so the version
	// bump rides along in the same transactional batch. It takes the versions as
	// format arguments rather than bound parameters to keep the script free of
	// arguments, which is what makes it a batch.
	//
	// The WHERE clause guards against a stale bump: it only lands if the version
	// is still the one this mutation expected to find, so a server that lost a
	// migration race cannot move the version on top of the winner's.
	tursoSchemaVersionBump = `UPDATE schema_version SET version = %d, updated_at = current_timestamp` +
		` WHERE id = 0 AND version = %d;`

	// tursoMutationTimeout bounds the whole migration run. It is more generous
	// than the local SQLite equivalent because every statement is a round-trip
	// to a remote database.
	tursoMutationTimeout = 2 * time.Minute
)

// newTursoEvolver returns a configured evolver.
func newTursoEvolver(db *sql.DB, mutations fs.FS) *tursoEvolver {
	return &tursoEvolver{
		db:        db,
		mutations: mutations,
		timeout:   tursoMutationTimeout,
	}
}

// MutateSchema applies any mutation whose version exceeds the version recorded
// in schema_version.
//
// Each mutation is sent together with its own schema_version bump in a single
// multi-statement Exec. libSQL runs a multi-statement script as one
// transactional batch, so a mutation and the record of it landing either both
// commit or both roll back. That matters because the migration files are not
// replay-safe — they seed rows as well as creating tables — so a mutation that
// applied without being recorded would fail on the next start.
//
// The bump cannot be issued in a separate database/sql transaction: the libSQL
// driver opens an explicit transaction by sending BEGIN on the stream, and a
// multi-statement script inside it would nest a second BEGIN.
//
// Two servers starting against the same database race: both read the same
// version and both try to apply the same mutation. libSQL serializes the two
// batches, and the loser's copy of a mutation that seeds rows fails on the rows
// the winner already inserted, rolling its whole batch back. That failure is
// expected rather than fatal, so the version is re-read: if the winner has
// already recorded this mutation, the loser moves on instead of refusing to
// start.
func (e *tursoEvolver) MutateSchema() error {
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	if err := e.ensureSchemaVersionTable(ctx); err != nil {
		return err
	}

	currentVersion, versionErr := e.schemaVersion(ctx)
	if versionErr != nil {
		return versionErr
	}

	mutations, loadErr := loadSQLMutations(e.mutations)
	if loadErr != nil {
		return loadErr
	}

	for _, m := range mutations {
		if m.version <= currentVersion {
			continue
		}

		// The versions are indexes into the mutation files, never user input,
		// so interpolating them keeps the script a single parameterless batch.
		script := fmt.Sprintf("%s\n%s\n", m.changes,
			fmt.Sprintf(tursoSchemaVersionBump, m.version, m.version-1),
		)

		if _, err := e.db.ExecContext(ctx, script); err != nil {
			// Losing the race is not a failure: whoever won applied exactly the
			// mutation this one was about to. Anything else is a real error.
			applied, readErr := e.schemaVersion(ctx)
			if readErr == nil && applied >= m.version {
				currentVersion = applied

				continue
			}

			return fmt.Errorf("apply schema mutation %q: %w", m.name, err)
		}

		currentVersion = m.version
	}

	return nil
}

// schemaVersion reads the currently recorded schema version.
func (e *tursoEvolver) schemaVersion(ctx context.Context) (int, error) {
	var version int

	if err := e.db.QueryRowContext(ctx,
		`SELECT version FROM schema_version WHERE id = 0`,
	).Scan(&version); err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}

	return version, nil
}

func (e *tursoEvolver) ensureSchemaVersionTable(ctx context.Context) error {
	if _, err := e.db.ExecContext(ctx, tursoSchemaVersionDDL); err != nil {
		return fmt.Errorf("create schema_version table: %w", err)
	}

	if _, err := e.db.ExecContext(ctx, tursoSchemaVersionSeed); err != nil {
		return fmt.Errorf("seed schema_version table: %w", err)
	}

	return nil
}

// sqlMutation is a single versioned migration file.
type sqlMutation struct {
	name    string
	changes []byte
	version int
}

// loadSQLMutations reads every .sql file from the mutations filesystem and
// numbers them by lexicographic order, exactly as litekit.Evolver does. The
// version of a file is its 1-based position among all entries in the
// directory, so both evolvers agree on version numbers for the same set of
// files.
func loadSQLMutations(mutations fs.FS) ([]sqlMutation, error) {
	entries, readErr := fs.ReadDir(mutations, ".")
	if readErr != nil {
		return nil, fmt.Errorf("read mutations dir: %w", readErr)
	}

	slices.SortFunc(entries, func(i, j fs.DirEntry) int {
		return strings.Compare(i.Name(), j.Name())
	})

	loaded := make([]sqlMutation, 0, len(entries))

	for i, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		changes, readFileErr := fs.ReadFile(mutations, entry.Name())
		if readFileErr != nil {
			return nil, fmt.Errorf("read mutation file %q: %w", entry.Name(), readFileErr)
		}

		loaded = append(loaded, sqlMutation{
			name:    entry.Name(),
			changes: changes,
			version: i + 1,
		})
	}

	if len(loaded) == 0 {
		return nil, errors.New("no schema mutations found")
	}

	return loaded, nil
}
