package main

import (
	"context"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// pgEvolver applies embedded Postgres migrations against a pool. It mirrors
// the contract of litekit.Evolver so callers see parallel behavior: filenames
// are sorted lexicographically, each file is one versioned "mutation", and a
// schema_version table tracks which mutations have been applied.
//
// Migration SQL files can contain multiple semicolon-separated statements.
// They are executed via pgconn's simple query protocol (one round-trip per
// file) so multi-statement scripts work without the extended-protocol
// restriction of single statement per Exec.
type pgEvolver struct {
	pool      *pgxpool.Pool
	mutations fs.FS
	timeout   time.Duration
}

const pgSchemaVersionDDL = `
CREATE TABLE IF NOT EXISTS schema_version
(
    id         integer     DEFAULT 0     NOT NULL,
    version    integer     DEFAULT 0     NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    updated_at timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT schema_version_pk PRIMARY KEY (id)
);
INSERT INTO schema_version (id, version) VALUES (0, 0) ON CONFLICT DO NOTHING;
`

// newPgEvolver returns a configured evolver.
func newPgEvolver(pool *pgxpool.Pool, mutations fs.FS) *pgEvolver {
	return &pgEvolver{
		pool:      pool,
		mutations: mutations,
		timeout:   2 * time.Minute,
	}
}

// MutateSchema applies any mutations whose version exceeds the current
// schema_version.version. Idempotent DDL (CREATE IF NOT EXISTS, INSERT ... ON
// CONFLICT) means re-running a partially applied migration is safe if the
// version bump didn't persist.
//
//nolint:cyclop // Complex migration logic is inherent to the domain.
func (e *pgEvolver) MutateSchema() error {
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	conn, err := e.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire conn: %w", err)
	}

	defer conn.Release()

	pgConn := conn.Conn().PgConn()

	if _, err := pgConn.Exec(ctx, pgSchemaVersionDDL).ReadAll(); err != nil {
		return fmt.Errorf("ensure schema_version table: %w", err)
	}

	var currentVersion int32

	if err := conn.QueryRow(ctx, `SELECT version FROM schema_version WHERE id = 0`).Scan(&currentVersion); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}

	entries, err := fs.ReadDir(e.mutations, ".")
	if err != nil {
		return fmt.Errorf("read mutations dir: %w", err)
	}

	slices.SortFunc(entries, func(a, b fs.DirEntry) int {
		return strings.Compare(a.Name(), b.Name())
	})

	for i, entry := range entries {
		version := int32(i + 1)

		if version <= currentVersion {
			continue
		}

		if !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		changes, readErr := fs.ReadFile(e.mutations, entry.Name())
		if readErr != nil {
			return fmt.Errorf("read migration %q: %w", entry.Name(), readErr)
		}

		if _, err := pgConn.Exec(ctx, string(changes)).ReadAll(); err != nil {
			return fmt.Errorf("apply migration %q: %w", entry.Name(), err)
		}

		if _, err := conn.Exec(ctx,
			`UPDATE schema_version SET version = $1, updated_at = now() WHERE id = 0`,
			version,
		); err != nil {
			return fmt.Errorf("bump schema_version to %d: %w", version, err)
		}
	}

	return nil
}
