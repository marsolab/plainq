package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/marsolab/plainq/internal/server/mutations"
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

// pgMigrationAdvisoryLock is the signed 64-bit rendering of "PLAINQMG".
// It serializes all PlainQ schema evolvers connected to one database.
const pgMigrationAdvisoryLock int64 = 0x504c41494e514d47

// newPgEvolver returns a configured evolver.
func newPgEvolver(pool *pgxpool.Pool, migrationFS fs.FS) *pgEvolver {
	return &pgEvolver{
		pool:      pool,
		mutations: migrationFS,
		timeout:   2 * time.Minute,
	}
}

// MutateSchema applies each pending migration and its guarded version bump in
// one transaction while holding a database-wide advisory lock.
func (e *pgEvolver) MutateSchema() (mErr error) { //nolint:cyclop // migration lock cleanup has distinct failure paths.
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	loaded, err := mutations.ValidatedStorageMutations(e.mutations)
	if err != nil {
		return fmt.Errorf("validate postgres migrations: %w", err)
	}

	conn, err := e.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire conn: %w", err)
	}

	locked := false
	defer func() {
		if !locked {
			conn.Release()

			return
		}

		if err := unlockPGMigrations(conn); err != nil {
			mErr = errors.Join(mErr, err)
		}
	}()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, pgMigrationAdvisoryLock); err != nil {
		return fmt.Errorf("acquire postgres migration lock: %w", err)
	}

	locked = true

	if _, err := conn.Conn().PgConn().Exec(ctx, pgSchemaVersionDDL).ReadAll(); err != nil {
		return fmt.Errorf("ensure schema_version table: %w", err)
	}

	var currentVersion int

	if err := conn.QueryRow(ctx, `SELECT version FROM schema_version WHERE id = 0`).Scan(&currentVersion); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}

	if currentVersion < 0 || currentVersion > loaded[len(loaded)-1].Version {
		return fmt.Errorf("schema version %d is outside migration range 0..%d",
			currentVersion, loaded[len(loaded)-1].Version)
	}

	for _, migration := range loaded {
		if migration.Version <= currentVersion {
			continue
		}

		if err := applyPGMigration(ctx, conn, migration); err != nil {
			return err
		}

		currentVersion = migration.Version
	}

	return nil
}

func applyPGMigration(
	ctx context.Context,
	conn *pgxpool.Conn,
	migration mutations.StorageMutation,
) (aErr error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin migration %q: %w", migration.Name, err)
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()

		if err := tx.Rollback(rollbackCtx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			aErr = errors.Join(aErr, fmt.Errorf("rollback migration %q: %w", migration.Name, err))
		}
	}()

	if _, err := tx.Conn().PgConn().Exec(ctx, string(migration.Changes)).ReadAll(); err != nil {
		return fmt.Errorf("apply migration %q: %w", migration.Name, err)
	}

	tag, err := tx.Exec(ctx, `
		UPDATE schema_version
		SET version = $1, updated_at = now()
		WHERE id = 0 AND version = $2`, migration.Version, migration.Version-1)
	if err != nil {
		return fmt.Errorf("bump schema_version to %d: %w", migration.Version, err)
	}

	if tag.RowsAffected() != 1 {
		return fmt.Errorf("bump schema_version to %d: expected version %d",
			migration.Version, migration.Version-1)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migration %q: %w", migration.Name, err)
	}

	return nil
}

func unlockPGMigrations(conn *pgxpool.Conn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var unlocked bool

	err := conn.QueryRow(ctx, `SELECT pg_advisory_unlock($1)`, pgMigrationAdvisoryLock).Scan(&unlocked)
	if err == nil && unlocked {
		conn.Release()

		return nil
	}

	raw := conn.Hijack()

	closeErr := raw.Close(ctx)
	if err != nil {
		return errors.Join(fmt.Errorf("release postgres migration lock: %w", err), closeErr)
	}

	if !unlocked {
		return errors.Join(errors.New("release postgres migration lock: lock was not held"), closeErr)
	}

	return closeErr
}
