// Package pqlite holds the database handle abstraction shared by the
// SQLite-dialect storage implementations (the litestore packages).
//
// PlainQ speaks the SQLite dialect to two different engines: a local SQLite
// file, opened through servekit's litekit.Conn, and a Turso/libSQL database
// reached over the network through a database/sql handle backed by the libsql
// driver. Both expose the same database/sql surface, so the storages depend on
// the DB interface declared here instead of on a concrete connection type.
package pqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/marsolab/plainq/internal/shared/pqerr"
)

// Compilation time check that *sql.DB implements the DB interface.
// *litekit.Conn satisfies it too, by embedding *sql.DB.
var _ DB = (*sql.DB)(nil)

// DB is the subset of *sql.DB used by the SQLite-dialect storages.
//
// It is a superset of the sqlc-generated DBTX interface, so a DB value can be
// handed straight to sqlcgen.New.
type DB interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
	Conn(ctx context.Context) (*sql.Conn, error)
	PingContext(ctx context.Context) error
}

// Tx is the database/sql transaction surface used by SQLite-dialect stores.
type Tx interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// WriteRetry bounds retries for SQLite/libSQL writer contention.
type WriteRetry struct {
	MaxAttempts int
	MinBackoff  time.Duration
	MaxBackoff  time.Duration
}

// DefaultWriteRetry returns the production retry policy for writer contention.
func DefaultWriteRetry() WriteRetry {
	return WriteRetry{
		MaxAttempts: 5,
		MinBackoff:  5 * time.Millisecond,
		MaxBackoff:  100 * time.Millisecond,
	}
}

// BeginTx starts a transaction with the driver's default isolation level.
//
// SQLite serializes writers by design, and the mattn/go-sqlite3 driver ignores
// sql.TxOptions entirely, so the default level already provides the guarantees
// these storages rely on. Asking for sql.LevelSerializable explicitly is a
// no-op on SQLite but a hard error on Turso: the libSQL HTTP driver rejects
// every isolation level except sql.LevelDefault.
func BeginTx(ctx context.Context, db DB) (*sql.Tx, error) {
	return db.BeginTx(ctx, nil) //nolint:wrapcheck // callers add their own context.
}

// EnforceForeignKeys enables and verifies SQLite foreign-key enforcement on a
// dedicated connection. PRAGMA foreign_keys is connection-local and is a no-op
// after a transaction has begun, so callers must invoke this first.
func EnforceForeignKeys(ctx context.Context, conn *sql.Conn) error {
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		return fmt.Errorf("enable foreign keys: %w", err)
	}

	var enabled int
	if err := conn.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&enabled); err != nil {
		return fmt.Errorf("read foreign key setting: %w", err)
	}

	if enabled != 1 {
		return fmt.Errorf("foreign key enforcement is disabled: PRAGMA foreign_keys = %d", enabled)
	}

	return nil
}

// WithWriteTx executes fn atomically on one dedicated SQLite/libSQL
// connection. Each attempt enables foreign keys before beginning and retries
// the entire side-effect-free callback only for writer contention.
//
//nolint:cyclop // Retry cleanup and cancellation paths are intentionally explicit.
func WithWriteTx(ctx context.Context, db DB, retry WriteRetry, fn func(Tx) error) error {
	policy := normalizedRetry(retry)

	var lastErr error

	for attempt := 0; attempt < policy.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return unavailable(err)
		}

		conn, err := db.Conn(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return unavailable(ctx.Err())
			}

			if !isRetryableWriteError(err) {
				return fmt.Errorf("acquire write connection: %w", err)
			}

			lastErr = err
			if err := waitBeforeRetry(ctx, policy, attempt); err != nil {
				return unavailable(err)
			}

			continue
		}

		err = writeAttempt(ctx, conn, fn)

		closeErr := conn.Close()
		if closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close write connection: %w", closeErr))
		}

		if err == nil {
			return nil
		}

		if ctx.Err() != nil {
			return unavailable(ctx.Err())
		}

		if !isRetryableWriteError(err) {
			return err
		}

		lastErr = err
		if attempt+1 < policy.MaxAttempts {
			if err := waitBeforeRetry(ctx, policy, attempt); err != nil {
				return unavailable(err)
			}
		}
	}

	return fmt.Errorf("%w: write transaction retries exhausted: %w", pqerr.ErrUnavailable, lastErr)
}

func writeAttempt(ctx context.Context, conn *sql.Conn, fn func(Tx) error) (wErr error) {
	if err := EnforceForeignKeys(ctx, conn); err != nil {
		return err
	}

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin write transaction: %w", err)
	}

	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			wErr = errors.Join(wErr, fmt.Errorf("rollback write transaction: %w", err))
		}
	}()

	if err := fn(tx); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit write transaction: %w", err)
	}

	return nil
}

func normalizedRetry(retry WriteRetry) WriteRetry {
	defaults := DefaultWriteRetry()
	if retry.MaxAttempts <= 0 {
		retry.MaxAttempts = defaults.MaxAttempts
	}

	if retry.MinBackoff < 0 {
		retry.MinBackoff = 0
	}

	if retry.MaxBackoff < retry.MinBackoff {
		retry.MaxBackoff = retry.MinBackoff
	}

	if retry.MinBackoff == 0 && retry.MaxBackoff == 0 {
		retry.MinBackoff = defaults.MinBackoff
		retry.MaxBackoff = defaults.MaxBackoff
	}

	return retry
}

func waitBeforeRetry(ctx context.Context, retry WriteRetry, attempt int) error {
	ceiling := retry.MinBackoff
	for index := 0; index < attempt && ceiling < retry.MaxBackoff; index++ {
		if ceiling > retry.MaxBackoff/2 {
			ceiling = retry.MaxBackoff

			break
		}

		ceiling *= 2
	}

	if ceiling > retry.MaxBackoff {
		ceiling = retry.MaxBackoff
	}

	delay := ceiling
	if ceiling > 0 {
		floor := ceiling / 2
		delay = floor + time.Duration(rand.Int64N(int64(ceiling-floor)+1)) //nolint:gosec // retry jitter is not security-sensitive.
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isRetryableWriteError(err error) bool {
	if err == nil {
		return false
	}

	message := strings.ToUpper(err.Error())
	for _, marker := range []string{
		"SQLITE_BUSY",
		"SQLITE_LOCKED",
		"DATABASE IS LOCKED",
		"DATABASE TABLE IS LOCKED",
		"BUSY_SNAPSHOT",
		"SERIALIZATION",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}

	return false
}

func unavailable(cause error) error {
	return fmt.Errorf("%w: %w", pqerr.ErrUnavailable, cause)
}
