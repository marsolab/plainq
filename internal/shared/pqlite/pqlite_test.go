package pqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/shared/pqerr"
	_ "github.com/mattn/go-sqlite3"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := "file:" + filepath.Join(t.TempDir(), "plainq.db") + "?_busy_timeout=0&_journal_mode=WAL"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(4)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close sqlite: %v", err)
		}
	})

	return db
}

func TestWithWriteTxEnforcesForeignKeysBeforeBeginning(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openTestDB(t)
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE parents (id INTEGER PRIMARY KEY);
		CREATE TABLE children (id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL REFERENCES parents(id));
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	err := WithWriteTx(ctx, db, DefaultWriteRetry(), func(tx Tx) error {
		var enabled int
		if err := tx.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&enabled); err != nil {
			return err
		}
		if enabled != 1 {
			t.Fatalf("foreign_keys = %d, want 1", enabled)
		}

		if _, err := tx.ExecContext(ctx, `INSERT INTO children (id, parent_id) VALUES (1, 404)`); err == nil {
			t.Fatal("orphan insert succeeded with foreign keys enabled")
		}

		return nil
	})
	if err != nil {
		t.Fatalf("write transaction: %v", err)
	}
}

func TestWithWriteTxRollsBackCallbackFailure(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openTestDB(t)
	if _, err := db.ExecContext(ctx, `CREATE TABLE records (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	wantErr := errors.New("injected callback failure")
	err := WithWriteTx(ctx, db, DefaultWriteRetry(), func(tx Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO records (id) VALUES (1)`); err != nil {
			return err
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("write transaction error = %v, want %v", err, wantErr)
	}

	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM records`).Scan(&count); err != nil {
		t.Fatalf("count records: %v", err)
	}
	if count != 0 {
		t.Fatalf("record count = %d, want 0", count)
	}
}

func TestWithWriteTxRetriesBusyCallback(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openTestDB(t)
	if _, err := db.ExecContext(ctx, `CREATE TABLE records (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	blocker, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("acquire blocker: %v", err)
	}
	t.Cleanup(func() { _ = blocker.Close() })
	blockerTx, err := blocker.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin blocker transaction: %v", err)
	}
	if _, err := blockerTx.ExecContext(ctx, `INSERT INTO records (id) VALUES (1)`); err != nil {
		t.Fatalf("lock records table: %v", err)
	}

	released := make(chan struct{})
	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = blockerTx.Commit()
		close(released)
	}()

	var attempts atomic.Int32
	err = WithWriteTx(ctx, db, WriteRetry{
		MaxAttempts: 50,
		MinBackoff:  time.Millisecond,
		MaxBackoff:  2 * time.Millisecond,
	}, func(tx Tx) error {
		attempts.Add(1)
		_, err := tx.ExecContext(ctx, `INSERT INTO records (id) VALUES (2)`)
		return err
	})
	<-released
	if err != nil {
		t.Fatalf("write transaction: %v", err)
	}
	if attempts.Load() < 2 {
		t.Fatalf("callback attempts = %d, want at least 2", attempts.Load())
	}
}

func TestWithWriteTxMapsRetryExhaustionAndCancellationToUnavailable(t *testing.T) {
	t.Parallel()

	t.Run("retry exhaustion", func(t *testing.T) {
		ctx := context.Background()
		db := openTestDB(t)
		if _, err := db.ExecContext(ctx, `CREATE TABLE records (id INTEGER PRIMARY KEY)`); err != nil {
			t.Fatalf("create table: %v", err)
		}

		blocker, err := db.Conn(ctx)
		if err != nil {
			t.Fatalf("acquire blocker: %v", err)
		}
		defer blocker.Close()
		blockerTx, err := blocker.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin blocker transaction: %v", err)
		}
		defer blockerTx.Rollback()
		if _, err := blockerTx.ExecContext(ctx, `INSERT INTO records (id) VALUES (1)`); err != nil {
			t.Fatalf("lock records table: %v", err)
		}

		err = WithWriteTx(ctx, db, WriteRetry{MaxAttempts: 2}, func(tx Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO records (id) VALUES (2)`)
			return err
		})
		if !errors.Is(err, pqerr.ErrUnavailable) {
			t.Fatalf("write transaction error = %v, want %v", err, pqerr.ErrUnavailable)
		}
	})

	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := WithWriteTx(ctx, openTestDB(t), DefaultWriteRetry(), func(Tx) error {
			t.Fatal("callback ran for canceled context")
			return nil
		})
		if !errors.Is(err, pqerr.ErrUnavailable) {
			t.Fatalf("write transaction error = %v, want %v", err, pqerr.ErrUnavailable)
		}
	})
}
