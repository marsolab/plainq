package main

import (
	"context"
	"database/sql/driver"
	"fmt"

	"github.com/mattn/go-sqlite3"
)

// sqliteConnector preserves SQLite's concurrent-reader WAL contract while
// avoiding deferred read-to-write promotion races. database/sql marks the few
// long-lived snapshot transactions as ReadOnly; those use plain BEGIN. Every
// ordinary transaction reserves SQLite's single writer with BEGIN IMMEDIATE.
type sqliteConnector struct {
	driver *sqlite3.SQLiteDriver
	dsn    string
}

func newSQLiteConnector(dsn string) driver.Connector {
	return &sqliteConnector{driver: &sqlite3.SQLiteDriver{}, dsn: dsn}
}

func (c *sqliteConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	opened, err := c.driver.Open(c.dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite driver connection: %w", err)
	}

	conn, ok := opened.(*sqlite3.SQLiteConn)
	if !ok {
		_ = opened.Close()

		return nil, fmt.Errorf("sqlite driver returned connection %T", opened)
	}

	return &transactionModeSQLiteConn{SQLiteConn: conn}, nil
}

func (c *sqliteConnector) Driver() driver.Driver {
	return c.driver
}

type transactionModeSQLiteConn struct {
	*sqlite3.SQLiteConn
}

func (c *transactionModeSQLiteConn) Begin() (driver.Tx, error) {
	return c.begin(context.Background(), false)
}

func (c *transactionModeSQLiteConn) BeginTx(
	ctx context.Context,
	opts driver.TxOptions,
) (driver.Tx, error) {
	return c.begin(ctx, opts.ReadOnly)
}

func (c *transactionModeSQLiteConn) begin(ctx context.Context, readOnly bool) (driver.Tx, error) {
	statement := "BEGIN IMMEDIATE"
	if readOnly {
		statement = "BEGIN"
	}

	if _, err := c.ExecContext(ctx, statement, nil); err != nil {
		// database/sql driver adapters must preserve sentinel identity.
		return nil, err //nolint:wrapcheck
	}

	return &transactionModeSQLiteTx{conn: c}, nil
}

type transactionModeSQLiteTx struct {
	conn *transactionModeSQLiteConn
}

func (tx *transactionModeSQLiteTx) Commit() error {
	_, err := tx.conn.ExecContext(context.Background(), "COMMIT", nil)
	if err != nil {
		// SQLite can leave a failed COMMIT transaction open, while database/sql
		// considers it finished as soon as this method returns. Match the
		// upstream driver and release any lock before the connection is pooled.
		_, _ = tx.conn.ExecContext(context.Background(), "ROLLBACK", nil) //nolint:errcheck // best-effort cleanup
	}

	// database/sql handles driver sentinels returned by Commit directly.
	return err //nolint:wrapcheck
}

func (tx *transactionModeSQLiteTx) Rollback() error {
	_, err := tx.conn.ExecContext(context.Background(), "ROLLBACK", nil)

	// database/sql handles driver sentinels returned by Rollback directly.
	return err //nolint:wrapcheck
}
