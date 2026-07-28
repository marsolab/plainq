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
	PingContext(ctx context.Context) error
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
