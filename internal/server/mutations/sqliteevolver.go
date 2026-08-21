package mutations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marsolab/plainq/internal/shared/pqlite"
)

const sqliteSchemaVersionDDL = `
CREATE TABLE IF NOT EXISTS schema_version (
  id INTEGER NOT NULL DEFAULT 0 PRIMARY KEY,
  version INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT current_timestamp,
  updated_at TIMESTAMP NOT NULL DEFAULT current_timestamp
);
CREATE UNIQUE INDEX IF NOT EXISTS id_uindex ON schema_version (id);
INSERT OR IGNORE INTO schema_version (id, version) VALUES (0, 0);`

const sqliteUsersTable = "users"

// ApplySQLiteStorage applies the embedded SQLite schema on one dedicated
// connection. Migration 006 rebuilds users with foreign keys temporarily
// disabled, so it is guarded by before/after data digests and explicit FK
// checks rather than being delegated to a pool-wide generic evolver.

//nolint:cyclop,gocyclo // Migration orchestration keeps every rollback and post-commit FK guard explicit.
func ApplySQLiteStorage(ctx context.Context, db pqlite.DB) (aErr error) {
	if db == nil {
		return errors.New("sqlite storage database is nil")
	}

	loaded, err := ValidatedStorageMutations(SqliteStorageMutations())
	if err != nil {
		return fmt.Errorf("validate sqlite storage migrations: %w", err)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire sqlite migration connection: %w", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			aErr = errors.Join(aErr, fmt.Errorf("close sqlite migration connection: %w", err))
		}
	}()

	if err := pqlite.EnforceForeignKeys(ctx, conn); err != nil {
		return fmt.Errorf("initialize sqlite migration connection: %w", err)
	}

	if _, err := conn.ExecContext(ctx, sqliteSchemaVersionDDL); err != nil {
		return fmt.Errorf("ensure sqlite schema version: %w", err)
	}

	var currentVersion int
	if err := conn.QueryRowContext(ctx, `SELECT version FROM schema_version WHERE id = 0`).Scan(&currentVersion); err != nil {
		return fmt.Errorf("read sqlite schema version: %w", err)
	}

	if currentVersion < 0 || currentVersion > loaded[len(loaded)-1].Version {
		return fmt.Errorf("sqlite schema version %d is outside migration range 0..%d",
			currentVersion, loaded[len(loaded)-1].Version)
	}

	for _, migration := range loaded {
		if migration.Version <= currentVersion {
			continue
		}

		if migration.Version == 6 {
			if err := applySQLiteTenantSecurity(ctx, conn, migration); err != nil {
				return err
			}
		} else if err := applySQLiteMigration(ctx, conn, migration); err != nil {
			return err
		}

		currentVersion = migration.Version
	}

	if err := pqlite.EnforceForeignKeys(ctx, conn); err != nil {
		return fmt.Errorf("restore sqlite migration foreign keys: %w", err)
	}

	if err := requireEmptySQLiteForeignKeyCheck(ctx, conn); err != nil {
		return fmt.Errorf("verify migrated sqlite foreign keys: %w", err)
	}

	return nil
}

func applySQLiteMigration(ctx context.Context, conn *sql.Conn, migration StorageMutation) (aErr error) {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sqlite migration %q: %w", migration.Name, err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			aErr = errors.Join(aErr, fmt.Errorf("rollback sqlite migration %q: %w", migration.Name, err))
		}
	}()

	for index, statement := range strings.Split(string(migration.Changes), ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}

		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply sqlite migration %q statement %d: %w", migration.Name, index+1, err)
		}
	}

	if err := bumpSQLiteVersion(ctx, tx, migration.Version); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite migration %q: %w", migration.Name, err)
	}

	return nil
}

//nolint:cyclop,gocyclo // Every migration guard has a distinct rollback/cleanup diagnostic.
func applySQLiteTenantSecurity(ctx context.Context, conn *sql.Conn, migration StorageMutation) (aErr error) {
	before, err := captureTenantSecurityDigests(ctx, conn)
	if err != nil {
		return fmt.Errorf("capture pre-migration tenant security digests: %w", err)
	}

	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
		return fmt.Errorf("disable sqlite foreign keys for users rebuild: %w", err)
	}

	foreignKeysDisabled := true
	defer func() {
		if !foreignKeysDisabled {
			return
		}

		if _, err := conn.ExecContext(context.WithoutCancel(ctx), `PRAGMA foreign_keys = ON`); err != nil {
			aErr = errors.Join(aErr, fmt.Errorf("restore sqlite foreign keys after migration failure: %w", err))
		}
	}()

	var enabled int
	if err := conn.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&enabled); err != nil {
		return fmt.Errorf("read disabled sqlite foreign key setting: %w", err)
	}

	if enabled != 0 {
		return fmt.Errorf("sqlite foreign keys remained enabled during users rebuild: %d", enabled)
	}

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sqlite migration %q: %w", migration.Name, err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			aErr = errors.Join(aErr, fmt.Errorf("rollback sqlite migration %q: %w", migration.Name, err))
		}
	}()

	if _, err := tx.ExecContext(ctx, string(migration.Changes)); err != nil {
		return fmt.Errorf("apply sqlite migration %q: %w", migration.Name, err)
	}

	after, err := captureTenantSecurityDigests(ctx, tx)
	if err != nil {
		return fmt.Errorf("capture post-migration tenant security digests: %w", err)
	}

	for table, want := range before {
		if got := after[table]; got != want {
			return fmt.Errorf("tenant security migration changed %s rows: before %x after %x",
				table, want, got)
		}
	}

	if err := requireEmptySQLiteForeignKeyCheck(ctx, tx); err != nil {
		return fmt.Errorf("pre-commit sqlite foreign key check: %w", err)
	}

	if err := bumpSQLiteVersion(ctx, tx, migration.Version); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite migration %q: %w", migration.Name, err)
	}

	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		return fmt.Errorf("re-enable sqlite foreign keys: %w", err)
	}

	foreignKeysDisabled = false

	if err := pqlite.EnforceForeignKeys(ctx, conn); err != nil {
		return fmt.Errorf("verify re-enabled sqlite foreign keys: %w", err)
	}

	if err := requireEmptySQLiteForeignKeyCheck(ctx, conn); err != nil {
		return fmt.Errorf("post-commit sqlite foreign key check: %w", err)
	}

	return nil
}

func bumpSQLiteVersion(ctx context.Context, tx *sql.Tx, version int) error {
	result, err := tx.ExecContext(ctx, `
		UPDATE schema_version SET version = ?, updated_at = current_timestamp
		WHERE id = 0 AND version = ?`, version, version-1)
	if err != nil {
		return fmt.Errorf("bump sqlite schema version to %d: %w", version, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read sqlite schema version bump result: %w", err)
	}

	if rows != 1 {
		return fmt.Errorf("bump sqlite schema version to %d: expected version %d", version, version-1)
	}

	return nil
}

type sqliteQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func captureTenantSecurityDigests(ctx context.Context, queryer sqliteQueryer) (map[string][32]byte, error) {
	queries := map[string]string{
		sqliteUsersTable: `SELECT user_id, email, password, CAST(verified AS INTEGER), created_at, updated_at,
			coalesce(org_id, '01HQ5RJNXS6TPXK89PQWY4N8JH'), oauth_provider, oauth_sub,
			last_sync_at, CAST(is_oauth_user AS INTEGER) FROM users ORDER BY user_id`,
	}

	children, err := sqliteUserChildDigestQueries(ctx, queryer)
	if err != nil {
		return nil, err
	}

	for table, query := range children {
		queries[table] = query
	}

	result := make(map[string][32]byte, len(queries))
	for table, query := range queries {
		digest, err := digestSQLiteRows(ctx, queryer, query)
		if err != nil {
			return nil, fmt.Errorf("digest %s: %w", table, err)
		}

		result[table] = digest
	}

	return result, nil
}

// sqliteUserChildDigestQueries discovers the preservation set from the
// database rather than assuming it can never grow. refresh_tokens is the one
// deliberate exception: migration 006 revokes and rebuilds that clear-token
// table by design. Every other pre-v6 FK child is hashed before and after the
// users-table rebuild.

//nolint:cyclop // Discovery keeps required-child and per-table preservation checks explicit.
func sqliteUserChildDigestQueries(
	ctx context.Context,
	queryer sqliteQueryer,
) (map[string]string, error) {
	tables, err := sqliteTableNames(ctx, queryer)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string)

	for _, table := range tables {
		if table == sqliteUsersTable || table == "refresh_tokens" {
			continue
		}

		child, err := sqliteTableReferencesUsers(ctx, queryer, table)
		if err != nil {
			return nil, err
		}

		if !child {
			continue
		}

		columns, err := sqliteTableColumns(ctx, queryer, table)
		if err != nil {
			return nil, err
		}

		quoted := make([]string, 0, len(columns))
		for _, column := range columns {
			quoted = append(quoted, quoteSQLiteIdentifier(column))
		}

		result[table] = `SELECT ` + strings.Join(quoted, ", ") + ` FROM ` +
			quoteSQLiteIdentifier(table) + ` ORDER BY ` + strings.Join(quoted, ", ")
	}

	for _, required := range []string{"user_roles", "user_teams"} {
		if _, ok := result[required]; !ok {
			return nil, fmt.Errorf("required users child table %s has no discoverable foreign key", required)
		}
	}

	return result, nil
}

func sqliteTableNames(ctx context.Context, queryer sqliteQueryer) ([]string, error) {
	rows, err := queryer.QueryContext(ctx, `
		SELECT name FROM sqlite_master
		WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
		ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list sqlite tables for users child digests: %w", err)
	}
	defer rows.Close()

	var tables []string

	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			return nil, fmt.Errorf("scan sqlite table name: %w", err)
		}

		tables = append(tables, table)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sqlite table names: %w", err)
	}

	return tables, nil
}

func sqliteTableReferencesUsers(ctx context.Context, queryer sqliteQueryer, table string) (bool, error) {
	foreignKeys, err := queryer.QueryContext(ctx, `PRAGMA foreign_key_list(`+quoteSQLiteIdentifier(table)+`)`)
	if err != nil {
		return false, fmt.Errorf("list %s foreign keys: %w", table, err)
	}
	defer foreignKeys.Close()

	child := false

	for foreignKeys.Next() {
		var (
			id, sequence                                int
			target, from, to, onUpdate, onDelete, match string
		)

		if err := foreignKeys.Scan(&id, &sequence, &target, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			return false, fmt.Errorf("scan %s foreign key: %w", table, err)
		}

		child = child || target == sqliteUsersTable
	}

	if err := foreignKeys.Err(); err != nil {
		return false, fmt.Errorf("iterate %s foreign keys: %w", table, err)
	}

	return child, nil
}

func sqliteTableColumns(ctx context.Context, queryer sqliteQueryer, table string) ([]string, error) {
	rows, err := queryer.QueryContext(ctx, `PRAGMA table_info(`+quoteSQLiteIdentifier(table)+`)`)
	if err != nil {
		return nil, fmt.Errorf("read %s columns: %w", table, err)
	}
	defer rows.Close()

	var columns []string

	for rows.Next() {
		var (
			cid, notNull, primaryKey int
			name, kind               string
			defaultValue             any
		)

		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, fmt.Errorf("scan %s column: %w", table, err)
		}

		columns = append(columns, name)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate %s columns: %w", table, err)
	}

	if len(columns) == 0 {
		return nil, fmt.Errorf("users child table %s has no columns", table)
	}

	sort.Strings(columns)

	return columns, nil
}

func quoteSQLiteIdentifier(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}

func digestSQLiteRows(ctx context.Context, queryer sqliteQueryer, query string) ([32]byte, error) {
	rows, err := queryer.QueryContext(ctx, query)
	if err != nil {
		return [32]byte{}, fmt.Errorf("query rows for digest: %w", err)
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return [32]byte{}, fmt.Errorf("read columns: %w", err)
	}

	var (
		count  uint64
		result [32]byte
	)

	digest := sha256.New()

	for rows.Next() {
		values := make([]any, len(columns))       //nolint:makezero // Scan requires indexed destinations.
		destinations := make([]any, len(columns)) //nolint:makezero // One destination per selected column.

		for index := range values {
			destinations[index] = &values[index]
		}

		if err := rows.Scan(destinations...); err != nil {
			return [32]byte{}, fmt.Errorf("scan row: %w", err)
		}

		count++

		writeDigestUint64(digest, uint64(len(values)))

		for _, value := range values {
			writeDigestValue(digest, value)
		}
	}

	if err := rows.Err(); err != nil {
		return [32]byte{}, fmt.Errorf("iterate rows: %w", err)
	}

	writeDigestUint64(digest, count)
	copy(result[:], digest.Sum(nil))

	return result, nil
}

func writeDigestValue(digest hash.Hash, value any) {
	var encoded []byte

	switch typed := value.(type) {
	case nil:
		encoded = []byte{0}
	case []byte:
		encoded = append([]byte{1}, typed...)
	case string:
		encoded = append([]byte{2}, typed...)
	case int64:
		encoded = append([]byte{3}, strconv.FormatInt(typed, 10)...)
	case float64:
		encoded = append([]byte{4}, strconv.FormatFloat(typed, 'g', -1, 64)...)
	case bool:
		encoded = append([]byte{5}, strconv.FormatBool(typed)...)
	case time.Time:
		encoded = append([]byte{6}, typed.UTC().Format(time.RFC3339Nano)...)
	default:
		encoded = append([]byte{7}, fmt.Sprint(typed)...)
	}

	writeDigestUint64(digest, uint64(len(encoded)))
	mustWriteDigest(digest, encoded)
}

func writeDigestUint64(digest hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	mustWriteDigest(digest, encoded[:])
}

func mustWriteDigest(digest hash.Hash, encoded []byte) {
	if _, err := digest.Write(encoded); err != nil {
		panic(fmt.Sprintf("write in-memory row digest: %v", err))
	}
}

func requireEmptySQLiteForeignKeyCheck(ctx context.Context, queryer sqliteQueryer) error {
	rows, err := queryer.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("run foreign key check: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		var (
			table, parent string
			rowID         any
			foreignKeyID  int
		)

		if err := rows.Scan(&table, &rowID, &parent, &foreignKeyID); err != nil {
			return fmt.Errorf("scan foreign key violation: %w", err)
		}

		return fmt.Errorf("foreign key violation in %s row %v referencing %s constraint %d",
			table, rowID, parent, foreignKeyID)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate foreign key check: %w", err)
	}

	return nil
}
