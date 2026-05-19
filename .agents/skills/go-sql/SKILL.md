---
name: go-sql
description: >-
  Type-safe SQL access in Go with sqlc and goose migrations. ALWAYS use
  this skill when writing or reviewing Go database code — `sqlc.yaml`
  configuration, query annotations (`:one`, `:many`, `:exec`,
  `:execrows`), generated `Querier` interface for mocking, goose Up/Down
  migrations, transaction patterns with `BEginTx` and `db.WithTx`,
  `pgx`/`pgxpool` vs `database/sql`, `sql.ErrNoRows` handling, JSON
  columns, and testing the data layer. Pair with go-http for the
  service-handler-storage stack, go-errors for wrapping `sql.ErrNoRows`,
  and go-testing for `Querier` mocking.
version: 1.0.0
tags:
  - go
  - golang
  - sql
  - sqlc
  - goose
  - postgres
  - database
---

# Go SQL

Use [sqlc](https://sqlc.dev/) to generate type-safe Go code from SQL
queries, and [goose](https://github.com/pressly/goose) for migrations.
Write SQL, get Go.

This combo gives you:
- Compile-time checking of column names and types.
- Real SQL in your editor, no DSL or ORM to learn.
- A `Querier` interface auto-generated for mocking in tests.

## Project layout

```text
myservice/
├── db/
│   ├── migrations/
│   │   └── 001_create_users.sql
│   └── queries/
│       └── users.sql
├── internal/
│   └── db/                # sqlc output goes here
│       ├── db.go
│       ├── models.go
│       ├── querier.go
│       └── users.sql.go
├── sqlc.yaml
└── go.mod
```

## sqlc.yaml

```yaml
version: "2"
sql:
  - schema: "db/migrations"
    queries: "db/queries"
    engine: "postgresql"
    gen:
      go:
        package: "db"
        out: "internal/db"
        emit_json_tags: true
        emit_interface: true       # generates Querier interface for mocking
        emit_empty_slices: true    # nil-free :many results
        sql_package: "pgx/v5"      # use pgx/v5 if connecting via pgx
```

`emit_interface: true` is important — it gives you `db.Querier` for
unit tests, so handlers and services can depend on the interface and
real DB connections only show up in integration tests.

## Migrations with goose

```sql
-- db/migrations/001_create_users.sql
-- +goose Up
CREATE TABLE users (
    id         BIGSERIAL PRIMARY KEY,
    email      TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE users;
```

Run with:

```bash
goose -dir db/migrations postgres "$DATABASE_URL" up
goose -dir db/migrations postgres "$DATABASE_URL" status
goose -dir db/migrations postgres "$DATABASE_URL" down
```

Always write a `Down` migration unless the change is impossible to
reverse (and even then, write a comment explaining the impossibility).

## Query annotations

```sql
-- db/queries/users.sql

-- name: GetUser :one
SELECT id, email, name, created_at
FROM users
WHERE id = $1;

-- name: ListUsers :many
SELECT id, email, name, created_at
FROM users
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CreateUser :one
INSERT INTO users (email, name)
VALUES ($1, $2)
RETURNING id, email, name, created_at;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;

-- name: UpdateUserName :execrows
UPDATE users SET name = $1 WHERE id = $2;
```

| Annotation | Returns |
|---|---|
| `:one` | Single row, or `sql.ErrNoRows` |
| `:many` | Slice of rows |
| `:exec` | No rows; only `error` |
| `:execrows` | Rows-affected count plus `error` |
| `:execresult` | Full `sql.Result` (driver-dependent) |

## Generate

```bash
sqlc generate
```

Re-run after every change to migrations or queries. Commit the generated
files — code review benefits from seeing the diff.

## Calling generated code

```go
type Service struct {
    queries *db.Queries
}

func (s *Service) GetUser(ctx context.Context, id int64) (db.User, error) {
    user, err := s.queries.GetUser(ctx, id)
    if errors.Is(err, sql.ErrNoRows) {
        return db.User{}, ErrNotFound
    }
    if err != nil {
        return db.User{}, fmt.Errorf("get user %d: %w", id, err)
    }
    return user, nil
}
```

Wrap `sql.ErrNoRows` into a domain error at the data-layer boundary —
upstream code shouldn't depend on `database/sql`.

## Transactions

The generated `Queries.WithTx` returns a new `*Queries` bound to a
transaction:

```go
func (s *Service) Transfer(ctx context.Context, from, to int64, amount int64) error {
    tx, err := s.db.BeginTx(ctx, nil)
    if err != nil {
        return fmt.Errorf("begin: %w", err)
    }
    defer tx.Rollback()                              // no-op after commit

    q := s.queries.WithTx(tx)
    if err := q.Debit(ctx, from, amount); err != nil {
        return fmt.Errorf("debit: %w", err)
    }
    if err := q.Credit(ctx, to, amount); err != nil {
        return fmt.Errorf("credit: %w", err)
    }
    return tx.Commit()
}
```

For pgx, use `pgxpool.Pool.BeginTx` and `pgx.Tx`; the pattern is
identical.

## Testing

Two approaches, used together:

**Unit tests** — mock the `Querier` interface:

```go
type fakeQuerier struct {
    db.Querier             // embed for unimplemented methods
    user db.User
    err  error
}

func (f *fakeQuerier) GetUser(ctx context.Context, id int64) (db.User, error) {
    return f.user, f.err
}

func TestServiceGetUser(t *testing.T) {
    svc := &Service{queries: &fakeQuerier{user: db.User{ID: 1, Name: "ada"}}}
    u, err := svc.GetUser(context.Background(), 1)
    // ...
}
```

**Integration tests** — real database, gated by env var:

```go
func TestUsersIntegration(t *testing.T) {
    dsn := os.Getenv("TEST_DATABASE_URL")
    if dsn == "" {
        t.Skip("set TEST_DATABASE_URL")
    }
    pool, err := pgxpool.New(context.Background(), dsn)
    // ...
}
```

Run migrations against a throwaway database (testcontainers, a CI
ephemeral Postgres) before each integration run.

## NULL handling

Postgres NULL columns map to `sql.Null*` types or pointers:

| SQL | Go (database/sql) | Go (pgx) |
|---|---|---|
| `INT NULL` | `sql.NullInt64` | `pgtype.Int8` |
| `TEXT NULL` | `sql.NullString` | `pgtype.Text` |
| `TIMESTAMPTZ NULL` | `sql.NullTime` | `pgtype.Timestamptz` |

If you'd rather work with pointers, configure
`emit_pointers_for_null_types: true` in `sqlc.yaml`.

## Common pitfalls

- **Forgetting to regenerate.** Add `sqlc generate` to your `Makefile`
  and CI lint step.
- **Using `:exec` when you wanted `:one RETURNING`** — `:exec` discards
  the returned row.
- **Passing `database/sql` types into the service layer.** Wrap or
  translate at the storage boundary.
- **Long-running transactions.** Hold transactions only for the work
  that must be atomic; release the connection before any RPC or HTTP
  call.

## When to load a sibling skill

| Task | Skill |
|---|---|
| Translating `sql.ErrNoRows` into HTTP 404 | go-http + go-errors |
| Mocking the `Querier` interface in tests | go-testing |
| Logging slow queries with attrs | go-logging |
| Connection pool lifecycle, graceful shutdown | go-concurrency |
| General Go idioms and naming | go-style |
