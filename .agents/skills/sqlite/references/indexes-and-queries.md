# Indexes and query performance

The cheap wins are: pick the right index shape, order columns
correctly, run `EXPLAIN QUERY PLAN`, and let `PRAGMA optimize`
keep stats fresh.

## Index shapes

### Composite indexes — the order rule

**Equality → range → sort.** Whatever columns you filter by `=`
go first; range predicates (`<`, `>`, `BETWEEN`) next; then any
column the query orders by.

```sql
-- Query: WHERE tenant_id = ? AND created_at > ? ORDER BY created_at DESC
CREATE INDEX idx_events_tenant_time
    ON events(tenant_id, created_at DESC);
```

A trailing `DESC` in the index lets the planner avoid a temp
B-tree for the `ORDER BY`. Mixing `ASC` and `DESC` in one index
only matters if you have a multi-column `ORDER BY` with mixed
directions — most apps don't.

### Covering indexes

If every column the query needs is in the index, SQLite never
touches the table heap. The plan shows `USING COVERING INDEX`.

```sql
CREATE INDEX idx_users_email_cover ON users(email, name, status);

-- Index-only scan:
SELECT name, status FROM users WHERE email = ?;
```

Don't go wild — every column duplicated in the index costs space
and write throughput. Worth it for hot read paths.

### Partial indexes

Index only the relevant subset. Smaller, faster, and the planner
will only consider it for queries whose `WHERE` matches the
partial predicate.

```sql
-- Only active rows
CREATE INDEX idx_users_email_active
    ON users(email)
    WHERE deleted_at IS NULL;

-- Soft-delete unique constraint
CREATE UNIQUE INDEX idx_users_email_unique_active
    ON users(email)
    WHERE deleted_at IS NULL;

-- Job queue's pending rows only
CREATE INDEX idx_jobs_pending
    ON jobs(run_after)
    WHERE status = 'queued';
```

### Expression indexes

Index a derived value. The planner uses the index when the
expression in the `WHERE` matches **exactly**.

```sql
CREATE INDEX idx_users_lower_email ON users(lower(email));

-- Uses the index:
SELECT * FROM users WHERE lower(email) = lower(?);

-- Does NOT use the index:
SELECT * FROM users WHERE email = ? COLLATE NOCASE;
```

The expression must be deterministic (no `random()`, no
non-`SQLITE_DETERMINISTIC` user functions).

## `EXPLAIN QUERY PLAN`

```sql
EXPLAIN QUERY PLAN
SELECT id, title FROM posts
WHERE author_id = 7 AND created_at > '2026-01-01'
ORDER BY created_at DESC LIMIT 20;
```

What to look for:

| Plan output | Meaning |
|---|---|
| `SEARCH posts USING INDEX idx_posts_author_time` | Good — index seek |
| `SEARCH posts USING COVERING INDEX …` | Excellent — no heap fetch |
| `SCAN posts` | Bad on large tables — full table scan |
| `USE TEMP B-TREE FOR ORDER BY` | Sort happening — add an index that satisfies the order |
| `USING INDEX … (col=?)` | Index used for equality |
| `USING INDEX … (col>?)` | Index used for range; columns after this in the index won't be used for further filtering |

CLI helper: `.eqp on` prints the plan before each query.

## `ANALYZE` and `PRAGMA optimize`

The planner uses `sqlite_stat1` (and `sqlite_stat4`, if compiled
in) to pick indices.

```sql
ANALYZE;                      -- full rebuild; can be slow
ANALYZE users;                -- one table
PRAGMA optimize;              -- smart, cheap; preferred
```

Run `PRAGMA optimize` on connection close (or hourly on a
server). It analyzes only tables that have changed enough since
the last analyze, and (3.46+) auto-limits scope.

Pre-3.46: precede with `PRAGMA analysis_limit = 400;` so it never
runs unbounded on huge tables.

## STRICT tables (3.37+)

Type enforcement that the default affinity system silently
ignores. Strongly recommended for new schemas.

```sql
CREATE TABLE users (
    id    INTEGER PRIMARY KEY,
    email TEXT    NOT NULL,
    age   INTEGER CHECK (age >= 0),
    role  TEXT    NOT NULL DEFAULT 'user'
                   CHECK (role IN ('user','admin'))
) STRICT;

-- This fails with STRICT, silently succeeds without:
INSERT INTO users(id, email, age) VALUES (1, 'a@b', 'oops');
```

Allowed types: `INT`, `INTEGER`, `REAL`, `TEXT`, `BLOB`, `ANY`.
`ANY` accepts anything (escape hatch for migrations).

STRICT-table DBs **cannot** be read by SQLite < 3.37.

## `WITHOUT ROWID`

The table is stored as a clustered B-tree on the declared PK.
Lookups by PK are O(1) and there's no `rowid` overhead.

```sql
CREATE TABLE session_tokens (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
) WITHOUT ROWID, STRICT;
```

When it helps:

- PK is a natural key (UUID, slug, short token).
- Rows are small.
- Most reads are by PK.

When it hurts:

- PK is large and you have many secondary indexes (each copies the
  full PK).
- Rows contain large BLOBs.
- You insert in random PK order (page splits).

## `INTEGER PRIMARY KEY` and AUTOINCREMENT

```sql
-- preferred: alias for rowid, no extra storage
CREATE TABLE t (id INTEGER PRIMARY KEY, ...);

-- only if you need strict monotonicity (never reuses IDs)
CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, ...);
```

`AUTOINCREMENT` writes to the shared `sqlite_sequence` table on
every insert — a hidden contention hotspot. Drop it unless you
specifically need IDs that never repeat.

## Generated columns (3.31+)

```sql
ALTER TABLE orders ADD COLUMN total_cents INTEGER
    GENERATED ALWAYS AS (price_cents * qty) STORED;

CREATE INDEX idx_orders_total ON orders(total_cents);
```

- `VIRTUAL` (default) — computed on read; zero storage; can be
  indexed only via an expression index.
- `STORED` — persisted; can be indexed directly; costs disk.

Common use: pull a JSON path into an indexable column.

```sql
ALTER TABLE events ADD COLUMN kind TEXT
    GENERATED ALWAYS AS (payload ->> '$.kind') VIRTUAL;
CREATE INDEX idx_events_kind ON events(kind);
```

## Substring vs prefix search

| Query shape | Index? |
|---|---|
| `LIKE 'foo%'` (left-anchored) | Uses B-tree index on the column |
| `LIKE '%foo'` | Cannot use a regular index — reverse the value or use FTS5 |
| `LIKE '%foo%'` | Substring — needs FTS5 with `trigram` tokenizer |
| `GLOB 'foo*'` | Same as `LIKE 'foo%'` — usable, no case-folding |

Avoid `PRAGMA case_sensitive_like` — it's a global flag, brittle.
Use `lower()` + expression index, or `COLLATE NOCASE` on the
column.

## Common anti-patterns

- **Function on indexed column.** `WHERE date(created_at) = '…'`
  ignores the index. Use a range: `WHERE created_at >= '…' AND
  created_at < '…'`.
- **Leading `%` in `LIKE`.** Index unusable. Move to FTS5.
- **`OR` across columns.** SQLite often can't use multiple indexes.
  Rewrite as a `UNION ALL` of two indexed queries.
- **`NULL` in indexed predicate.** `WHERE col = NULL` never matches
  anything. Use `IS NULL`. Standard indexes do include NULLs;
  partial indexes commonly exclude them deliberately.
- **`SELECT *`.** Defeats covering-index optimizations.
- **`COUNT(*)` on a big table without WHERE.** O(N). Maintain a
  running counter in a separate table if you need it cheap.
- **Forgetting `ORDER BY` on `LIMIT`.** Row order is undefined.

## Quick reference: planner hints

You almost never need these, but they exist:

```sql
-- Tell the planner to prefer or avoid an index:
SELECT ... FROM t INDEXED BY idx_name WHERE ...;
SELECT ... FROM t NOT INDEXED       WHERE ...;
```

Use only as a last resort — fix the index or the query instead.
