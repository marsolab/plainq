---
name: sqlite
description: >-
  Production-grade SQLite for web, mobile, and CLI projects. Use this skill
  when designing schemas, tuning PRAGMAs (WAL, busy_timeout, mmap, optimize),
  modeling writer concurrency (single-writer pool, BEGIN IMMEDIATE, busy
  retry), building indexes (covering, partial, expression, STRICT, WITHOUT
  ROWID), paginating with keyset cursors, implementing job queues via
  `UPDATE ... RETURNING`, full-text search with FTS5 + sqlite-vec,
  replicating with Litestream / Turso / Cloudflare D1, picking a driver
  (better-sqlite3, modernc.org/sqlite, GRDB, Room, SQLDelight, expo-sqlite,
  SQLCipher), or running the 12-step `ALTER TABLE` rewrite. Pair with go-sql
  for sqlc + goose against SQLite, apple-dev for GRDB on iOS, and front-dev
  for in-browser SQLite via OPFS.
version: 1.0.0
tags:
  - sqlite
  - database
  - sql
  - wal
  - fts5
  - litestream
  - turso
  - libsql
  - sqlcipher
  - mobile
  - embedded
---

# SQLite

Production patterns for SQLite as a primary datastore on servers,
mobile devices, and inside CLI tools. Defaults below assume SQLite
3.45+ (Debian stable, macOS 14, Ubuntu 24.04). Version-gated
features are flagged.

## When SQLite is the right call

SQLite is the best choice when:

- **Single-node OLTP/OLAP** up to ~1 TB with mostly read-heavy or
  modest write traffic (single-digit thousand writes/sec).
- You want **zero operational overhead** — no daemon, no network,
  one file plus a `-wal` + `-shm` sidecar.
- You want **fork-safe local state** in a CLI, agent, mobile app,
  Electron shell, or edge worker.
- **Read replicas** are acceptable for HA (Litestream, Turso, D1).

Skip SQLite when:

- You need **multi-writer scale-out** (Postgres / CockroachDB / D1
  with replication caveats).
- The DB lives on **NFS/SMB/Dropbox/iCloud Drive** — WAL locking is
  unsafe across those filesystems.
- You need **per-row access control** at the engine level.

## Open every connection with this preamble

Most "SQLite is slow" reports are an un-tuned default config. Run
this on **every** connection (PRAGMAs reset per handle):

```sql
PRAGMA journal_mode = WAL;          -- many readers + one writer, no block
PRAGMA synchronous = NORMAL;        -- safe with WAL; ~10x faster than FULL
PRAGMA busy_timeout = 5000;         -- ms; let SQLite handle lock contention
PRAGMA foreign_keys = ON;           -- off by default for back-compat
PRAGMA temp_store = MEMORY;         -- keep tmp tables/indexes off disk
PRAGMA cache_size = -64000;         -- 64 MiB page cache (negative = KiB)
PRAGMA mmap_size = 134217728;       -- 128 MiB mmap window for reads
```

Run `PRAGMA optimize;` before closing long-lived connections (or
every few hours on a server) to refresh stats and let the planner
rebuild affected indexes — cheap if nothing changed.

Full PRAGMA reference, safety implications, and pool sizing:
[references/pragmas-and-connection.md](references/pragmas-and-connection.md).

## The writer-concurrency rule

SQLite allows **many concurrent readers** but **exactly one writer**
at a time, even with WAL. The canonical server pattern is:

- **One writer connection** (serialize writes through it).
- **N reader connections** (pool sized to CPU count).
- All writes start with `BEGIN IMMEDIATE` (acquires `RESERVED` lock
  up front) — never plain `BEGIN`, which is `DEFERRED` and causes
  upgrade deadlocks when two readers both try to become writers.
- Retry on `SQLITE_BUSY` outside the transaction with jittered
  backoff. `busy_timeout` handles short waits; long-tail contention
  needs explicit retry.

```python
def write(conn, fn, *, max_retries=5):
    for attempt in range(max_retries):
        try:
            conn.execute("BEGIN IMMEDIATE")
            fn(conn)
            conn.execute("COMMIT")
            return
        except sqlite3.OperationalError as e:
            conn.execute("ROLLBACK")
            if "locked" not in str(e) or attempt == max_retries - 1:
                raise
            time.sleep((2 ** attempt) * 0.05 + random.random() * 0.05)
```

Frameworks that bake this in: **GRDB** (`DatabasePool`),
**better-sqlite3** (single sync connection), **Rails 7.1+**
(separate writer/reader pools).

## Schema design

- Use **`STRICT` tables** (3.37+) — type enforcement that catches
  bugs the default affinity hides.
- Prefer `INTEGER PRIMARY KEY` (rowid alias, lookup is O(1)) over
  `AUTOINCREMENT` unless you specifically need monotonic-never-
  reused IDs.
- `WITHOUT ROWID` helps narrow composite PKs without large blobs;
  hurts wide tables.
- Use **`CHECK` constraints** liberally; SQLite enforces them
  cheaply.
- Store time as **either** ISO-8601 text (`TEXT`) **or** unix
  seconds (`INTEGER`) — pick one project-wide. Never Julian
  real-numbers.

```sql
CREATE TABLE posts (
    id          INTEGER PRIMARY KEY,
    author_id   INTEGER NOT NULL REFERENCES users(id),
    title       TEXT    NOT NULL,
    body        TEXT    NOT NULL,
    created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
    deleted_at  INTEGER,
    CHECK (length(title) BETWEEN 1 AND 200)
) STRICT;
```

## Indexes

Three index shapes that solve 90% of slow queries:

| Shape | Example | When |
|---|---|---|
| Covering | `CREATE INDEX … ON t(a, b) INCLUDE (c)` (via composite) | Reads only the indexed columns; avoids table fetch |
| Partial | `CREATE INDEX … ON t(created_at) WHERE deleted_at IS NULL` | Hot subset of a sparse predicate |
| Expression | `CREATE INDEX … ON users(lower(email))` | Querying by a derived value |

Column order rule: **equality → range → sort**. A query that
filters `WHERE author_id = ? AND created_at > ?` benefits from
`(author_id, created_at)`, not the reverse.

Always inspect plans with `EXPLAIN QUERY PLAN`. Look for `SEARCH …
USING INDEX` (good) vs `SCAN` (bad on large tables).

Deep dive: [references/indexes-and-queries.md](references/indexes-and-queries.md).

## Pagination: keyset, not OFFSET

`LIMIT N OFFSET M` is O(N+M) — SQLite still scans the skipped
rows. Use **keyset / seek pagination** with a composite cursor that
includes the PK as tiebreaker:

```sql
-- next page (created_at, id) < (?, ?)
SELECT id, created_at, title
FROM posts
WHERE deleted_at IS NULL
  AND (created_at, id) < (:cursor_at, :cursor_id)
ORDER BY created_at DESC, id DESC
LIMIT 50;
```

Encode the cursor as `base64(created_at || ":" || id)` and hand it
back to the client. Reverse the comparison and sort order for the
previous page.

Patterns and the bidirectional cursor:
[references/pagination-and-queues.md](references/pagination-and-queues.md).

## Job queue in one table

`UPDATE … RETURNING` (3.35+) lets you atomically claim the next job
without a row lock or `SELECT FOR UPDATE`:

```sql
CREATE TABLE jobs (
    id           INTEGER PRIMARY KEY,
    queue        TEXT    NOT NULL DEFAULT 'default',
    payload      TEXT    NOT NULL,            -- JSON
    status       TEXT    NOT NULL DEFAULT 'queued'
                         CHECK (status IN ('queued','running','done','failed')),
    priority     INTEGER NOT NULL DEFAULT 0,
    run_after    INTEGER NOT NULL DEFAULT (unixepoch()),
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    leased_at    INTEGER,
    last_error   TEXT
) STRICT;

CREATE INDEX jobs_claim_idx ON jobs(queue, status, run_after, priority DESC, id)
    WHERE status = 'queued';

-- atomically claim one job
UPDATE jobs
   SET status = 'running',
       leased_at = unixepoch(),
       attempts = attempts + 1
 WHERE id = (
     SELECT id FROM jobs
      WHERE queue = ?1
        AND status = 'queued'
        AND run_after <= unixepoch()
      ORDER BY priority DESC, id
      LIMIT 1
   )
RETURNING id, payload;
```

A sweeper requeues leases older than the timeout. A dead-letter
move happens when `attempts >= max_attempts`. Full implementation:
[references/pagination-and-queues.md#job-queue](references/pagination-and-queues.md#job-queue).

## Full-text + vector search

FTS5 ships with SQLite; **`sqlite-vec`** adds vector kNN. Combine
them with reciprocal-rank fusion for hybrid search.

```sql
-- external-content FTS5: index stays in sync via triggers
CREATE VIRTUAL TABLE posts_fts USING fts5(
    title, body, content='posts', content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);

CREATE TRIGGER posts_ai AFTER INSERT ON posts BEGIN
    INSERT INTO posts_fts(rowid, title, body)
    VALUES (new.id, new.title, new.body);
END;
CREATE TRIGGER posts_ad AFTER DELETE ON posts BEGIN
    INSERT INTO posts_fts(posts_fts, rowid, title, body)
    VALUES ('delete', old.id, old.title, old.body);
END;
CREATE TRIGGER posts_au AFTER UPDATE ON posts BEGIN
    INSERT INTO posts_fts(posts_fts, rowid, title, body)
    VALUES ('delete', old.id, old.title, old.body);
    INSERT INTO posts_fts(rowid, title, body)
    VALUES (new.id, new.title, new.body);
END;

-- ranked search
SELECT p.id, p.title, snippet(posts_fts, 1, '<b>', '</b>', '…', 10) AS hit
FROM posts_fts JOIN posts p ON p.id = posts_fts.rowid
WHERE posts_fts MATCH ?
ORDER BY bm25(posts_fts);
```

For substring (not just prefix) matches, use the `trigram`
tokenizer. Hybrid retrieval and the `sqlite-vec` schema:
[references/fts5-and-vector-search.md](references/fts5-and-vector-search.md).

## JSON

`json_extract`, `->`, and `->>` (3.38+) let you treat columns as
documents:

```sql
SELECT id, payload ->> '$.user.email' AS email
FROM events
WHERE payload ->> '$.kind' = 'signup';

-- index a hot JSON path
CREATE INDEX events_kind_idx
    ON events (payload ->> '$.kind');
```

Promote anything you query often to a real column with a generated
column. Treat JSON as a **schemaless escape hatch**, not a default.

## Backups and replication

| Tool | Use for | Notes |
|---|---|---|
| `VACUUM INTO 'snap.db'` | Atomic snapshot to a file (3.27+) | Single-statement, works under load |
| Online backup API | Hot snapshot via SQLite C API | Used by `sqlite3.backup` in Python, etc. |
| **Litestream** | Continuous async replication to S3 / GCS / SFTP | One-process sidecar; near-zero data loss |
| **Turso / libSQL** | Embedded read replicas + write-through to a hosted primary | Drop-in SQLite-compatible client |
| **Cloudflare D1** | Serverless SQLite over HTTP at the edge | Per-DB limits; eventual replication |
| **rqlite / dqlite** | Raft-backed HA | Pay latency for consensus |

**Never** `cp` a live WAL database — it loses the `-wal` and
`-shm` state. Use `VACUUM INTO`, the backup API, or Litestream.

Full replication walkthrough:
[references/extensions-and-replication.md](references/extensions-and-replication.md).

## Migrations

SQLite does **not** support most `ALTER TABLE` operations natively
(rename column with deps, drop CHECK/FK, change type). The
canonical workaround is the **12-step rewrite** documented at
<https://sqlite.org/lang_altertable.html#otheralter>:

```sql
PRAGMA foreign_keys = OFF;
BEGIN;
CREATE TABLE posts_new ( … );           -- target shape
INSERT INTO posts_new SELECT … FROM posts;
DROP TABLE posts;
ALTER TABLE posts_new RENAME TO posts;
-- recreate indexes, triggers, views referring to posts
PRAGMA foreign_key_check;               -- verify before commit
COMMIT;
PRAGMA foreign_keys = ON;
```

Use a real migrator: **goose**, **atlas**, **alembic**,
**sqlx-migrate**, **dbmate**, or **sqlite-utils**. Pair with
[go-sql](../../go-sql/skills/go-sql/SKILL.md) for the sqlc + goose
flow against an SQLite engine.

## Driver picks

| Stack | Pick | Why |
|---|---|---|
| Node / Bun server | **better-sqlite3** (Node), **bun:sqlite** (Bun) | Synchronous API matches single-writer model; fast |
| Browser | **wa-sqlite** + OPFS | Real WAL semantics in the browser |
| Python | stdlib **sqlite3** + `isolation_level=None`; **aiosqlite** for async; **sqlite-utils** for CLI work | Stdlib is good enough; manage txns explicitly |
| Go | **modernc.org/sqlite** (pure Go, no CGo) or **mattn/go-sqlite3** (CGo, faster) | Pair with sqlc — see `go-sql` |
| Rust | **rusqlite** (sync) or **sqlx** (compile-time checked, async) | Bundled feature pins the SQLite version |
| iOS / Swift | **GRDB** | Recommended over SQLite.swift; clean concurrency model |
| Android / Kotlin | **Room** (Jetpack) or **SQLDelight** (KMP) | Codegen + compile-time SQL checking |
| React Native | **op-sqlite** (perf) or **expo-sqlite** (Expo-managed) | op-sqlite is JSI-based, much faster |
| Encrypted | **SQLCipher** | Drop-in AES-256 page encryption; ~5-15% perf cost |

Stack-specific tuning, pool sizing, and bundle/build notes:
[references/platforms.md](references/platforms.md).

## Useful extensions

- **`sqlean`** — uuid, stats, math, crypto, fileio, regexp, text;
  the "missing stdlib" for SQLite.
- **`sqlite-vec`** — vector kNN (cosine, L2, dot); successor to
  sqlite-vss.
- **R\*Tree** — spatial indexing; ships with SQLite.
- **`spellfix1`** — typo-tolerant suggestion; ships with SQLite.
- **`STMT` virtual table** — lists currently-prepared statements;
  ships with SQLite.

Load via `sqlite3 -cmd ".load ./vec0"` or the driver API
(`better-sqlite3` `loadExtension`, Python `enable_load_extension`,
Go `sqlite3_load_extension`). You must build/install the extension
binary for your platform.

Index of extensions and Litestream/Turso config:
[references/extensions-and-replication.md](references/extensions-and-replication.md).

## Gotchas

- **`INSERT OR REPLACE`** deletes the old row, cascading FKs.
  Prefer `INSERT … ON CONFLICT(col) DO UPDATE SET …` (upsert).
- **`foreign_keys = ON` is per-connection.** Easy to miss on a
  reader; enforce in the connection preamble.
- **WAL sidecars (`-wal`, `-shm`) must travel with the DB.** Don't
  ship just the `.db` file.
- **`cp` of a live WAL DB is corrupt.** Use `VACUUM INTO` or the
  backup API.
- **Type affinity without `STRICT`.** A `TEXT 'abc'` will happily
  land in an `INTEGER` column. STRICT tables reject it.
- **Date/time format.** Pick ISO-8601 text **or** unix seconds for
  the whole project. Mixing breaks indexes and comparisons.
- **`sqlite_sequence` quirks.** `AUTOINCREMENT` writes to that
  shared table on every insert — it's a contention hotspot. Drop
  `AUTOINCREMENT` unless you specifically need it.
- **`UPDATE` without `WHERE`.** Same risk as any SQL; the CLI's
  `.bail on` and `.changes on` help during interactive work.
- **Multithreading mode.** Check `PRAGMA compile_options` for
  `THREADSAFE=1` (full) or `=2` (multi-thread, no shared cache).
  Single-thread builds will deadlock under any concurrency.

## Observability and debugging

| Tool | Use |
|---|---|
| `EXPLAIN QUERY PLAN <sql>` | Show the planner's choices |
| `PRAGMA optimize` | Refresh stats; cheap to run on close |
| `ANALYZE` | Full stats rebuild; run after large bulk loads |
| `.timer on`, `.eqp on`, `.changes on` | CLI introspection toggles |
| `sqlite_stmt` vtable | List live prepared statements |
| `sqldiff old.db new.db` | Schema + data diff |
| `sqlite3_analyzer` | Per-table storage breakdown |
| `PRAGMA integrity_check` | Catches page-level corruption |
| `PRAGMA wal_checkpoint(TRUNCATE)` | Force a checkpoint + shrink the `-wal` file |

## When to load a sibling skill

| Task | Skill |
|---|---|
| sqlc + goose with SQLite engine | [go-sql](../../go-sql/skills/go-sql/SKILL.md) |
| Embedding SQLite in a Go CLI binary | [go-cli](../../go-cli/skills/go-cli/SKILL.md) |
| GRDB / Core Data on iOS | [apple-dev](../../apple-dev/skills/apple-dev/SKILL.md) |
| Browser SQLite via OPFS / wa-sqlite | [front-dev](../../front-dev/skills/front-dev/SKILL.md) |
| Wrapping `sql.ErrNoRows` cleanly in Go | [go-errors](../../go-errors/skills/go-errors/SKILL.md) |
