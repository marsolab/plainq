# PRAGMAs, connection setup, and the writer-concurrency model

PRAGMA values are mostly **per connection** (a few are persisted in
the DB file). Set the full preamble on every new handle in your
connection factory — the most common foot-gun is a stray reader
without `foreign_keys = ON` or `busy_timeout`.

## The full preamble, annotated

```sql
PRAGMA journal_mode = WAL;            -- persisted in DB; idempotent
PRAGMA synchronous = NORMAL;          -- per-conn; safe with WAL
PRAGMA busy_timeout = 5000;           -- ms; per-conn
PRAGMA foreign_keys = ON;             -- per-conn; OFF by default
PRAGMA temp_store = MEMORY;           -- per-conn
PRAGMA cache_size = -64000;           -- per-conn; negative = KiB
PRAGMA mmap_size = 134217728;         -- per-conn; bytes
PRAGMA journal_size_limit = 67108864; -- per-DB; caps WAL on truncate
```

For long-lived server connections, add on open:

```sql
PRAGMA optimize = 0x10002;            -- 3.46+; analyze on connect
```

and on close (or hourly):

```sql
PRAGMA optimize;
```

### `journal_mode`

- `DELETE` (default) — rollback journal, blocks readers during writes.
- `WAL` — write-ahead log, **enables N readers concurrent with 1
  writer**. Persists in the DB file; survives reopens.
- `MEMORY` / `OFF` — unsafe; only for tests.
- `TRUNCATE` / `PERSIST` — older optimizations of `DELETE`.

**Do not use WAL on NFS, SMB, GlusterFS, Dropbox, iCloud Drive.**
The `-shm` file uses memory-mapped shared memory that is not
reliable across network filesystems. Use a local SSD.

### `synchronous`

| Setting | What it does | When |
|---|---|---|
| `OFF` | No fsync — fastest, can corrupt on power loss | Ephemeral tests only |
| `NORMAL` | fsync at WAL checkpoint; tail commits may be lost on **kernel/power** crash but **never** corrupt the DB. Safe across **application** crashes. | Default for WAL servers |
| `FULL` | fsync at every commit. Slower (~10×). Durable across power loss. | Financial / audit data |
| `EXTRA` | `FULL` + sync the directory entry too | Paranoid |

`NORMAL` is the sweet spot with `WAL`. The classic
"SQLite is slow on writes" report is usually a default
`journal_mode=DELETE` + `synchronous=FULL` combination.

### `busy_timeout`

When a connection hits a lock, SQLite spins (with internal
exponential backoff) up to `busy_timeout` ms before returning
`SQLITE_BUSY`. **5 seconds** is a reasonable default; bump to
30 s for batch jobs.

This only helps if the conflicting transaction will release the
lock soon. Long-running write transactions still cause `BUSY`.

### `foreign_keys`

Off by default for back-compat with pre-3.6.19 (2009!) databases.
**Set this on every connection.** Forgetting it on a reader means
SQLite happily lets dangling FKs propagate. ORMs like SQLAlchemy
emit this on every `connect` event automatically; raw drivers
don't.

### `cache_size`

Negative = KiB; positive = pages (1 page is 4 KiB by default).
`-64000` ≈ 64 MiB per connection. **Per-connection**, so a pool
of 10 readers × 64 MiB ≈ 640 MiB resident.

For mobile: drop to `-8000` (8 MiB) to fit in process budgets.

### `mmap_size`

Memory-map the main DB file for reads. 128 MiB is a safe default
on 64-bit servers; up to 1 GiB for DBs that fit in RAM. Set to
`0` on:

- 32-bit systems (address space exhaustion)
- mobile (VM pressure / OOM-killer)
- DBs much larger than physical RAM (mmap eviction is opaque)

### `temp_store`

`MEMORY` keeps temp tables / sorts / `WITH` materializations off
disk. On Linux containers with small `/tmp`, this prevents
"database or disk is full" mid-query.

### `journal_size_limit`

Without this, a single huge write transaction permanently inflates
the `-wal` sidecar (SQLite checkpoints but doesn't shrink the
file). 64 MiB is generous for most apps; tune to your largest
expected transaction.

### `auto_vacuum`

Must be set **before** the first `CREATE TABLE`, or you must run a
full `VACUUM` to apply.

| Mode | Behavior |
|---|---|
| `NONE` (default) | Free pages reused; file never shrinks |
| `FULL` | File shrinks on every commit (write amplification) |
| `INCREMENTAL` | Free pages tracked; call `PRAGMA incremental_vacuum(N)` manually during idle |

Use `INCREMENTAL` for production data stores where you delete a
lot of rows and want file size predictability.

### `secure_delete`

Overwrites freed pages with zeros so deleted bytes can't be
recovered from the file. ~2× slower DELETE/UPDATE. Use for
PII, password vaults, encrypted-at-rest stores (combine with
SQLCipher).

### `PRAGMA optimize`

Since SQLite 3.18 (2017), redesigned in 3.46 (May 2024) to
auto-limit ANALYZE scope. Recommended:

- **Long-lived connections** — `PRAGMA optimize = 0x10002` on open,
  then `PRAGMA optimize;` every few hours.
- **Short-lived (CLI)** — `PRAGMA optimize;` before close.
- **After bulk loads or schema changes** — always.

On pre-3.46, run `PRAGMA analysis_limit = 400;` first to keep
`optimize` cheap on huge tables.

### WAL checkpoint modes

`PRAGMA wal_checkpoint(MODE)` flushes WAL frames into the main DB:

| Mode | Behavior |
|---|---|
| `PASSIVE` | Default. Checkpoints what it can without blocking. |
| `FULL` | Waits for readers to release snapshots, then checkpoints. |
| `RESTART` | `FULL` + ensures next writer starts at WAL offset 0. |
| `TRUNCATE` | `RESTART` + shrinks the WAL file to zero bytes. |

`PRAGMA wal_autocheckpoint = 1000;` (default) auto-checkpoints
every ~4 MiB of WAL growth. Lower for smaller WAL footprint,
higher to reduce checkpoint stalls under sustained write load.

## Connection lifecycle

```python
def open_conn(path: str, readonly: bool = False) -> sqlite3.Connection:
    uri = f"file:{path}?mode={'ro' if readonly else 'rwc'}"
    conn = sqlite3.connect(uri, uri=True, isolation_level=None)
    conn.executescript("""
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA busy_timeout = 5000;
        PRAGMA foreign_keys = ON;
        PRAGMA temp_store = MEMORY;
        PRAGMA cache_size = -64000;
        PRAGMA mmap_size = 134217728;
        PRAGMA journal_size_limit = 67108864;
    """)
    # 3.46+: warm up planner stats
    conn.execute("PRAGMA optimize = 0x10002")
    return conn

def close_conn(conn):
    try:
        conn.execute("PRAGMA optimize")
    finally:
        conn.close()
```

`isolation_level=None` in Python's stdlib `sqlite3` disables its
implicit `BEGIN` behavior so you can manage transactions
explicitly — recommended.

## Writer concurrency

### One writer, many readers

WAL allows concurrent readers but **exactly one writer at a time**.
The canonical pool layout:

```
┌─ writer connection (1) ─────────┐
│  - serializes all writes        │
│  - BEGIN IMMEDIATE on every txn │
└─────────────────────────────────┘
┌─ reader pool (N, sized to CPU) ─┐
│  - opened mode=ro               │
│  - PRAGMA query_only = 1        │
│  - share via channel/semaphore  │
└─────────────────────────────────┘
```

Framework support that bakes this in:

- **Rails 7.1+** — separate `writer` (size 1) and `reader` pools.
- **GRDB.swift** — `DatabasePool` (readers share snapshots).
- **better-sqlite3** — single sync connection (Node single-thread).
- **Go** — `db.SetMaxOpenConns(1)` on the write handle; a separate
  read DSN with `?mode=ro&_journal_mode=WAL`.
- **Rust sqlx** — `SqlitePoolOptions::max_connections(1)` for write
  pool; second pool for readers.

### `BEGIN IMMEDIATE` for any txn that writes

```sql
BEGIN IMMEDIATE;     -- grabs RESERVED lock now
  UPDATE ...
  INSERT ...
COMMIT;
```

`BEGIN` defaults to `DEFERRED`. With `DEFERRED`, a transaction
that did `SELECT` first and then tries to `UPDATE` may have to
upgrade its lock. If another writer beat you to it, SQLite
returns `SQLITE_BUSY` **immediately** — `busy_timeout` is
ignored — because waiting could deadlock (two readers each
holding a snapshot, both wanting to write).

`BEGIN IMMEDIATE` takes the write intention up front and **does**
respect `busy_timeout`. **Use `IMMEDIATE` for every transaction
that writes.**

`BEGIN EXCLUSIVE` additionally blocks new readers (rare; only for
schema migrations).

### Busy-retry algorithm

```python
import random, time

def write_with_retry(conn, fn, *, max_retries=5, base=0.05):
    for attempt in range(max_retries):
        try:
            conn.execute("BEGIN IMMEDIATE")
            fn(conn)
            conn.execute("COMMIT")
            return
        except sqlite3.OperationalError as e:
            conn.execute("ROLLBACK")
            if "locked" not in str(e) and "busy" not in str(e):
                raise
            if attempt == max_retries - 1:
                raise
            time.sleep((2 ** attempt) * base + random.random() * base)
```

Retry **outside** the transaction. Inside, you can't recover
cleanly from `SQLITE_BUSY`.

### Common "database is locked" causes

1. **Long write transaction holding the lock.** Break it into
   smaller chunks. Move RPC / HTTP calls outside the txn.
2. **DEFERRED transaction upgrading mid-flight.** Switch to
   `BEGIN IMMEDIATE`.
3. **Reader pinning a snapshot during checkpoint.** Less common
   with `wal_autocheckpoint`. Use shorter read transactions.
4. **Two writers in the same process.** Serialize through one
   writer connection, not a pool.

## Multithreading mode

`PRAGMA compile_options` tells you which build you're on:

- `THREADSAFE=0` — single-thread; deadlock if shared.
- `THREADSAFE=2` — multi-thread; one connection per thread (most
  builds).
- `THREADSAFE=1` — serialized; safe to share a connection across
  threads, internal locks. Default on most distros.

For server use, `THREADSAFE=1` is usually fine. For max perf,
build with `=2` and explicitly hand out one connection per
worker.
