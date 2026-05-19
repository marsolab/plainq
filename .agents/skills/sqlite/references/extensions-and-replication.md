# Extensions, backups, and replication

What ships with SQLite, what's worth installing, and how to keep
the data alive across reboots / disasters / multiple regions.

## Loading extensions

By default, the SQLite CLI enables extension loading; library
bindings usually disable it for safety. Enable in code first:

```c
sqlite3_enable_load_extension(db, 1);
sqlite3_load_extension(db, "./vec0", "sqlite3_vec_init", &err);
```

Per-driver:

| Driver | API |
|---|---|
| Python stdlib | `conn.enable_load_extension(True); conn.load_extension("./vec0")` |
| Node `better-sqlite3` | `db.loadExtension("./vec0")` |
| Rust `rusqlite` | crate feature `load_extension`; `conn.load_extension(...)` |
| Go `mattn/go-sqlite3` | build tag `sqlite_load_extension`; `sqlite3_load_extension` DSN param |
| Go `modernc.org/sqlite` | currently limited; check upstream |

For CLI: `.load ./vec0` from `sqlite3` shell.

You're responsible for shipping the extension `.so`/`.dylib`/`.dll`
for the right architecture. Most extensions publish per-platform
builds on their releases page.

## Bundled and built-in extensions

These ship inside SQLite proper or in `ext/misc/` — no install
needed for most distros:

- **JSON1** — built-in since 3.38. `json_extract`, `->`, `->>`,
  `json_each`, `json_tree`.
- **FTS5** — full-text search; enabled in most distro builds. Check
  `PRAGMA compile_options` for `ENABLE_FTS5`.
- **R*Tree** — spatial indexing; usually enabled.
- **JSONB** (3.45+, 2024) — binary JSON columns; `jsonb()`,
  `jsonb_extract()`. ~3× faster than JSON1 on large documents.
- **`spellfix1`** — typo-tolerant suggestion (Soundex + edit
  distance).
- **`stmt` virtual table** — list currently-prepared statements
  (`SELECT * FROM sqlite_stmt`). Requires `ENABLE_STMTVTAB`.
- **`csv` virtual table** — read CSV as a table.
- **`series` virtual table** — `SELECT value FROM generate_series(1, 100)`.
- **`zipfile` virtual table** — read/write zip archives as rows.

## Worth installing

### `sqlean` — the missing stdlib

[`sqlean`](https://github.com/nalgeon/sqlean) is a modular pack
maintained by Anton Zhiyanov. Drop-in `.so`s for what should have
been in stdlib:

| Module | What |
|---|---|
| `crypto` | md5, sha1/256/384/512, hex, base64 |
| `uuid` | `uuid4()`, `uuid_str()`, `uuid_blob()` |
| `fileio` | `readfile()`, `writefile()`, `lsdir()` |
| `regexp` | PCRE-style regex |
| `text` | `text_split`, `text_join`, padding, case helpers |
| `time` | `time_now`, `time_add`, `time_fmt` |
| `math` | trig, log, hypot |
| `stats` | median, percentile, stddev |
| `vsv` | virtual CSV reader (more flexible than built-in `csv`) |
| `unicode` | normalization, casefold |

Load: `.load ./sqlean-uuid`, etc.

### `sqlite-vec` — vector kNN

See `fts5-and-vector-search.md`. The current vector extension of
choice; replaces deprecated `sqlite-vss`.

### `sqlite-regex` — Rust-backed regex

[`asg017/sqlite-regex`](https://github.com/asg017/sqlite-regex) —
PCRE2 with named captures.

```sql
SELECT regexp_capture(line, '(\d+) (\w+)') FROM logs;
SELECT regexp_replace(s, '\s+', ' ') FROM …;
```

### `spellfix1` — fuzzy text

```sql
CREATE VIRTUAL TABLE demo USING spellfix1;
INSERT INTO demo(word) VALUES ('similar'), ('typo'), …;
SELECT word FROM demo WHERE word MATCH 'similer';   -- finds 'similar'
```

Combine with FTS5 for spell-correction in search UIs.

### R*Tree — spatial

Built-in. Use for geo-bounding-box queries:

```sql
CREATE VIRTUAL TABLE places USING rtree(
    id,
    min_lng, max_lng,
    min_lat, max_lat
);
SELECT id FROM places
WHERE min_lng <= ? AND max_lng >= ?
  AND min_lat <= ? AND max_lat >= ?;
```

For real GIS, use SpatiaLite (a separate extension built on
SQLite + R*Tree + GEOS).

## Backups

### `VACUUM INTO` (3.27+)

The simplest reliable backup. Atomic, consistent, defragments,
and works while the DB is in use.

```sql
VACUUM INTO '/backups/app-2026-05-12.db';
```

Single statement. Output is a compacted copy. Use for nightly
snapshots and pre-migration safety nets.

### Online backup API

C-level `sqlite3_backup_init/step/finish` copies pages
incrementally with brief read-lock acquisitions. Exposed by:

- **Python**: `dest.backup(src, pages=100, sleep=0.05)`.
- **Go** (`mattn`): `conn.Backup("main", dst, "main")`.
- **Node `better-sqlite3`**: `db.backup(destPath, {progress})`.
- **Rust `rusqlite`**: `conn.backup(MAIN_DB, dst_path, None)`.

Use when you want a backup running concurrent with sustained
write traffic — `VACUUM INTO` briefly holds a write lock; the
backup API yields between page batches.

### `.dump`

```bash
sqlite3 prod.db ".dump" > prod.sql
sqlite3 restored.db < prod.sql
```

Slow on restore, but human-readable and works across major
version jumps. Useful for migrations from SQLite to Postgres /
MySQL (with light editing).

### What **not** to do

- **`cp prod.db prod.db.bak`** while writers are active — the
  `-wal` sidecar has uncheckpointed frames; the copy is
  corrupt.
- **`tar czf snapshot.tgz prod.db`** — same problem.
- **`rsync prod.db` over a live DB** — partial-write window.

Always use `VACUUM INTO`, the backup API, Litestream, or shut
down writers and `PRAGMA wal_checkpoint(TRUNCATE);` first.

## Replication

### Litestream

[Litestream](https://litestream.io) streams WAL frames to
S3-compatible storage in near real-time. Sidecar process; no
schema awareness, no SQL parsing.

Minimal `litestream.yml`:

```yaml
dbs:
  - path: /var/lib/app/data.db
    replicas:
      - url: s3://my-backups/data
        retention: 168h
        snapshot-interval: 24h
        sync-interval: 1s
```

Run alongside your app:

```bash
litestream replicate -config /etc/litestream.yml
```

Restore:

```bash
litestream restore -o /var/lib/app/data.db s3://my-backups/data
```

**Trade-offs:**

- Single-writer: one node writes; replicas are restore-only, not
  hot read replicas.
- RPO: sub-second with `sync-interval: 1s`.
- RTO: restore time, typically seconds-to-minutes.
- Works with any S3-compatible store, GCS, Azure, SFTP, ABS.

### Turso / libSQL

[Turso](https://turso.tech) ships a fork called
**[libSQL](https://github.com/tursodatabase/libsql)** with
native replication. SQLite-compatible API; client drivers in
most languages.

Features beyond stock SQLite:

- **Embedded replicas**: app opens a local libSQL file that
  auto-syncs from a hosted primary (write-through to primary,
  local reads).
- **`BEGIN CONCURRENT`** (optimistic write concurrency).
- **`ALTER TABLE`** extensions (drop CHECK, change types).
- **Vector primitives** in core (parallel to `sqlite-vec`).
- HTTP-only client for serverless.

```ts
import { createClient } from "@libsql/client";

const db = createClient({
  url: "file:local.db",                // embedded replica path
  syncUrl: "libsql://my-db.turso.io",
  authToken: process.env.TURSO_TOKEN,
});
await db.sync();                        // pull updates
```

Use Turso when you want **read replicas at the edge** with a
SQLite mental model.

### Cloudflare D1

SQLite over HTTP at the edge, managed entirely by Cloudflare.
Workers get a binding; you write SQL.

```ts
export default {
  async fetch(req, env) {
    const { results } = await env.DB
      .prepare("SELECT * FROM posts WHERE id = ?")
      .bind(id)
      .all();
    return Response.json(results);
  }
}
```

Caveats:

- No `PRAGMA`s exposed; no extension loading.
- Eventual consistency between replicas; primary is per-DB.
- Per-DB size limit (10 GiB at time of writing).
- Per-query CPU/time limits — beware long-running statements.

### rqlite and dqlite

| Tool | Model | Use |
|---|---|---|
| [**rqlite**](https://rqlite.io) | Raft cluster wrapping SQLite, HTTP API | Multi-node HA with strong consistency |
| [**dqlite**](https://dqlite.io) | Library form of Raft + SQLite (powers LXD) | Embed HA into your own daemon |

Pay a latency cost (consensus round-trip per write). Suitable
for control-plane / configuration data, not chat/feed traffic.

### When to pick what

| Need | Pick |
|---|---|
| Backup safety net | `VACUUM INTO` nightly + Litestream continuous |
| Read replicas at the edge | Turso embedded replicas |
| Serverless edge DB | Cloudflare D1 |
| Multi-region HA, strong consistency | rqlite |
| HA inside your own Go/C daemon | dqlite |
| Backup-only, no replicas | Litestream alone |

## Diagnostic tools

| Tool | Use |
|---|---|
| `sqldiff old.db new.db` | Schema + data diff |
| `sqlite3_analyzer` | Per-table page/space report |
| `sqlite3 :memory: '.recover'` | Recover rows from a corrupt file |
| `sqlite3_rsync` (3.46+) | rsync-like for live DBs over SSH |
| `PRAGMA integrity_check` | Full DB consistency check |
| `PRAGMA quick_check` | Faster, less thorough variant |

`integrity_check` is safe to run periodically against a hot DB;
budget for a few seconds per GiB.
