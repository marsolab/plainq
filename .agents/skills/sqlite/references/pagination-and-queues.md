# Pagination and job queues

Two patterns that come up in nearly every SQLite-backed app:
keyset pagination (so list views stay O(page) regardless of
depth) and a one-table job queue (so you don't reach for Redis
just to schedule work).

## Pagination

### Why not OFFSET

`LIMIT N OFFSET M` scans `N + M` rows and discards the first `M`.
Page 10 (offset 200) is fine; page 1000 (offset 20 000) reads 20 050
rows for every request. Cheap-to-start, expensive at scale, and
unstable when rows are inserted/deleted between page loads.

### Keyset / seek pagination

Order by a deterministic key, including the PK as a tie-breaker.
Carry the last row's values forward as a cursor.

```sql
-- first page
SELECT id, created_at, title
FROM posts
ORDER BY created_at DESC, id DESC
LIMIT 20;

-- next page: cursor = last row's (created_at, id)
SELECT id, created_at, title
FROM posts
WHERE (created_at, id) < (:cursor_at, :cursor_id)
ORDER BY created_at DESC, id DESC
LIMIT 20;
```

SQLite supports **row-value comparisons** since 3.15 — use them.
They compare lexicographically, so `(a, b) < (x, y)` means
`a < x OR (a = x AND b < y)`.

Matching index:

```sql
CREATE INDEX idx_posts_created_desc
    ON posts(created_at DESC, id DESC);
```

The index direction must match the sort. With this, the query is
a bounded index range scan — O(20).

### Encoding the cursor

Hand the client an opaque token:

```python
def encode_cursor(created_at: int, id_: int) -> str:
    raw = f"{created_at}:{id_}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")

def decode_cursor(tok: str) -> tuple[int, int]:
    pad = "=" * (-len(tok) % 4)
    a, b = base64.urlsafe_b64decode(tok + pad).decode().split(":")
    return int(a), int(b)
```

Treat the token as opaque server-side — clients should never
parse it. If you need to change the order later, version the
cursor: `v1:1715512345:42`.

### Bidirectional pagination

Previous page: flip the comparator and the sort, then reverse the
results in app code.

```sql
SELECT id, created_at, title
FROM posts
WHERE (created_at, id) > (:cursor_at, :cursor_id)
ORDER BY created_at ASC, id ASC
LIMIT 20;
-- then reverse the rows before returning
```

To detect whether more pages exist, fetch `LIMIT N+1` and strip
the extra row.

### When you need a total count

Counts on large tables are expensive. Options, worst to best:

1. `SELECT COUNT(*) FROM posts WHERE …` — O(N).
2. Window function: `COUNT(*) OVER ()` alongside the page — pays
   the cost once but still O(N).
3. **Approximate**: maintain a counter table updated by triggers,
   or use `SELECT MAX(rowid) - MIN(rowid)` as a rough estimate.
4. **Don't show a total.** Show "N+ results" if there's a next
   page. Most users don't care.

---

## Job queue in one table

A surprisingly capable queue, no Redis, no Postgres. Atomic
claim via `UPDATE … RETURNING` (SQLite 3.35+, March 2021) and a
sweeper for lease timeouts.

### Schema

```sql
CREATE TABLE jobs (
    id           INTEGER PRIMARY KEY,
    queue        TEXT    NOT NULL DEFAULT 'default',
    payload      TEXT    NOT NULL,                  -- JSON
    status       TEXT    NOT NULL DEFAULT 'queued'
                          CHECK (status IN ('queued','running','done','failed','dead')),
    priority     INTEGER NOT NULL DEFAULT 0,        -- higher first
    run_after    INTEGER NOT NULL DEFAULT (unixepoch()),
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    leased_at    INTEGER,
    leased_by    TEXT,
    last_error   TEXT,
    created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
    finished_at  INTEGER
) STRICT;

-- The hot path: pick the next runnable row in one queue.
CREATE INDEX idx_jobs_claim
    ON jobs(queue, priority DESC, run_after, id)
    WHERE status = 'queued';

-- The sweeper's path.
CREATE INDEX idx_jobs_stuck
    ON jobs(leased_at)
    WHERE status = 'running';
```

### Atomic claim

```sql
UPDATE jobs
   SET status     = 'running',
       leased_at  = unixepoch(),
       leased_by  = :worker_id,
       attempts   = attempts + 1
 WHERE id = (
     SELECT id
       FROM jobs
      WHERE status = 'queued'
        AND queue = :queue
        AND run_after <= unixepoch()
      ORDER BY priority DESC, run_after, id
      LIMIT 1
   )
RETURNING id, payload, attempts, max_attempts;
```

Wrap in `BEGIN IMMEDIATE`. The single-writer model means you
don't need `FOR UPDATE SKIP LOCKED` — there's no concurrent
claimer.

### Completing a job

```sql
UPDATE jobs
   SET status = 'done',
       finished_at = unixepoch(),
       leased_at = NULL,
       leased_by = NULL
 WHERE id = :id;
```

### Retrying with exponential backoff

```sql
-- On failure
UPDATE jobs
   SET status     = 'queued',
       run_after  = unixepoch() + (1 << min(attempts, 10)),  -- 2^attempts s, capped
       last_error = :err,
       leased_at  = NULL,
       leased_by  = NULL
 WHERE id = :id;
```

When `attempts >= max_attempts`, set `status = 'dead'` instead —
the dead-letter row stays in the table for inspection. Move to a
separate `jobs_dead` table on a cron if the live table gets
crowded.

### Sweeping orphaned leases

Workers crash. Find rows whose lease expired and return them to
the queue:

```sql
UPDATE jobs
   SET status     = 'queued',
       leased_at  = NULL,
       leased_by  = NULL,
       last_error = 'lease expired'
 WHERE status = 'running'
   AND leased_at < unixepoch() - :lease_seconds;
```

Run this every `lease_seconds / 2` from one process (or any
process — it's idempotent).

### Polling vs change notification

Cheapest: poll every 1 second for `queue = ?, status = 'queued',
run_after <= now`. With the partial index, this is a few µs.

Lower-latency: register an `sqlite3_update_hook` callback. On any
`INSERT` into `jobs` in your process, wake the worker. Drivers
expose this:

- Node `better-sqlite3`: `db.aggregate`, `db.function`, plus the
  `update_hook` via the C API (community wrappers).
- Rust `rusqlite`: `conn.update_hook(…)`.
- Go `mattn/go-sqlite3`: `sqlite3.SQLiteConn.RegisterUpdateHook`.
- Python: not exposed by stdlib; use `apsw`'s `setupdatehook`.

For **cross-process** notification, you need a side channel — a
Unix socket, a pipe, or a `litequeue`-style "wake the worker"
file. The DB itself doesn't broadcast.

### Priorities and queues

Multiple named queues live in one table. Worker A claims from
`queue = 'email'`, worker B from `queue IN ('default','low')`.
Sort by `priority DESC` to favor high-priority rows.

If you need per-queue rate limits, add a `tokens` table and a
CTE that decrements a bucket before claiming a row.

### Dead-letter inspection

```sql
-- Recent failures by error pattern
SELECT substr(last_error, 1, 80) AS err, count(*) AS n
FROM jobs WHERE status IN ('failed','dead')
GROUP BY err ORDER BY n DESC LIMIT 20;

-- Retry a specific dead job
UPDATE jobs
   SET status='queued', attempts=0, run_after=unixepoch(), last_error=NULL
 WHERE id = :id;
```

### Real-world implementations

- **[litequeue](https://github.com/litements/litequeue)** —
  Python, the canonical "small SQLite queue" example.
- **[goqite](https://github.com/maragudk/goqite)** — Go, similar
  shape with `UPDATE … RETURNING`.
- **[River](https://github.com/riverqueue/river)** — Postgres
  queue; the schema and lease pattern translate cleanly to
  SQLite.
- **[Oban](https://github.com/oban-bg/oban)** — Elixir; same
  ideas, also Postgres-first.

The pattern is portable: a partial index on `WHERE status =
'queued'`, atomic claim via `UPDATE … RETURNING`, lease-based
recovery.
