# Full-text and vector search

FTS5 ships with SQLite; **`sqlite-vec`** is a small extension that
adds vector kNN. Together they make a respectable hybrid search
stack you can embed anywhere SQLite runs.

## FTS5 basics

### External-content vs contentless

| Mode | Source rows | Pros | Cons |
|---|---|---|---|
| **External-content** (`content='posts'`) | Live in the source table | One copy of data; FTS5 is just an index | Need triggers to keep in sync |
| **Contentless** (`content=''`) | Stored only in FTS5 | Compact; good for ephemeral search | Cannot reconstruct original text |
| Standalone (default) | FTS5 owns the data | Simplest | Data duplicated |

External-content is the right default for most apps.

### Creating an external-content FTS5 table

```sql
CREATE TABLE posts (
    id          INTEGER PRIMARY KEY,
    author_id   INTEGER NOT NULL,
    title       TEXT NOT NULL,
    body        TEXT NOT NULL,
    created_at  INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE VIRTUAL TABLE posts_fts USING fts5(
    title,
    body,
    content='posts',
    content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);
```

### Sync triggers

```sql
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
```

The `'delete'` first column is the **FTS5 command channel** — it's
how you tell FTS5 to remove a row from a contentless / external-
content table without touching the source.

### Backfilling

After dropping/recreating an FTS5 index:

```sql
INSERT INTO posts_fts(posts_fts) VALUES ('rebuild');
```

That repopulates from the source table. For incremental
maintenance use `'optimize'`:

```sql
INSERT INTO posts_fts(posts_fts) VALUES ('optimize');
```

### Tokenizers

| Tokenizer | Use |
|---|---|
| `unicode61` (default) | Language-agnostic; lowercases; strips diacritics with `remove_diacritics 2` |
| `porter` | English stemming; `running` → `run` |
| `trigram` | 3-char shingles; substring (`LIKE '%foo%'`) replacement, requires 3.34+ |
| `ascii` | Fastest, ASCII only |
| custom | Implement `fts5_tokenizer` via the C API |

Multi-language stemming usually means installing a custom
tokenizer (snowball-stemmer-based or Lucene's analyzers ported).

```sql
-- Substring search
CREATE VIRTUAL TABLE files_fts USING fts5(
    path, content,
    tokenize='trigram'
);

-- Now "foo" finds "barfoobaz"
SELECT * FROM files_fts WHERE files_fts MATCH 'foo';
```

### Querying

FTS5's query syntax supports phrases, AND/OR, NEAR, prefix:

```
quick fox             -- both terms (AND by default)
"quick brown fox"     -- exact phrase
fox NOT lazy          -- exclusion
quick OR fox          -- either
quic*                 -- prefix
title:fox             -- column-specific
NEAR(quick fox, 10)   -- within 10 tokens
```

### Ranking with `bm25()`

```sql
SELECT
    posts.id,
    snippet(posts_fts, 1, '<b>', '</b>', '…', 10) AS excerpt,
    bm25(posts_fts, 10.0, 1.0) AS rank
FROM posts_fts
JOIN posts ON posts.id = posts_fts.rowid
WHERE posts_fts MATCH :query
ORDER BY rank        -- LOWER bm25 = better match
LIMIT 20;
```

`bm25(table, weight_title, weight_body, …)` lets you boost
specific columns. Title weight 10× body weight is a common
default for blog/article search.

`snippet(table, column_idx, start_marker, end_marker, ellipsis, max_tokens)`
returns a highlighted excerpt. `highlight(table, column_idx, start, end)`
returns the full text with all matches marked.

### Index maintenance

```sql
PRAGMA wal_checkpoint(PASSIVE);
INSERT INTO posts_fts(posts_fts) VALUES ('optimize');
ANALYZE posts_fts;
```

Run nightly on busy indexes. `optimize` merges b-tree segments.

## Vector search with sqlite-vec

[`sqlite-vec`](https://github.com/asg017/sqlite-vec) is the
current recommendation (it replaced the deprecated
`sqlite-vss`/Faiss-based extension). Pure C, no heavy deps, runs
in WASM and mobile.

### Loading the extension

```sql
.load ./vec0
-- or in code: sqlite3_load_extension(db, "./vec0", "sqlite3_vec_init", &err)
```

### Schema

```sql
CREATE VIRTUAL TABLE vec_posts USING vec0(
    post_id    INTEGER PRIMARY KEY,
    embedding  float[384]                -- dim must match your model
);
```

Common embedding dims:
- `384` — `all-MiniLM-L6-v2`, BGE-small.
- `768` — BGE-base, `text-embedding-3-small`-projection.
- `1536` — OpenAI `text-embedding-3-small`.
- `3072` — OpenAI `text-embedding-3-large`.

### Insert and query

```sql
INSERT INTO vec_posts(post_id, embedding)
VALUES (?, vec_f32(?));        -- pass a 4*dim-byte BLOB or JSON array

-- k-nearest neighbors
SELECT post_id, distance
FROM vec_posts
WHERE embedding MATCH vec_f32(:query_embedding)
ORDER BY distance
LIMIT 10;
```

Distance metric defaults to L2 (Euclidean). Use cosine via
`vec_distance_cosine()` if you keep raw vectors.

### Binary quantization for size

For million-row+ collections, store binary-quantized vectors to
shrink storage ~32× at the cost of recall:

```sql
CREATE VIRTUAL TABLE vec_posts USING vec0(
    post_id INTEGER PRIMARY KEY,
    embedding bit[384]
);
```

Use the binary index for first-pass kNN, then re-rank top-100
with the full-precision vectors stored elsewhere.

## Hybrid search: FTS5 + vec

Pure keyword search misses semantic neighbors; pure vector misses
exact matches and rare terms. Fuse them with **Reciprocal Rank
Fusion (RRF)**:

```sql
WITH
  kw AS (
    SELECT rowid AS id,
           row_number() OVER (ORDER BY bm25(posts_fts)) AS rk
    FROM posts_fts
    WHERE posts_fts MATCH :query
    LIMIT 100
  ),
  vec AS (
    SELECT post_id AS id,
           row_number() OVER (ORDER BY distance) AS rk
    FROM vec_posts
    WHERE embedding MATCH vec_f32(:query_embedding)
    ORDER BY distance
    LIMIT 100
  ),
  fused AS (
    SELECT id, sum(1.0 / (60 + rk)) AS score
    FROM (SELECT * FROM kw UNION ALL SELECT * FROM vec)
    GROUP BY id
  )
SELECT p.id, p.title, fused.score
FROM fused JOIN posts p ON p.id = fused.id
ORDER BY fused.score DESC
LIMIT 20;
```

The constant `60` in `1/(60+rk)` is the RRF smoothing parameter —
larger values flatten the contribution of high-rank items;
smaller values let the top-ranked items dominate. 60 is the
canonical default from the original RRF paper.

To **boost** one signal over the other:

```
score = α * 1/(60+kw_rk) + (1-α) * 1/(60+vec_rk)
```

## When to skip SQLite vector search

`sqlite-vec` is brute-force kNN — fast up to a few million
rows, slow beyond that. If you have hundreds of millions of
vectors, use a dedicated vector DB (pgvector with HNSW, Qdrant,
Weaviate, LanceDB). For the laptop-, mobile-, and edge-scale
cases SQLite excels at, brute force is plenty.

## Auxiliary helpers

`vec0` virtual tables expose useful functions:

```sql
SELECT vec_length(embedding)            FROM vec_posts WHERE post_id = 1;
SELECT vec_distance_l2(a, b)            FROM …;
SELECT vec_distance_cosine(a, b)        FROM …;
SELECT vec_normalize(embedding)         FROM …;
SELECT vec_quantize_binary(embedding)   FROM …;     -- → bit[]
```
