# Platform-specific drivers and patterns

What to install, what to watch out for, and stack-specific
quirks. The PRAGMA preamble from
[pragmas-and-connection.md](pragmas-and-connection.md) applies
everywhere — these notes are about the driver and the
surrounding ecosystem.

## Node.js / Bun / Deno

### Node — pick `better-sqlite3`

[**better-sqlite3**](https://github.com/WiseLibs/better-sqlite3)
is the default choice for Node servers:

```js
import Database from "better-sqlite3";

const db = new Database("app.db");
db.pragma("journal_mode = WAL");
db.pragma("synchronous = NORMAL");
db.pragma("busy_timeout = 5000");
db.pragma("foreign_keys = ON");

const getUser = db.prepare("SELECT * FROM users WHERE id = ?");
const user = getUser.get(42);     // sync, no callback
```

- **Synchronous API** matches Node's single-threaded event loop
  and SQLite's single-writer model perfectly.
- Prepared statements are reusable, fast, and cached.
- `db.transaction(fn)` wraps in `BEGIN IMMEDIATE` automatically.
- Extension loading via `db.loadExtension('./vec0')`.

Avoid the legacy `sqlite3` npm package for new code — async/callback
API, slower, no transparent advantages.

`node:sqlite` ships in **Node 22.5+** as built-in (currently
experimental, stable in 24+). Same shape as `better-sqlite3`,
zero install.

### Bun

`bun:sqlite` is built-in, synchronous, very fast:

```js
import { Database } from "bun:sqlite";

const db = new Database("app.db", { create: true });
db.exec("PRAGMA journal_mode = WAL");
```

### Deno

Use `jsr:@db/sqlite` (`x/sqlite` is older / slower) or
`node:sqlite` (Deno honors Node compat).

### Browser SQLite

For in-browser DBs, **`wa-sqlite`** with OPFS storage is the
modern choice — real WAL semantics, durable across reloads.
`sql.js` (Emscripten port without OPFS) works for read-only
demos but loses data on reload.

Bundle sizes are ~1 MiB wasm. Persistence:

| Backend | Persistent? | Cross-tab? | Notes |
|---|---|---|---|
| OPFS-Async | yes | no | Default; needs cross-origin headers |
| OPFS (sync, COOP/COEP) | yes | yes | Web Worker only |
| IndexedDB shim | yes | yes | Slower; cross-tab |
| In-memory | no | n/a | Default `sql.js` |

For LLM-app prototypes and offline-first PWAs, `wa-sqlite` +
OPFS is the right pick.

## Python

Stdlib `sqlite3` is fine for most uses. Configure it for sanity:

```python
conn = sqlite3.connect(
    "app.db",
    isolation_level=None,       # manage transactions yourself
    detect_types=sqlite3.PARSE_DECLTYPES,
    check_same_thread=False,    # if you're using a connection-per-task pool
)
conn.row_factory = sqlite3.Row
conn.executescript(PREAMBLE)
```

- **`isolation_level=None`** disables Python's implicit `BEGIN`
  inserter, which otherwise wraps statements in a transaction
  you didn't ask for and silently swallows DDL.
- **`apsw`** ([Another Python SQLite Wrapper](https://github.com/rogerbinns/apsw))
  exposes the full C API including update hooks, BLOB I/O,
  load_extension, virtual tables — use it if stdlib `sqlite3`
  can't reach the API you need.
- **`aiosqlite`** wraps stdlib in an asyncio interface (work
  happens on a single background thread; no true parallelism).
- **`sqlite-utils`** (Simon Willison) — fantastic CLI for
  schema inspection, bulk loads, transforms, view creation, FTS
  setup. The `transform` subcommand handles the 12-step `ALTER
  TABLE` rewrite for you.
- **[Datasette](https://datasette.io)** — instant read-only HTTP
  API + browsable UI for any SQLite file. Excellent for
  internal data exploration.

SQLAlchemy works well with SQLite; remember to register the
PRAGMA preamble on the connection event:

```python
from sqlalchemy import event

@event.listens_for(engine, "connect")
def on_connect(dbapi_conn, _):
    dbapi_conn.executescript(PREAMBLE)
```

## Go

### Driver pick

| Driver | CGo? | Speed | Notes |
|---|---|---|---|
| **`modernc.org/sqlite`** | No | ~10% slower | Pure Go, easy cross-compile; recommended default |
| **`mattn/go-sqlite3`** | Yes | Fastest | Most features, all extension hooks |
| **`zombiezen.com/go/sqlite`** | Yes | Fast | Low-level, ergonomic for hot paths |
| **`crawshaw.io/sqlite`** | Yes | Fast | Predecessor of zombiezen; still maintained |

For 90% of projects, `modernc.org/sqlite` is the right pick:
zero CGo, builds in containers without a C toolchain.

### DSN options

```go
dsn := "file:app.db?" +
    "_pragma=journal_mode(WAL)&" +
    "_pragma=busy_timeout(5000)&" +
    "_pragma=foreign_keys(ON)&" +
    "_pragma=synchronous(NORMAL)"
db, _ := sql.Open("sqlite", dsn)

db.SetMaxOpenConns(1)            // serialize writes
db.SetConnMaxLifetime(0)         // SQLite connections are cheap to keep
```

Open a **second** `*sql.DB` with `?mode=ro` for the reader pool:

```go
ro, _ := sql.Open("sqlite", roDSN)
ro.SetMaxOpenConns(runtime.NumCPU())
```

### sqlc + SQLite

`sqlc` supports SQLite as a generation target. Pair with `goose`
for migrations. See the sibling `go-sql` skill — most of its
guidance applies directly; just swap engine and the rowid alias
syntax.

## Rust

```toml
# Cargo.toml
[dependencies]
rusqlite = { version = "0.31", features = ["bundled", "backup", "blob"] }
# or
sqlx     = { version = "0.8",  features = ["sqlite", "runtime-tokio-rustls"] }
```

- **`rusqlite`** — synchronous, lowest overhead. Use for CLI,
  embedded, single-threaded servers.
- **`sqlx`** — async, runtime-checked or **compile-time-checked**
  queries via `query!` macro (requires a dev DB).
- **`diesel`** — ORM with strong type-level guarantees.
- **`bundled` feature** pins a known-good SQLite version into your
  binary — recommended for reproducible builds.
- **Extension loading** — `rusqlite` needs the `load_extension`
  feature flag; `sqlx` exposes `SqliteConnectOptions::extensions()`.

## iOS / Swift

**[GRDB.swift](https://github.com/groue/GRDB.swift)** is the
modern choice:

```swift
let config = Configuration()
let dbPool = try DatabasePool(path: "/.../app.db", configuration: config)

try dbPool.write { db in
    try Post.fetchAll(db, sql: "SELECT * FROM posts WHERE id = ?", arguments: [id])
}
```

- Records, observation (`ValueObservation`), migrations, FTS5,
  SQLCipher, type-safe query DSL.
- `DatabasePool` implements the one-writer-many-readers pattern.
- Cleaner concurrency than raw `SQLite.swift`.

**Core Data** sits on SQLite but adds opaque overhead and a
strict object-graph model. Use GRDB unless you've already
committed to Core Data semantics.

### iOS data protection class

Mobile-specific landmine. Set the right `NSFileProtection` class
on **all three** files: `.db`, `.db-wal`, `.db-shm`. The default
(`NSFileProtectionComplete`) makes the DB **unreadable when the
device is locked** — which silently breaks background tasks.

```swift
try FileManager.default.setAttributes(
    [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
    ofItemAtPath: dbPath
)
```

`completeUntilFirstUserAuthentication` is the practical default
for most apps. Set it before opening the DB.

### iCloud / Files app

Do **not** put a SQLite DB inside an iCloud-synced directory.
Apple's syncing is file-level and can corrupt the WAL state.
Keep the DB in Application Support; use CloudKit (record-level)
or a server-mediated sync.

## Android / Kotlin

### Room (Jetpack)

```kotlin
@Database(entities = [User::class], version = 2)
abstract class AppDatabase : RoomDatabase() {
    abstract fun userDao(): UserDao
}
```

Compile-time SQL checking via `@Query("SELECT …")`. Migrations
written as `Migration(from, to) { db -> db.execSQL(...) }`. KMP
support since Room 2.7+.

Configure WAL via:

```kotlin
Room.databaseBuilder(ctx, AppDatabase::class.java, "app.db")
    .setJournalMode(JournalMode.WRITE_AHEAD_LOGGING)
    .build()
```

### SQLDelight

```sql
-- src/commonMain/sqldelight/com/app/posts.sq
selectAllPosts:
SELECT * FROM posts ORDER BY created_at DESC LIMIT :limit;
```

Generates type-safe Kotlin from `.sq` files. Excellent for
Kotlin Multiplatform (one schema, iOS + Android + JVM clients).

## React Native

| Lib | Engine | Notes |
|---|---|---|
| **`expo-sqlite`** | Bridged | Default in Expo; current API is async/JSI in recent SDKs |
| **`op-sqlite`** | JSI | Fastest; synchronous and async; FTS5 + sqlite-vec opt-in |
| `react-native-sqlite-storage` | Bridged (legacy) | Avoid for new code |

`op-sqlite` is the perf-oriented choice for apps that do heavy
local-DB work (offline-first, sync clients). Configure
`enableFTS5: true` and `enableSqliteVec: true` at install
to bundle the extensions.

## Encryption — SQLCipher

[SQLCipher](https://www.zetetic.net/sqlcipher/) provides
transparent AES-256 page encryption. Drop-in across all
platforms.

```sql
PRAGMA key = 'long-random-passphrase';
PRAGMA cipher_compatibility = 4;          -- v4 page format (current)
PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;
PRAGMA cipher_use_hmac = ON;
```

Costs: ~5–15% on read-heavy workloads, more on write-heavy. Key
derivation (PBKDF2) is slow by design — set the key once per
connection and cache it.

Drivers with SQLCipher support:

- iOS: GRDB + `SQLCipher` pod.
- Android: SQLCipher for Android.
- Node: `@journeyapps/sqlcipher`.
- Python: `pysqlcipher3`.
- Rust: `rusqlite` with `bundled-sqlcipher` feature.

Don't store the passphrase in plain text on disk. iOS Keychain,
Android Keystore, OS-keyring on desktop.

## CLI / embedded distribution

### Shipping a single binary

- **Go**: pure-Go `modernc.org/sqlite` → one static binary, no
  libsqlite3 dep.
- **Rust**: `rusqlite`/`sqlx` with `bundled` feature → linked in.
- **Bun**: `bun build --compile` → standalone executable with
  `bun:sqlite` built-in.
- **Deno**: `deno compile` → same idea.

### `:memory:` for tests

```python
conn = sqlite3.connect(":memory:")
# or
conn = sqlite3.connect("file::memory:?cache=shared", uri=True)
```

Run the same migrations; tests fly. The `cache=shared` URI lets
multiple connections in one process see the same in-memory DB.

### Copy-on-open

Bundle a seed DB; on first launch, copy it to the writable app
data directory and run migrations:

```swift
if !FileManager.default.fileExists(atPath: writableDB) {
    try FileManager.default.copyItem(atPath: seedDB, toPath: writableDB)
}
let pool = try DatabasePool(path: writableDB, configuration: config)
try migrator.migrate(pool)
```

This is the standard pattern for shipping reference data with
an app (offline-first dictionaries, catalogs, etc.).
