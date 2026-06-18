# PlainQ

Truly Simple Queue Service. ☺️

PlainQ is a small, self-contained queue server written in Go. A single binary
gives you a gRPC API, a CLI, and a built-in admin web UI (Houston), backed by
either embedded SQLite for local and small deployments or PostgreSQL when you
need to scale out.

## Highlights

- **One binary, no broker fleet.** Run `./plainq serve` and you have a queue.
- **gRPC API + CLI.** Same surface, scripted or interactive. Schema is
  published to the [Buf Schema Registry](https://buf.build/plainq/schema) so
  you can generate clients in any supported language.
- **Houston admin UI.** An Astro + React dashboard for queues, accounts,
  RBAC, and metrics — served straight from the same binary.
- **Pick your storage.** Embedded SQLite (default) for local and Litestream-friendly
  deployments, or PostgreSQL when you want a shared backend.
- **Auth that's actually built in.** JWT sessions, refresh tokens, RBAC, and
  OAuth/OIDC hooks (Kinde, Auth0, Okta, WorkOS) ship with the server — not as
  an afterthought.
- **Operational basics included.** `/health` and `/metrics` endpoints,
  structured logs, and per-queue knobs for retention, visibility timeout,
  max-receive attempts, and dead-letter / drop eviction.

## Table of contents

- [Quick start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
  - [CLI](#cli)
  - [gRPC](#grpc)
  - [Houston (admin UI)](#houston-admin-ui)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Project layout](#project-layout)
- [Development](#development)
- [Community & contributing](#community--contributing)
- [License](#license)

## Quick start

From a fresh clone to a message round-trip in under a minute:

```shell
# Build Houston (embedded into the server binary), then build plainq itself.
# Requires Go 1.26+ and Bun.
make build

# Start the server (SQLite at ./plainq.db, gRPC on :8080, Houston on :8081).
./plainq serve --auth.jwt.secret="$(openssl rand -hex 32)"

# In another shell:
QID=$(./plainq create my-queue)
./plainq send "$QID" --message='hello, plainq'
./plainq receive "$QID"
```

Open <http://localhost:8081> for the Houston admin UI.

## Installation

### Build from source

Requirements:

- Go **1.26.1** or later
- Bun (for building Houston)

```shell
make build
```

`make houston` builds the admin UI into `internal/houston/ui/dist`, which the
server embeds at compile time. `make build` then produces a `./plainq` binary
at the repo root.

Prebuilt binaries and a Docker image aren't published yet — building from
source is the supported path today.

## Usage

### CLI

The `plainq` binary is both the server and the client. Every client command
talks gRPC and accepts `--grpc.addr` (default `localhost:8080`) and `--json`
for machine-readable output.

| Command                       | Description                                          |
| ----------------------------- | ---------------------------------------------------- |
| `plainq serve`                | Run the PlainQ server (gRPC + HTTP + Houston UI).    |
| `plainq version`              | Print the build version, commit, and build time.    |
| `plainq ctx`                  | Manage local client contexts.                        |
| `plainq list`                 | List queues.                                         |
| `plainq create <queue-name>`  | Create a queue. Supports `--retention-period`, `--visibility-timeout`, `--max-receive-attempts`, `--drop-policy` (`drop` or `dead-letter`), `--dead-letter-queue-id`. |
| `plainq describe <queue-id>`  | Describe a queue.                                    |
| `plainq purge <queue-id>`     | Delete all messages from a queue.                    |
| `plainq delete <queue-id>`    | Delete a queue (`--force` to skip safety checks).    |
| `plainq send <queue-id>`      | Send a message (`--message=...`).                    |
| `plainq receive <queue-id>`   | Receive messages (`--batch=N`, up to 10).            |

Run any command with `-h` for its full flag list.

### gRPC

The wire API is defined in [`schema/v1/schema.proto`](schema/v1/schema.proto)
and published to the Buf Registry at
[`buf.build/plainq/schema`](https://buf.build/plainq/schema). The service
exposes eight RPCs:

- `ListQueues` — paginated queue list with optional prefix and sort.
- `DescribeQueue` — fetch queue settings by ID or name.
- `CreateQueue` — create a queue with retention, visibility, eviction policy.
- `PurgeQueue` — remove every message from a queue.
- `DeleteQueue` — drop the queue itself.
- `Send` — enqueue one or more messages.
- `Receive` — dequeue a batch (1–10) with visibility-timeout semantics.
- `Delete` — acknowledge and remove messages by ID.

Use `buf generate` (or your language's Buf workflow) to produce a client SDK
directly from the registry.

### Houston (admin UI)

Houston is the bundled web dashboard — Astro + React + TypeScript, served by
the same binary on the HTTP listener (default `:8081`). It covers queue
browsing, account and RBAC management, OAuth provider setup, and metrics
visualization. After `./plainq serve`, point a browser at
<http://localhost:8081> and follow the onboarding flow to create the first
admin account.

## Configuration

Every flag below is set on the `serve` subcommand. The most useful ones:

| Flag                          | Default       | Purpose                                                            |
| ----------------------------- | ------------- | ------------------------------------------------------------------ |
| `--storage.driver`            | `sqlite`      | Storage backend: `sqlite` or `postgres`.                           |
| `--storage.path`              | `./plainq.db` | Path to the SQLite database file.                                  |
| `--storage.postgres.dsn`      | _required when `postgres`_ | PostgreSQL connection string.                          |
| `--grpc.addr`                 | `:8080`       | gRPC listener address.                                             |
| `--http.addr`                 | `:8081`       | HTTP listener address (Houston + metrics + health).                |
| `--auth.enable`               | `true`        | Toggle JWT auth.                                                   |
| `--auth.jwt.secret`           | _required when auth is on_ | HMAC secret used to sign access/refresh tokens.       |
| `--auth.access.ttl`           | `60m`         | Access token TTL.                                                  |
| `--auth.refresh.ttl`          | `720h`        | Refresh token TTL.                                                 |
| `--metrics.route`             | `/metrics`    | Prometheus-style metrics endpoint.                                 |
| `--health.route`              | `/health`     | Liveness/readiness endpoint.                                       |

Run `./plainq serve -h` for the complete list. For the full authentication
and RBAC story, see [`AUTH.md`](AUTH.md) and
[`docs/authentication-rbac.md`](docs/authentication-rbac.md).

## Architecture

PlainQ is intentionally boring on the inside:

- `internal/server` — HTTP + gRPC server wiring, middleware, and interceptors.
- `internal/server/service/{queue,account,rbac,oauth,onboarding}` — domain
  services. Each one owns its business logic and exposes a `Storage`
  interface implemented by both SQLite (`litestore`) and PostgreSQL
  (`pgstore`) backends. SQL is generated with [sqlc](https://sqlc.dev).
- `internal/houston/ui` — the Astro + React admin dashboard, built into the
  server binary's assets.
- `schema/v1` — the protobuf API, mirrored to the Buf Schema Registry.

The SQLite backend is the default because it's small, fast, and pairs
naturally with [Litestream](https://litestream.io) for cheap, continuous
replication to object storage. PostgreSQL is there when you want a shared
backend across replicas.

## Project layout

```
.
├── cmd/                    # CLI entry points (server + client commands)
├── docs/                   # Architecture and auth documentation
├── internal/
│   ├── client/             # gRPC client library
│   ├── houston/            # Admin dashboard (Astro + React)
│   ├── server/             # HTTP/gRPC server
│   │   ├── middleware/
│   │   ├── interceptor/
│   │   ├── schema/         # Generated protobuf code
│   │   ├── service/        # queue, account, rbac, oauth, onboarding
│   │   └── storage/
│   ├── shared/
│   └── sqlc/               # sqlc config + generated query code
└── schema/                 # Protobuf source published to Buf
```

## Development

```shell
make deps           # go mod tidy && go mod download
make schema         # regenerate gRPC code from buf.build/plainq/schema
make sqlc-generate  # regenerate SQL access code
make houston        # build the Houston UI
make build          # full build → ./plainq
make test           # go test -v -race ./...
make test-cover     # with coverage profile
```

You'll need Go 1.26.1, [`buf`](https://buf.build/docs/installation),
[`sqlc`](https://docs.sqlc.dev/en/latest/overview/install.html), and Bun on
your `PATH`.

## Community & contributing

Hi, and welcome. PlainQ is built in the open and contributions of every size
are appreciated — bug reports, doc fixes, design discussions, and code.

- **Found a bug or have an idea?** Open a [GitHub issue](https://github.com/marsolab/plainq/issues).
- **Want to chat about design or ask a question?** Use
  [GitHub Discussions](https://github.com/marsolab/plainq/discussions).
- **Ready to send a patch?** Read [`CONTRIBUTTING.md`](CONTRIBUTTING.md) for
  the dev setup and PR process. _(Yes, the filename has a typo — a fix is
  coming.)_ The Code of Conduct lives at the top of that file: be kind, be
  patient, and assume good intent.

Thanks for being here. ☺️

## License

PlainQ is licensed under the Apache License 2.0. A `LICENSE` file at the repo
root will follow shortly.
