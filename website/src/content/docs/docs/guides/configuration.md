---
title: Configuration
description: Tune PlainQ's storage backend, listeners, and authentication on the serve subcommand.
sidebar:
  order: 2
---

Every flag below is set on the `serve` subcommand. Run `./plainq serve -h` for
the complete list.

## Most useful flags

| Flag                     | Default                     | Purpose                                             |
| ------------------------ | --------------------------- | --------------------------------------------------- |
| `-storage.driver`        | `sqlite`                    | Storage backend: `sqlite` or `postgres`.            |
| `-storage.path`          | `./plainq.db`               | Path to the SQLite database file.                   |
| `-storage.postgres.dsn`  | _required when `postgres`_  | PostgreSQL connection string.                       |
| `-grpc.addr`             | `:8080`                     | gRPC listener address.                              |
| `-http.addr`             | `:8081`                     | HTTP listener address (Houston + metrics + health). |
| `-auth.enable`           | `true`                      | Toggle JWT auth.                                    |
| `-auth.jwt.secret`       | _always required by serve_  | HMAC secret used to sign access/refresh tokens.     |
| `-auth.bootstrap.secret` | _required when auth is on_  | Shared secret for the first remote administrator.  |
| `-auth.access.ttl`       | `60m`                       | Access token TTL.                                   |
| `-auth.refresh.ttl`      | `720h`                      | Refresh token TTL.                                  |
| `-metrics.route`         | `/metrics`                  | Prometheus-style metrics endpoint.                  |
| `-health.route`          | `/health`                   | Storage and cluster readiness endpoint.             |
| `-health.liveness.route` | `/live`                     | Process liveness endpoint.                          |

## Storage backends

PlainQ ships with two storage backends behind the same `Storage` interface.

### SQLite (default)

Small, fast, and the right choice for local development and single-node
deployments. It pairs naturally with [Litestream](https://litestream.io) for
cheap, continuous replication to object storage.

```shell
./plainq serve -storage.path=/data/plainq.db \
  -auth.jwt.secret="$(openssl rand -hex 32)" \
  -auth.bootstrap.secret="$(openssl rand -hex 32)"
```

### PostgreSQL

Use Postgres when you want a shared backend across replicas.

```shell
./plainq serve -storage.driver=postgres \
  -storage.postgres.dsn="postgres://user:pass@host:5432/plainq?sslmode=require" \
  -auth.jwt.secret="$(openssl rand -hex 32)" \
  -auth.bootstrap.secret="$(openssl rand -hex 32)"
```

## Listeners

PlainQ exposes two listeners:

- **gRPC** (`-grpc.addr`, default `:8080`) — queue and stable topic operations.
- **HTTP** (`-http.addr`, default `:8081`) — the Houston admin UI, plus the
  `/health` and `/metrics` endpoints.

## Authentication

The JWT secret powers Houston sessions and the shared HTTP/gRPC authentication
path. Authenticated queue/topic operations are tenant-scoped and
resource-authorized. Legacy `schema.v1` gRPC calls may omit a token while
`-grpc.protect-legacy=false`, but that compatibility identity is restricted to
migrated or legacy-created rows in the fixed legacy tenant. The bundled CLI/TUI
does not yet send bearer or TLS credentials, so keep compatibility enabled for
those clients. See the project's authentication & RBAC docs for the full account
story.

:::caution
Built-in gRPC TLS is activated with agent APIs. A legacy-only server needs a
TLS-terminating mesh/proxy; keep gRPC private while anonymous compatibility is
enabled. See the
[Deployment guide](/docs/guides/deployment/#network-exposure).
:::

## Telemetry

| Flag                                      | Default   | Purpose                                    |
| ----------------------------------------- | --------- | ------------------------------------------ |
| `--telemetry.enable`                      | `true`    | Enable typed telemetry and Houston history. |
| `--telemetry.provider`                    | `sqlite`  | Telemetry storage backend.                 |
| `--telemetry.log.enable`                  | `false`   | Log telemetry activity.                    |
| `--telemetry.sqlite.collection.timeout`   | `10s`     | Raw collection interval.                   |
| `--telemetry.sqlite.gc.timeout`           | `10m`     | Retention-sweep interval.                  |
| `--telemetry.sqlite.retention.period`     | `336h`    | Maximum history (14 days).                 |
| `--telemetry.prometheus.baseurl`          | _(empty)_ | Optional Prometheus API base URL.          |

The historical `collection.timeout` name means collection interval. It must be
at least 1ms, use whole milliseconds, and divide one minute evenly. GC must be
positive and enabled retention must be at least 24h. An interval change catches
up completed rollups, resets raw history, and appears as `notRecorded` instead
of mixing grids.
