---
title: Configuration reference
description: Every flag accepted by the plainq serve subcommand.
sidebar:
  order: 2
---

All configuration is passed to the `serve` subcommand. Run `./plainq serve -h`
for the authoritative, build-specific list. The commonly used flags are below.

## Storage

| Flag                    | Default                    | Purpose                                  |
| ----------------------- | -------------------------- | ---------------------------------------- |
| `-storage.driver`       | `sqlite`                   | Storage backend: `sqlite` or `postgres`. |
| `-storage.path`         | `./plainq.db`              | Path to the SQLite database file.        |
| `-storage.postgres.dsn` | _required when `postgres`_ | PostgreSQL connection string.            |

## Listeners

| Flag         | Default | Purpose                                             |
| ------------ | ------- | --------------------------------------------------- |
| `-grpc.addr` | `:8080` | gRPC queue/topic listener address.                  |
| `-http.addr` | `:8081` | HTTP listener address (Houston + metrics + health). |

## Authentication

| Flag                 | Default                    | Purpose                                         |
| -------------------- | -------------------------- | ----------------------------------------------- |
| `-auth.enable`       | `true`                     | Toggle HTTP/Houston JWT sessions.               |
| `-auth.jwt.secret`   | _always required by serve_ | HMAC secret used to sign access/refresh tokens. |
| `-auth.bootstrap.secret` | _required when auth is on_ | Shared secret for the first remote administrator. |
| `-auth.access.ttl`   | `60m`                      | Access token TTL.                               |
| `-auth.refresh.ttl`  | `720h`                     | Refresh token TTL.                              |

HTTP queue/topic and admin routes use sessions when enabled. Authenticated HTTP
and gRPC queue/topic operations are tenant-scoped and resource-authorized.
Legacy `schema.v1` gRPC calls may omit a token while
`-grpc.protect-legacy=false`; that compatibility identity can reach only
migrated or legacy-created rows in the fixed legacy tenant. The bundled CLI/TUI
requires this compatibility mode because it does not yet send bearer/TLS
credentials.

## Observability

| Flag                                      | Default   | Purpose                                      |
| ----------------------------------------- | --------- | -------------------------------------------- |
| `-metrics.route`                          | `/metrics` | Prometheus text exposition endpoint.        |
| `-health.route`                           | `/health` | Storage and cluster readiness endpoint.      |
| `-health.liveness.route`                  | `/live`   | Process liveness endpoint.                   |
| `--telemetry.enable`                      | `true`    | Enable typed telemetry and Houston history.  |
| `--telemetry.provider`                    | `sqlite`  | Telemetry storage backend.                   |
| `--telemetry.log.enable`                  | `false`   | Log telemetry activity.                      |
| `--telemetry.sqlite.collection.timeout`   | `10s`     | Raw collection interval.                     |
| `--telemetry.sqlite.gc.timeout`           | `10m`     | Retention-sweep interval.                    |
| `--telemetry.sqlite.retention.period`     | `336h`    | Maximum history (14 days).                   |
| `--telemetry.prometheus.baseurl`          | _(empty)_ | Optional Prometheus API base URL.            |

`collection.timeout` is the legacy name for collection interval. It must be a
whole-millisecond duration of at least 1ms and divide one minute evenly. GC must
be positive and enabled retention at least 24h. Changing it catches up rollups,
resets retained raw history, and produces an explicit `notRecorded` gap.

## Example

```shell
./plainq serve \
  -storage.driver=postgres \
  -storage.postgres.dsn="postgres://user:pass@host:5432/plainq?sslmode=require" \
  -grpc.addr=:8080 \
  -http.addr=:8081 \
  -auth.jwt.secret="$(openssl rand -hex 32)" \
  -auth.bootstrap.secret="$(openssl rand -hex 32)" \
  -auth.access.ttl=60m \
  -auth.refresh.ttl=720h
```
