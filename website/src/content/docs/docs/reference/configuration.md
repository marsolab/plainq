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
| `-grpc.addr` | `:8080` | gRPC listener address.                              |
| `-http.addr` | `:8081` | HTTP listener address (Houston + metrics + health). |

## Authentication

| Flag                 | Default                    | Purpose                                         |
| -------------------- | -------------------------- | ----------------------------------------------- |
| `-auth.enable`       | `true`                     | Toggle JWT auth.                                |
| `-auth.jwt.secret`   | _required when auth is on_ | HMAC secret used to sign access/refresh tokens. |
| `-auth.access.ttl`   | `60m`                      | Access token TTL.                               |
| `-auth.refresh.ttl`  | `720h`                     | Refresh token TTL.                              |

## Observability

| Flag              | Default    | Purpose                            |
| ----------------- | ---------- | ---------------------------------- |
| `-metrics.route`  | `/metrics` | Prometheus-style metrics endpoint. |
| `-health.route`   | `/health`  | Liveness/readiness endpoint.       |

## Example

```shell
./plainq serve \
  -storage.driver=postgres \
  -storage.postgres.dsn="postgres://user:pass@host:5432/plainq?sslmode=require" \
  -grpc.addr=:8080 \
  -http.addr=:8081 \
  -auth.jwt.secret="$(openssl rand -hex 32)" \
  -auth.access.ttl=60m \
  -auth.refresh.ttl=720h
```
