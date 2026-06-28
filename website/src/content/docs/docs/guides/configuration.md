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
| `-auth.jwt.secret`       | _required when auth is on_  | HMAC secret used to sign access/refresh tokens.     |
| `-auth.access.ttl`       | `60m`                       | Access token TTL.                                   |
| `-auth.refresh.ttl`      | `720h`                      | Refresh token TTL.                                  |
| `-metrics.route`         | `/metrics`                  | Prometheus-style metrics endpoint.                  |
| `-health.route`          | `/health`                   | Liveness/readiness endpoint.                        |

## Storage backends

PlainQ ships with two storage backends behind the same `Storage` interface.

### SQLite (default)

Small, fast, and the right choice for local development and single-node
deployments. It pairs naturally with [Litestream](https://litestream.io) for
cheap, continuous replication to object storage.

```shell
./plainq serve -storage.path=/data/plainq.db \
  -auth.jwt.secret="$(openssl rand -hex 32)"
```

### PostgreSQL

Use Postgres when you want a shared backend across replicas.

```shell
./plainq serve -storage.driver=postgres \
  -storage.postgres.dsn="postgres://user:pass@host:5432/plainq?sslmode=require" \
  -auth.jwt.secret="$(openssl rand -hex 32)"
```

## Listeners

PlainQ exposes two listeners:

- **gRPC** (`-grpc.addr`, default `:8080`) — all queue operations.
- **HTTP** (`-http.addr`, default `:8081`) — the Houston admin UI, plus the
  `/health` and `/metrics` endpoints.

## Authentication

The JWT secret powers Houston's login/onboarding and the account subsystem. See
the project's `AUTH.md` and the authentication & RBAC docs in the repository for
the full story, including OAuth/OIDC provider setup.

:::caution
Treat both the gRPC (`:8080`) and HTTP (`:8081`) ports as privileged and keep
them on a trusted network. See the
[Deployment guide](/docs/guides/deployment/#network-exposure).
:::
