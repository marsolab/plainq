# Configuration

All server configuration is set via flags on the `plainq serve` subcommand. This
guide groups the flags by concern and explains the ones that matter. For a flat
lookup table see the [Configuration reference](../reference/configuration.md).

```shell
./plainq serve [flags]
./plainq serve -h    # the authoritative, always-current flag list
```

> The compiled binary's `-h` output is the source of truth. This guide documents
> the flags as of writing; if they ever disagree, trust `-h`.

## Storage

| Flag                       | Default       | Purpose                                                       |
| -------------------------- | ------------- | ------------------------------------------------------------- |
| `--storage.driver`         | `sqlite`      | Backend: `sqlite` or `postgres`.                              |
| `--storage.path`           | `./plainq.db` | SQLite database file path.                                    |
| `--storage.postgres.dsn`   | _(empty)_     | PostgreSQL connection string. **Required** when driver is `postgres`. |
| `--storage.journal-mode`   | _(driver default)_ | SQLite journal mode (e.g. `wal`).                       |
| `--storage.access-mode`    | _(driver default)_ | SQLite access mode.                                     |
| `--storage.gc.timeout`     | `0`           | Interval for the eviction GC sweep. `0` uses the built-in default (~30m). |
| `--storage.log.enable`     | `false`       | Log storage-engine activity.                                 |

For SQLite in production, enabling **WAL** journal mode improves concurrency:

```shell
./plainq serve --storage.journal-mode=wal ...
```

PostgreSQL example:

```shell
./plainq serve \
  --storage.driver=postgres \
  --storage.postgres.dsn='postgres://user:pass@db:5432/plainq?sslmode=require' \
  --auth.jwt.secret="$JWT_SECRET"
```

See [Deployment](deployment.md) for choosing a backend.

## Listeners

| Flag                          | Default | Purpose                                              |
| ----------------------------- | ------- | ---------------------------------------------------- |
| `--grpc.addr`                 | `:8080` | gRPC listener (queue API, used by the CLI).          |
| `--http.addr`                 | `:8081` | HTTP listener (Houston UI, REST, health, metrics).   |
| `--http.read-timeout`         | `0`     | HTTP read timeout (`0` = no timeout).                |
| `--http.read-header-timeout`  | `0`     | HTTP read-header timeout.                            |
| `--http.write-timeout`        | `0`     | HTTP write timeout.                                  |
| `--http.idle-timeout`         | `0`     | HTTP idle (keep-alive) timeout.                      |

For internet-facing HTTP, set sensible timeouts (a proxy in front is still
recommended):

```shell
./plainq serve \
  --http.read-header-timeout=5s \
  --http.read-timeout=30s \
  --http.write-timeout=30s \
  --http.idle-timeout=120s ...
```

## Authentication

| Flag                                | Default  | Purpose                                                      |
| ----------------------------------- | -------- | ------------------------------------------------------------ |
| `--auth.enable`                     | `true`   | Master switch for JWT auth on the HTTP/Houston surface.      |
| `--auth.jwt.secret`                 | _(empty)_| HMAC secret signing access/refresh tokens. **Required** to issue sessions. |
| `--auth.access.ttl`                 | `60m`    | Access-token lifetime.                                       |
| `--auth.refresh.ttl`                | `720h`   | Refresh-token lifetime (30 days).                            |
| `--auth.registration.enable`        | `true`   | Allow new user self-registration.                            |
| `--auth.email.verification.enable`  | `true`   | Require email verification.                                  |

> **`--auth.jwt.secret` is required even with auth enabled** — the server needs
> it to issue and verify sessions, and `serve` will fail fast without it.
> Generate one with `openssl rand -hex 32` and supply it via your secret manager
> or an environment variable; don't hardcode it.

See [Authentication & RBAC](../authentication-rbac.md) for the full model.

## OAuth & multi-tenancy

PlainQ can delegate identity to external OAuth/OIDC providers and layer on
organization/team multi-tenancy. These are configured through the OAuth and
organization settings (provider, client ID/secret, JWKS URL, claim names, and
multi-tenancy toggles). Because the surface is broad and provider-specific, it
has its own guide:

→ [OAuth, organizations & teams](../oauth-organizations-teams.md)

## Observability

| Flag                  | Default     | Purpose                                                  |
| --------------------- | ----------- | -------------------------------------------------------- |
| `--health`            | `true`      | Enable the health endpoint.                              |
| `--health.route`      | `/health`   | Health endpoint path.                                    |
| `--metrics`           | `true`      | Enable the Prometheus metrics endpoint.                  |
| `--metrics.route`     | `/metrics`  | Metrics endpoint path.                                   |
| `--telemetry.enable`  | `true`      | Enable the telemetry subsystem powering Houston's dashboards. |
| `--profiler`          | `false`     | Enable the profiler endpoint.                            |
| `--cors`              | `true`      | Enable CORS for Houston's API routes.                    |

Telemetry has finer-grained knobs (provider, retention, scrape/GC timeouts,
optional Prometheus base URL). See [Observability](observability.md) for the
details and what each metric means.

## Logging

| Flag                  | Default | Purpose                                              |
| --------------------- | ------- | ---------------------------------------------------- |
| `--log.enable`        | `true`  | Enable logging.                                      |
| `--log.level`         | `info`  | `debug`, `info`, `warning`, or `error`.              |
| `--log.access.enable` | `true`  | Enable access logging.                               |

```shell
./plainq serve --log.level=debug ...   # verbose, for troubleshooting
```

## A production-shaped command

```shell
./plainq serve \
  --storage.driver=postgres \
  --storage.postgres.dsn="$PLAINQ_DSN" \
  --grpc.addr=127.0.0.1:8080 \
  --http.addr=:8081 \
  --http.read-header-timeout=5s \
  --http.read-timeout=30s \
  --http.write-timeout=30s \
  --http.idle-timeout=120s \
  --auth.jwt.secret="$PLAINQ_JWT_SECRET" \
  --auth.access.ttl=15m \
  --log.level=info
```

Note `--grpc.addr=127.0.0.1:8080`: binding gRPC to loopback (or a private
interface) keeps the currently-unauthenticated queue API off the public network.

## Next steps

- [Deployment](deployment.md) — turning these flags into a running service.
- [Configuration reference](../reference/configuration.md) — the complete table.
- [Observability](observability.md) — health, metrics, and telemetry in depth.
</content>
