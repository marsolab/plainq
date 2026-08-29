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
  --auth.jwt.secret="$JWT_SECRET" \
  --auth.bootstrap.secret="$BOOTSTRAP_SECRET"
```

See [Deployment](deployment.md) for choosing a backend.

## Listeners

| Flag                          | Default | Purpose                                              |
| ----------------------------- | ------- | ---------------------------------------------------- |
| `--grpc.addr`                 | `:8080` | gRPC queue/topic API, used by the CLI.               |
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
| `--auth.enable`                     | `true`   | Master switch for the JWT auth subsystem (account APIs, Houston login). |
| `--auth.jwt.secret`                 | _(empty)_| HMAC secret signing access/refresh tokens. **Always required by `serve`.** |
| `--auth.bootstrap.secret`           | _(empty)_| Shared secret for creating the first remote administrator. **Required** with auth. |
| `--auth.access.ttl`                 | `60m`    | Access-token lifetime.                                       |
| `--auth.refresh.ttl`                | `720h`   | Refresh-token lifetime (30 days).                            |
| `--auth.registration.enable`        | `true`   | Allow new user self-registration.                            |
| `--auth.email.verification.enable`  | `false`  | Reserved; enabling it fails closed until a verifier/delivery backend is configured. |

> **The JWT secret is always required by the current `serve` construction, even
> when `--auth.enable=false`; the bootstrap secret is additionally required when
> authentication is enabled.** The JWT secret signs sessions; the separate
> bootstrap secret authorizes creation of the first remote administrator. Each
> must contain at least 32 bytes. Generate independent values with
> `openssl rand -hex 32`, inject them from a secret manager, and never hardcode
> them.

See [Authentication & RBAC](../authentication-rbac.md) for the full model.

> **Boundary:** when authentication is enabled, HTTP queue/topic and admin
> routes require bearer sessions. Authenticated HTTP and gRPC queue/topic
> operations are tenant-scoped and pass the shared resource-policy checks.
> Legacy `schema.v1` gRPC calls may omit a token only while
> `--grpc.protect-legacy=false`; that compatibility identity is restricted to
> migrated or legacy-created rows in the fixed legacy tenant. Set the flag to
> `true` after old clients have credentials. The bundled CLI/TUI currently sends
> neither bearer metadata nor TLS credentials, so it requires compatibility
> mode; use a generated/external authenticated client before enabling legacy
> protection. Keep transport TLS and network policy in place; see
> [Deployment → network exposure](deployment.md#network-exposure).

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
| `--health.route`      | `/health`   | Storage and cluster readiness endpoint.                  |
| `--health.liveness.route` | `/live` | Process liveness endpoint.                               |
| `--metrics`           | `true`      | Enable the Prometheus metrics endpoint.                  |
| `--metrics.route`     | `/metrics`  | Metrics endpoint path.                                   |
| `--telemetry.enable`  | `true`      | Enable the telemetry subsystem powering Houston's dashboards. |
| `--profiler`          | `false`     | Enable the profiler endpoint.                            |
| `--cors`              | `true`      | Enable CORS for Houston's API routes.                    |

Telemetry uses these stable defaults:

| Flag                                      | Default   | Purpose                                      |
| ----------------------------------------- | --------- | -------------------------------------------- |
| `--telemetry.enable`                      | `true`    | Enable typed telemetry and Houston history.  |
| `--telemetry.provider`                    | `sqlite`  | Telemetry storage backend.                   |
| `--telemetry.log.enable`                  | `false`   | Log telemetry subsystem activity.            |
| `--telemetry.sqlite.collection.timeout`   | `10s`     | Raw collection interval.                     |
| `--telemetry.sqlite.gc.timeout`           | `10m`     | Ordered retention-sweep interval.            |
| `--telemetry.sqlite.retention.period`     | `336h`    | Maximum history retention (14 days).         |
| `--telemetry.prometheus.baseurl`          | _(empty)_ | Optional external Prometheus API base URL.   |

The legacy name `collection.timeout` means collection **interval**. When
telemetry is enabled it must be at least 1ms, exactly representable in whole
milliseconds, and divide one minute without a remainder. The GC interval must
be positive and retention must be at least 24 hours. Changing the collection
interval first catches up completed rollups and then resets retained raw data;
the transition is shown as `notRecorded`, never as a mixed raw grid.

See [Observability](observability.md) for the stored resolutions, retention
behavior, Prometheus families, and Houston graphs.

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
  --auth.bootstrap.secret="$PLAINQ_BOOTSTRAP_SECRET" \
  --auth.access.ttl=15m \
  --log.level=info
```

Note `--grpc.addr=127.0.0.1:8080`: binding gRPC to loopback (or a private
interface) limits exposure while legacy anonymous compatibility remains
enabled. Set `--grpc.protect-legacy=true` only after moving the bundled CLI/TUI
to a client that sends a bearer credential.

## Next steps

- [Deployment](deployment.md) — turning these flags into a running service.
- [Configuration reference](../reference/configuration.md) — the complete table.
- [Observability](observability.md) — health, metrics, and telemetry in depth.
</content>
