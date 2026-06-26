# Configuration reference

The complete `plainq serve` flag set, grouped by concern, with defaults. For
guidance on which to set and why, see the
[Configuration guide](../guides/configuration.md). The binary's
`./plainq serve -h` output is always authoritative if anything here drifts.

## Storage

| Flag                       | Default       | Purpose                                                       |
| -------------------------- | ------------- | ------------------------------------------------------------- |
| `--storage.driver`         | `sqlite`      | `sqlite` or `postgres`.                                       |
| `--storage.path`           | `./plainq.db` | SQLite database file path.                                    |
| `--storage.postgres.dsn`   | _(empty)_     | PostgreSQL DSN. Required when driver is `postgres`.           |
| `--storage.journal-mode`   | _(driver default)_ | SQLite journal mode (e.g. `wal`).                       |
| `--storage.access-mode`    | _(driver default)_ | SQLite access mode.                                     |
| `--storage.gc.timeout`     | `0`           | Eviction GC sweep interval. `0` → built-in default (~30m).   |
| `--storage.log.enable`     | `false`       | Log storage-engine activity.                                 |

## Listeners

| Flag                          | Default | Purpose                                              |
| ----------------------------- | ------- | ---------------------------------------------------- |
| `--grpc.addr`                 | `:8080` | gRPC listener (queue API).                           |
| `--http.addr`                 | `:8081` | HTTP listener (Houston, REST, health, metrics).      |
| `--http.read-timeout`         | `0`     | HTTP read timeout (`0` = none).                      |
| `--http.read-header-timeout`  | `0`     | HTTP read-header timeout.                            |
| `--http.write-timeout`        | `0`     | HTTP write timeout.                                  |
| `--http.idle-timeout`         | `0`     | HTTP idle/keep-alive timeout.                        |

## Authentication

| Flag                                | Default   | Purpose                                                |
| ----------------------------------- | --------- | ------------------------------------------------------ |
| `--auth.enable`                     | `true`    | Enable JWT auth on the HTTP/Houston surface.           |
| `--auth.jwt.secret`                 | _(empty)_ | HMAC secret for tokens. Required to issue sessions.    |
| `--auth.access.ttl`                 | `60m`     | Access-token lifetime.                                 |
| `--auth.refresh.ttl`                | `720h`    | Refresh-token lifetime (30 days).                      |
| `--auth.registration.enable`        | `true`    | Allow user self-registration.                          |
| `--auth.email.verification.enable`  | `true`    | Require email verification.                            |

## Logging

| Flag                  | Default | Purpose                                  |
| --------------------- | ------- | ---------------------------------------- |
| `--log.enable`        | `true`  | Enable logging.                          |
| `--log.access.enable` | `true`  | Enable access logging.                   |
| `--log.level`         | `info`  | `debug`, `info`, `warning`, `error`.     |

## Telemetry

| Flag                                      | Default   | Purpose                                          |
| ----------------------------------------- | --------- | ------------------------------------------------ |
| `--telemetry.enable`                      | `true`    | Enable the telemetry subsystem.                  |
| `--telemetry.provider`                    | `sqlite`  | Telemetry backend.                               |
| `--telemetry.log.enable`                  | `false`   | Log telemetry activity.                          |
| `--telemetry.sqlite.collection.timeout`   | `10s`     | Metric collection interval.                      |
| `--telemetry.sqlite.gc.timeout`           | `10m`     | Telemetry GC sweep interval.                     |
| `--telemetry.sqlite.retention.period`     | `336h`    | Telemetry retention (14 days).                   |
| `--telemetry.prometheus.baseurl`          | _(empty)_ | External Prometheus API base URL.                |

## Health

| Flag                     | Default   | Purpose                                  |
| ------------------------ | --------- | ---------------------------------------- |
| `--health`               | `true`    | Enable the health endpoint.              |
| `--health.route`         | `/health` | Health endpoint path.                    |
| `--health.route.logs`    | `false`   | Access logs for the health endpoint.     |
| `--health.route.metrics` | `false`   | Self-metrics for the health endpoint.    |
| `--health.reporter`      | _(empty)_ | Health reporter format.                  |

## Metrics

| Flag                      | Default    | Purpose                                  |
| ------------------------- | ---------- | ---------------------------------------- |
| `--metrics`               | `true`     | Enable the Prometheus metrics endpoint.  |
| `--metrics.route`         | `/metrics` | Metrics endpoint path.                   |
| `--metrics.route.logs`    | `false`    | Access logs for the metrics endpoint.    |
| `--metrics.route.metrics` | `false`    | Self-metrics for the metrics endpoint.   |

## Other

| Flag          | Default | Purpose                                       |
| ------------- | ------- | --------------------------------------------- |
| `--cors`      | `true`  | Enable CORS for Houston API routes.           |
| `--profiler`  | `false` | Enable the profiler endpoint.                 |

## OAuth & multi-tenancy

OAuth and organization/team settings are configured separately and are
provider-specific. See
[OAuth, organizations & teams](../oauth-organizations-teams.md) for the full
list of settings (provider, client credentials, JWKS URL, claim names, sync, and
multi-tenancy toggles).
</content>
