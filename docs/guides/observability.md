# Observability

PlainQ ships the operational basics in the box: a health endpoint, Prometheus
metrics, an internal telemetry store that powers Houston's dashboards, structured
logs, and an optional profiler.

## Health

A liveness/readiness endpoint is served on the HTTP listener:

| Property | Default        |
| -------- | -------------- |
| Route    | `/health`      |
| Flag     | `--health.route` (path), `--health` (enable) |

```shell
curl http://localhost:8081/health
```

Wire this to your orchestrator's probes:

```yaml
# Kubernetes
livenessProbe:
  httpGet: { path: /health, port: 8081 }
  initialDelaySeconds: 5
  periodSeconds: 10
readinessProbe:
  httpGet: { path: /health, port: 8081 }
  periodSeconds: 10
```

The health endpoint is intentionally unauthenticated so probes work without
credentials. Related flags: `--health.route.logs` and `--health.route.metrics`
toggle access logging and self-metrics for the endpoint itself (both off by
default to avoid probe noise).

## Prometheus metrics

A Prometheus-style metrics endpoint is served on the HTTP listener:

| Property | Default        |
| -------- | -------------- |
| Route    | `/metrics`     |
| Flag     | `--metrics.route` (path), `--metrics` (enable) |

```shell
curl http://localhost:8081/metrics
```

Scrape config:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: plainq
    metrics_path: /metrics
    static_configs:
      - targets: ["plainq.internal:8081"]
```

Like health, the endpoint exposes `--metrics.route.logs` and
`--metrics.route.metrics` toggles, off by default.

## Telemetry & Houston dashboards

Beyond the raw Prometheus endpoint, PlainQ runs an internal **telemetry
subsystem** that periodically collects queue and message metrics into a store,
which powers the charts and rate/in-flight views in the
[Houston](houston.md) admin UI.

| Flag                                      | Default   | Purpose                                              |
| ----------------------------------------- | --------- | ---------------------------------------------------- |
| `--telemetry.enable`                      | `true`    | Master switch for the telemetry subsystem.           |
| `--telemetry.provider`                    | `sqlite`  | Telemetry backend.                                   |
| `--telemetry.sqlite.collection.timeout`   | `10s`     | How often metrics are collected.                     |
| `--telemetry.sqlite.retention.period`     | `14 days` | How long collected metrics are kept.                 |
| `--telemetry.sqlite.gc.timeout`           | `10m`     | Telemetry GC sweep interval.                         |
| `--telemetry.prometheus.baseurl`          | _(empty)_ | Optional external Prometheus API base URL.           |
| `--telemetry.log.enable`                  | `false`   | Log telemetry-subsystem activity.                    |

With the SQLite provider, telemetry is stored in a sibling database next to your
main one (e.g. `plainq_telemetry.db`), created and migrated automatically on
startup. If telemetry fails to initialize, the server logs a warning and keeps
running with the metrics dashboard disabled — it never blocks the queue service.

> Telemetry metrics live separately from the Prometheus `/metrics` endpoint. Use
> `/metrics` for your external monitoring stack; the telemetry store is for
> Houston's built-in dashboards.

## Logs

PlainQ emits structured logs via `log/slog`.

| Flag                  | Default | Purpose                                          |
| --------------------- | ------- | ------------------------------------------------ |
| `--log.enable`        | `true`  | Enable logging.                                  |
| `--log.level`         | `info`  | `debug`, `info`, `warning`, `error`.             |
| `--log.access.enable` | `true`  | Enable HTTP access logging.                      |

```shell
./plainq serve --log.level=debug ...
```

Ship logs to your aggregator the usual way (stdout → collector). Drop to `debug`
when diagnosing; keep `info` in production.

## Profiler

For deep performance investigation, enable the Go profiler endpoint:

```shell
./plainq serve --profiler ...
```

It's **off by default**. Only enable it on a trusted network — profiling
endpoints can expose internal detail and shouldn't face the public internet.

## What to watch

| Signal                          | Why it matters                                                |
| ------------------------------- | ------------------------------------------------------------- |
| **In-flight message count**     | Rising and not falling ⇒ consumers stalled or too slow.       |
| **Receive vs. delete rate**     | Receives ≫ deletes ⇒ messages failing and redelivering.       |
| **Dead-letter queue depth**     | Anything > 0 ⇒ poison messages to investigate.                |
| **Queue backlog (visible msgs)**| Growing ⇒ producers outpacing consumers; scale out.           |
| **`/health` status**            | Failing ⇒ take the instance out of rotation.                  |

Dead-letter depth is the highest-signal alert: a non-empty DLQ almost always
means something needs a human.

## Next steps

- [Houston](houston.md) — the dashboards these metrics feed.
- [Queues & messages](queues-and-messages.md) — what in-flight and retries mean.
- [Deployment](deployment.md) — wiring probes and scrapers.
</content>
