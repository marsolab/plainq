# Observability

PlainQ ships the operational basics in the box: health endpoints, Prometheus
metrics, an internal telemetry store that powers Houston's dashboards, structured
logs, and an optional profiler.

## Health

Separate liveness and readiness endpoints are served on the HTTP listener:

| Purpose | Default | Flag |
| --- | --- | --- |
| Process liveness | `/live` | `--health.liveness.route` |
| Storage and cluster readiness | `/health` | `--health.route` |
| Enable both endpoints | `true` | `--health` |

```shell
curl http://localhost:8081/live
curl http://localhost:8081/health
```

`/live` returns 200 while the process can answer HTTP. `/health` returns 503
when physical storage is unhealthy, a cluster has no write quorum, or the local
replica is quarantined after an unsafe state-machine outcome. Replica quarantine
survives process restart; recover it only with a verified snapshot restore or a
complete replica wipe and reseed. Do not create or delete the apply-guard files
individually.

Wire this to your orchestrator's probes:

```yaml
# Kubernetes
livenessProbe:
  httpGet: { path: /live, port: 8081 }
  initialDelaySeconds: 5
  periodSeconds: 10
readinessProbe:
  httpGet: { path: /health, port: 8081 }
  periodSeconds: 10
```

The health endpoints are intentionally unauthenticated so probes work without
credentials. Related flags: `--health.route.logs` and `--health.route.metrics`
toggle access logging and self-metrics for both endpoints (both off by default
to avoid probe noise).

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

Everything PlainQ exposes is namespaced `plainq_`, alongside the standard
`go_*` and `process_*` collectors. Latency and size distributions are real
Prometheus histograms with `le` buckets, so `histogram_quantile` works on them:

```promql
histogram_quantile(0.99, sum by (le, route) (rate(plainq_http_request_duration_seconds_bucket[5m])))
```

### The metric catalog

The exposition format carries `# TYPE` metadata and a name-only
`# HELP <family>` line. The pinned VictoriaMetrics writer does not include the
declaration's prose in that HELP line, so the full descriptions live in an API
endpoint generated from the same declarations the metrics themselves come
from:

```shell
curl -s localhost:8081/api/v1/metrics/catalog | jq '.[] | select(.name | startswith("plainq_cluster"))'
```

It lists every family the binary can expose — including ones with no series
yet, which is what you want when you are building a dashboard before the
first failure rather than after it.

### What is measured

### Queues and messages

| Metric | Type | Labels | Meaning |
| ------ | ---- | ------ | ------- |
| `plainq_batch_size` | histogram | `queue`, `operation` | Distribution of how many messages a single batched operation carried. |
| `plainq_empty_receives_total` | counter | `queue` | Receive calls that found nothing. A high ratio means consumers are polling an idle queue. |
| `plainq_message_in_queue_duration_seconds` | histogram | `queue` | How long a message sat in a queue before it was delivered. |
| `plainq_message_size_bytes` | histogram | `queue` | Distribution of message body sizes on send. |
| `plainq_messages_dead_lettered_total` | counter | `queue` | Messages moved to a dead-letter queue. Anything above zero wants a human. |
| `plainq_messages_deleted_total` | counter | `queue` | Messages acknowledged and removed. Persistently below the receive rate means consumers are failing. |
| `plainq_messages_dropped_total` | counter | `queue`, `policy` | Messages evicted by retention or retry exhaustion, by eviction policy. |
| `plainq_messages_in_flight` | gauge | `queue` | Messages claimed by a consumer and not yet acknowledged. Tracked by delta between exact samples, so it is live rather than exact; rising and not falling means consumers are stalled. |
| `plainq_messages_received_bytes_total` | counter | `queue` | Message body bytes handed to consumers. |
| `plainq_messages_received_total` | counter | `queue` | Messages handed to a consumer. Counts redeliveries, so it exceeds messages_sent when consumers fail. |
| `plainq_messages_redelivered_total` | counter | `queue` | Messages handed out again after a visibility timeout expired. |
| `plainq_messages_sent_bytes_total` | counter | `queue` | Message body bytes accepted into a queue. |
| `plainq_messages_sent_total` | counter | `queue` | Messages accepted into a queue. |
| `plainq_queue_depth` | gauge | `queue` | Messages held by a queue. Tracked by delta between exact samples, so it is live rather than exact. |
| `plainq_queue_operation_duration_seconds` | histogram | `backend`, `operation` | How long a queue operation took inside the storage layer, transport excluded. |
| `plainq_queue_operations_total` | counter | `backend`, `operation`, `result` | Queue operations by outcome. The error rate here is the queue API's error rate. |
| `plainq_queues_exist` | gauge | — | Queues that currently exist. |

### Topics and subscriptions

| Metric | Type | Labels | Meaning |
| ------ | ---- | ------ | ------- |
| `plainq_topic_deliveries_total` | counter | `topic` | Individual deliveries to subscriber queues. One publish to three subscribers is three deliveries. |
| `plainq_topic_delivery_failures_total` | counter | `topic` | Deliveries that failed to reach a subscriber queue. Publishing is best-effort per subscriber, so this is the only place a lost fan-out shows up. |
| `plainq_topic_fanout` | histogram | `topic` | Distribution of how many subscriber destinations a single publish selected. |
| `plainq_topic_messages_published_total` | counter | `topic` | Messages published to a topic, counted once per publish regardless of fan-out. |
| `plainq_topic_operation_duration_seconds` | histogram | `backend`, `operation` | How long a topic operation took inside the storage layer. |
| `plainq_topic_operations_total` | counter | `backend`, `operation`, `result` | Topic operations by outcome. |
| `plainq_topic_published_bytes_total` | counter | `topic` | Message body bytes published to a topic. |
| `plainq_topic_request_duration_seconds` | histogram | `backend`, `operation` | How long a decoded topic request took at the application boundary. |
| `plainq_topic_requests_total` | counter | `backend`, `operation`, `result` | Decoded topic requests by outcome. |
| `plainq_topic_subscriptions` | gauge | `topic` | Subscriptions currently attached to a topic. |
| `plainq_topic_subscriptions_created_total` | counter | `topic` | Subscriptions created on a topic. |
| `plainq_topic_subscriptions_deleted_total` | counter | `topic` | Subscriptions removed from a topic. |
| `plainq_topics_exist` | gauge | — | Topics that currently exist. |

Request and storage-operation families are intentionally separate: a decoded
request can fail validation before storage is called. Their label vocabulary is
closed. `backend` is exactly `sqlite`, `turso`, `postgres`, or `cluster`;
`operation` is exactly `create_topic`, `delete_topic`, `list_topics`, `publish`,
`subscribe`, or `unsubscribe`; and `result` is exactly `ok` or `error`. Neither
request nor storage-operation families use a `topic` label. Topic IDs appear
only on the bounded business and current-state families.

Useful pub/sub queries:

```promql
sum by (topic) (rate(plainq_topic_messages_published_total[5m]))
sum by (topic) (rate(plainq_topic_delivery_failures_total[5m]))
sum by (operation, result) (rate(plainq_topic_requests_total[5m]))
histogram_quantile(0.95, sum by (le, operation) (rate(plainq_topic_request_duration_seconds_bucket[5m])))
```

Subscription lifecycle counters include explicit unsubscribe plus bindings
removed by successful topic or queue deletion. Current topic/subscription gauges
come from authoritative storage reconciliation. On a cluster, `/metrics` and
Houston describe **This node**: local state and activity observed by the node
you queried, not a magically aggregated cluster-wide view. Aggregate nodes in
Prometheus when you need a cluster total and avoid summing replicated exact
gauges as if each replica were a different topic.

### HTTP and gRPC

| Metric | Type | Labels | Meaning |
| ------ | ---- | ------ | ------- |
| `plainq_grpc_request_duration_seconds` | histogram | `method` | gRPC unary call latency by method. |
| `plainq_grpc_requests_total` | counter | `method`, `code` | gRPC unary calls served, by method and status code. |
| `plainq_http_request_duration_seconds` | histogram | `method`, `route` | HTTP request latency by route, measured across the whole handler chain. |
| `plainq_http_request_size_bytes` | histogram | `method`, `route` | Distribution of HTTP request body sizes, as declared by Content-Length. |
| `plainq_http_requests_total` | counter | `method`, `route`, `code` | HTTP requests served, by route and status code. |
| `plainq_http_response_size_bytes` | histogram | `method`, `route` | Distribution of HTTP response body sizes. |
| `plainq_panics_recovered_total` | counter | `protocol` | Panics caught by a transport's recovery layer. Any value above zero is a bug. |
| `plainq_requests_in_flight` | gauge | `protocol` | Requests currently being served. Climbing while throughput is flat means the server is the bottleneck. |

### Authentication and authorization

| Metric | Type | Labels | Meaning |
| ------ | ---- | ------ | ------- |
| `plainq_auth_attempts_total` | counter | `scheme`, `outcome` | Authentication attempts by scheme and outcome. A climbing invalid_token rate on a stable client set is worth a look. |
| `plainq_authz_decisions_total` | counter | `check`, `permission`, `decision` | Authorization decisions by check and outcome. Denials are normal; errors mean the permission store is failing open or closed. |
| `plainq_oauth_request_duration_seconds` | histogram | `provider`, `stage` | Latency of calls out to an OAuth provider. A slow provider becomes a slow login. |
| `plainq_oauth_requests_total` | counter | `provider`, `stage`, `result` | Calls out to an OAuth provider, by stage of the flow and outcome. |
| `plainq_onboarding_checks_total` | counter | `outcome` | Onboarding gate evaluations, by outcome. `required` means the server is still refusing traffic pending initial setup. |
| `plainq_security_audit_failures_total` | counter | — | Authentication failures that could not be persisted to the security audit log. Any increase means the best-effort audit trail is incomplete. |

### Storage

| Metric | Type | Labels | Meaning |
| ------ | ---- | ------ | ------- |
| `plainq_storage_db_connections` | gauge | `backend`, `state` | Database connections by state. Saturating `in_use` is what a queue stalling on the write lock looks like. |
| `plainq_storage_db_wait_seconds_total` | counter | `backend` | Cumulative time spent waiting for a database connection. |
| `plainq_storage_db_waits_total` | counter | `backend` | Connection acquisitions that had to wait for a free connection. |
| `plainq_storage_errors_total` | counter | `backend`, `operation` | Storage-layer failures that were not attributable to a single API operation. |
| `plainq_storage_gc_duration_seconds` | histogram | `backend`, `scope` | How long a full retention sweep took. Approaching the sweep interval means the sweeper is falling behind. |
| `plainq_storage_gc_runs_total` | counter | `backend`, `result` | Retention sweeps started, by outcome. |

### Cluster

| Metric | Type | Labels | Meaning |
| ------ | ---- | ------ | ------- |
| `plainq_cluster_applied_index` | gauge | `node_id` | Highest log index this node has applied. Its distance from the commit index is this replica's lag. |
| `plainq_cluster_applies_total` | counter | `operation`, `result` | Writes proposed through consensus by this node, by operation and outcome. |
| `plainq_cluster_apply_duration_seconds` | histogram | `operation` | Time from proposing a write to it being committed and applied. This is the cost clustering adds to a write. |
| `plainq_cluster_commands_applied_total` | counter | `node_id` | Commands applied to the local replica. |
| `plainq_cluster_commands_failed_total` | counter | `node_id` | Commands that failed to apply. A rejected CreateQueue is a legitimate one; a steady climb is not. |
| `plainq_cluster_commit_index` | gauge | `node_id` | Highest committed log index. |
| `plainq_cluster_determinism_overflows_total` | counter | `operation` | Commands that needed more identifiers than the leader assigned. Replicas stay consistent, but the command was sized against state that had already moved. |
| `plainq_cluster_discovery_duration_seconds` | histogram | `provider` | How long a discovery provider took to answer. |
| `plainq_cluster_discovery_peers` | gauge | `provider` | Peers the last successful discovery run returned, by provider. |
| `plainq_cluster_discovery_runs_total` | counter | `provider`, `result` | Discovery queries by provider and outcome. A provider failing every run is a misconfigured cluster that has not noticed yet. |
| `plainq_cluster_forward_duration_seconds` | histogram | `operation` | Round-trip time of a write forwarded to the leader, network included. |
| `plainq_cluster_forwards_total` | counter | `operation`, `result` | Writes a follower handed to the leader, by outcome. |
| `plainq_cluster_fsm_applies_total` | counter | `operation`, `result` | Log entries applied to the local state machine, by operation and outcome. |
| `plainq_cluster_fsm_apply_duration_seconds` | histogram | `operation` | Time the state machine spent applying one log entry. Consistently slow means followers fall behind. |
| `plainq_cluster_gossip_events_total` | counter | `type` | Membership events observed, by type. A steady stream of join/leave pairs is a flapping node. |
| `plainq_cluster_gossip_join_peers` | histogram | — | How many peers each join attempt reached. |
| `plainq_cluster_gossip_joins_total` | counter | `result` | Attempts to join the gossip pool, by outcome. |
| `plainq_cluster_gossip_members` | gauge | `state` | Members in the gossip view, by state. |
| `plainq_cluster_healthy` | gauge | `node_id` | 1 when the cluster can commit a write. Alert on 0 — this is the metric that means the queue is down. |
| `plainq_cluster_replica_quarantined` | gauge | `node_id` | 1 when this replica is quarantined after a non-deterministic state-machine result and must not serve data; 0 otherwise. |
| `plainq_cluster_last_index` | gauge | `node_id` | Last log index stored locally. |
| `plainq_cluster_leader` | gauge | `node_id` | 1 on the leader, 0 on followers. Summed across a cluster this should be exactly 1. |
| `plainq_cluster_leader_last_contact_seconds` | gauge | `node_id` | How long ago this follower heard from the leader. Zero on the leader itself. |
| `plainq_cluster_leadership_changes_total` | counter | `state` | Times this node gained or lost leadership. |
| `plainq_cluster_members` | gauge | `node_id` | Members known to this node, voters and non-voters alike. |
| `plainq_cluster_members_reachable` | gauge | `node_id` | Members gossip can currently see. Below quorum and the cluster cannot commit. |
| `plainq_cluster_membership_changes_total` | counter | `action`, `result` | Membership changes the leader made while reconciling gossip against the configuration. |
| `plainq_cluster_node_info` | gauge | `node_id`, `version`, `engine` | Constant 1 carrying this node's identity, build and consensus engine as labels. |
| `plainq_cluster_not_leader_total` | counter | — | Writes rejected because this node is not the leader and no leader was known. Spikes during an election. |
| `plainq_cluster_peer_auth_failures_total` | counter | — | Peer RPCs rejected for a bad or missing shared secret. On a private network this should be flat at zero; it climbing means something is reaching the cluster port that should not be. |
| `plainq_cluster_peer_request_duration_seconds` | histogram | `path` | Latency of internal peer RPCs, server side. |
| `plainq_cluster_peer_requests_total` | counter | `path`, `result` | Internal peer RPCs served, by path and outcome. |
| `plainq_cluster_quorum` | gauge | `node_id` | Voters a write needs. Compare against members_reachable to see how many more failures the cluster survives. |
| `plainq_cluster_restore_duration_seconds` | histogram | — | How long it took to restore from a snapshot. The node is not serving reads for this long. |
| `plainq_cluster_restore_records_total` | counter | `kind` | Records read out of snapshots during a restore, by kind. |
| `plainq_cluster_restores_total` | counter | `result` | Snapshot restores, by outcome. A restore means this node was too far behind to catch up from the log. |
| `plainq_cluster_snapshot_bytes` | histogram | — | Size of the snapshots this node produced. |
| `plainq_cluster_snapshot_duration_seconds` | histogram | — | How long it took to stream a snapshot out. |
| `plainq_cluster_snapshot_records_total` | counter | `kind` | Records written into snapshots, by kind. |
| `plainq_cluster_snapshots_total` | counter | `result` | State-machine snapshots taken, by outcome. |
| `plainq_cluster_sweeps_total` | counter | `result` | Retention sweeps the leader proposed through the log, by outcome. |
| `plainq_cluster_term` | gauge | `node_id` | Current consensus term. Climbing steadily means the cluster keeps re-electing. |
| `plainq_cluster_transport_connections_total` | counter | `protocol`, `direction` | Connections on the multiplexed cluster port, by protocol and direction. |
| `plainq_cluster_transport_handshake_failures_total` | counter | — | Inbound connections dropped before a protocol could be identified. |
| `plainq_cluster_voters` | gauge | `node_id` | Voting members in the consensus configuration. |

### Telemetry subsystem

| Metric | Type | Labels | Meaning |
| ------ | ---- | ------ | ------- |
| `plainq_telemetry_aggregation_duration_seconds` | histogram | `interval` | How long a telemetry roll-up took. |
| `plainq_telemetry_aggregations_total` | counter | `interval`, `result` | Telemetry roll-ups, by window and outcome. |
| `plainq_telemetry_cleanups_total` | counter | `result` | Retention sweeps over the telemetry store, by outcome. |
| `plainq_telemetry_collection_duration_seconds` | histogram | — | How long one telemetry collection pass took. Approaching the collection interval means it is falling behind. |
| `plainq_telemetry_collections_total` | counter | `result` | Rate-calculation passes the telemetry collector ran, by outcome. |
| `plainq_telemetry_event_buffer_dropped_total` | counter | `metric` | Internal telemetry event samples dropped because bounded collector buffers were full. |
| `plainq_telemetry_store_writes_total` | counter | `operation`, `result` | Writes to the telemetry store, by operation and outcome. A climbing error count means the dashboards are going stale. |
| `plainq_telemetry_terminal_state_dropped_total` | counter | — | Terminal topic states dropped because the bounded completion ledger was full or unavailable. |
| `plainq_telemetry_tracked` | gauge | `kind` | Distinct queues and topics the collector is holding metrics for. |

The two dropped counters are process-wide Prometheus health signals. They are
deliberately not written back into PlainQ's own telemetry store: recursively
collecting collector failures would make another failure while reporting the
first one. Alert on any sustained increase and expect affected historical
buckets to be marked missing.

### Process

| Metric | Type | Labels | Meaning |
| ------ | ---- | ------ | ------- |
| `plainq_build_info` | gauge | `version`, `commit`, `go_version` | Constant 1 carrying the build's version, commit and Go toolchain as labels. |
| `plainq_metrics_series_dropped_total` | counter | `family` | Metric samples that exceeded the per-family series cap and were folded into an __overflow__ series. |
| `plainq_start_time_seconds` | gauge | — | Unix timestamp of when this process started. |
| `plainq_uptime_seconds` | gauge | — | Seconds since this process started. A reset to near-zero is a restart nobody mentioned. |

Cluster metrics only appear on a clustered server (`--cluster.enable`); the
connection-pool metrics take the `backend` of whichever storage driver is
running. See the [clustering guide](clustering.md#observability) for what the
cluster families mean in practice.

### Cardinality

Queue and topic identifiers are labels, and they come from users. Each family
is capped at 1024 distinct label combinations; past that, further combinations
collapse onto a single `__overflow__` series and
`plainq_metrics_series_dropped_total` starts climbing. The totals stay right —
what is lost is the attribution. If you see it move, either you have more
queues than a per-queue dashboard can usefully draw, or something is creating
queues in a loop.

Route labels are chi's route *patterns* (`/api/v1/queue/{id}/messages`), never
the request path, so a busy server does not mint a series per queue id.

### Depth and in-flight are live, not exact

Every counter and histogram above is exact. The two gauges
`plainq_queue_depth` and `plainq_messages_in_flight` are not: they are tracked
by delta on the write path so they move the instant traffic does, and corrected
against an exact row count at start-up and after every retention sweep.

The correction is not decoration. Deltas start from zero on a process that
restarts onto a database full of messages, and nothing emits an event when a
visibility timeout lapses and a claimed message quietly becomes available
again — so between samples both gauges can be a little off, and without the
samples they would drift without bound. Redeliveries are compensated
explicitly, because a queue whose consumers keep failing is precisely the one
you are watching in-flight for.

If you need an exact depth at a moment in time, `DescribeQueue` counts rows.

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
| `--telemetry.sqlite.retention.period`     | `336h`    | How long collected metrics are kept (14 days).       |
| `--telemetry.sqlite.gc.timeout`           | `10m`     | Telemetry GC sweep interval.                         |
| `--telemetry.prometheus.baseurl`          | _(empty)_ | Optional external Prometheus API base URL.           |
| `--telemetry.log.enable`                  | `false`   | Log telemetry-subsystem activity.                    |

With the SQLite provider, telemetry is stored in a sibling database next to your
main one (e.g. `plainq_telemetry.db`), created and migrated automatically on
startup. If telemetry fails to initialize, the server logs a warning and keeps
running with the metrics dashboard disabled — it never blocks the queue service.

Raw samples use the configured collection interval (10 seconds by default) and
are rolled into closed 1-minute, 1-hour, and 1-day tiers. The API automatically
uses raw data for ranges up to 1 hour, 1-minute data up to 24 hours, 1-hour data
up to 30 days, and 1-day data beyond that, bounded by configured retention.
Coverage is stored per metric series. Responses expose requested and effective
half-open ranges, `sampleIntervalMs`, expected/returned point counts, and
contiguous missing ranges classified as `notRecorded` or `outsideRetention`.
A real measured zero stays zero; unavailable history stays absent and Houston
never draws a line across it.

Authenticated topic telemetry routes include:

- `/api/v1/metrics/topic/{id}/rates` for publish, delivery, and failure rates;
- `/api/v1/metrics/topic/{id}/subscriptions` for active subscriptions and
  create/remove rates;
- topic summary and overview responses with range-scoped
  `operationSummaries` (decoded requests) and
  `storageOperationSummaries` (storage work).

The two operation fields are independently nullable because validation can fail
without a storage call. Houston does not conflate them and does not plot the
storage family. Its two public-subscribe graphs are delivery activity and active
subscriptions; active counts use step-after interpolation, while rates use
linear segments only between adjacent known samples.

> The telemetry store and the Prometheus endpoint are fed from the same event
> stream, so they cannot disagree about what happened. They differ in what they
> keep: `/metrics` holds counters your monitoring stack scrapes and stores
> itself, while the telemetry store keeps the rolled-up history Houston's charts
> draw from without needing a Prometheus at all.

Collection, rollup, or cleanup failures are retried in order and leave honest
gaps rather than fabricated coverage. Changing the raw interval first catches
up old completed tiers, then resets retained raw rows; the transition is
reported as `notRecorded`. The legacy `collection.timeout` option is the
collection interval and must be a whole-millisecond divisor of one minute;
enabled retention must be at least 24 hours.

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

The metrics worth an alert, and the queries that read them.

**Messages are being dead-lettered.** The highest-signal alert there is: a
non-empty dead-letter queue almost always means something needs a human.

```promql
increase(plainq_messages_dead_lettered_total[15m]) > 0
```

**Consumers are stalled.** In-flight messages climbing and not coming back down
means work is being claimed and never acknowledged.

```promql
plainq_messages_in_flight > 0
  and deriv(plainq_messages_in_flight[15m]) > 0
```

**Consumers are failing rather than busy.** Receives running well ahead of
deletes means messages are being handed out, dropped, and handed out again —
which the redelivery counter says outright.

```promql
rate(plainq_messages_redelivered_total[5m])
  / rate(plainq_messages_received_total[5m]) > 0.1
```

**Producers are outpacing consumers.** Depth climbing steadily is a backlog,
whatever the rates look like in isolation.

```promql
deriv(plainq_queue_depth[30m]) > 0
```

**The API is erroring.** One query covers every operation on every backend.

```promql
sum by (operation) (rate(plainq_queue_operations_total{result="error"}[5m]))
  / sum by (operation) (rate(plainq_queue_operations_total[5m]))
```

**The server is saturated.** Requests in flight climbing while throughput is
flat means the bottleneck is here, not upstream. On SQLite, compare it against
connections in use — writes serialize on one connection, and that is usually
what a slow queue turns out to be.

```promql
plainq_requests_in_flight
plainq_storage_db_connections{state="in_use"}
```

**The cluster cannot commit.** On a clustered server this is the metric that
means the queue is down.

```promql
min(plainq_cluster_healthy) == 0
```

**A replica is falling behind.** The gap between what the cluster committed and
what this node applied is its lag.

```promql
plainq_cluster_commit_index - plainq_cluster_applied_index > 1000
```

**The telemetry pipeline has stopped.** The failure mode of a metrics pipeline
is silence, so it needs its own alert rather than the absence of one.

```promql
rate(plainq_telemetry_store_writes_total{result="error"}[10m]) > 0
```

Two more worth a graph rather than an alert: `plainq_empty_receives_total`
against `plainq_messages_received_total` says how much of your consumer traffic
is polling an idle queue, and
`histogram_quantile(0.99, rate(plainq_message_in_queue_duration_seconds_bucket[5m]))`
says how long a message actually waits — which is the number your users
experience.

And keep the plain one: a failing readiness `/health` should take the instance
out of rotation. Do not wire liveness to readiness; `/live` deliberately stays
healthy during a dependency failure or replica quarantine so orchestration does
not erase useful recovery state in a restart loop.

## Next steps

- [Houston](houston.md) — the dashboards these metrics feed.
- [Queues & messages](queues-and-messages.md) — what in-flight and retries mean.
- [Deployment](deployment.md) — wiring probes and scrapers.
