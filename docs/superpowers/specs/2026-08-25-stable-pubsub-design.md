# Stable Queue-Backed Pub/Sub v1 Design

## Status

Approved design.

## Context

PlainQ already implements a queue-backed publish/subscribe system:

- a topic is a named fan-out point;
- a subscription binds an existing queue to a topic;
- publishing copies every message into every subscribed queue;
- consumers receive and acknowledge those copies through the ordinary queue API.

The implementation is available over HTTP and gRPC, but the public documentation
still calls it experimental and HTTP-only. The protobuf schema already contains
the six pub/sub RPCs, while the CLI exposes none of them. Prometheus declares a
substantial set of pub/sub metric families, but several lifecycle families are
not wired to events. PlainQ's SQLite telemetry store persists only a subset of
the pub/sub signals, and Houston has one topic throughput chart whose longer
time ranges outlive the underlying rate snapshots.

An older approved design describes a different, append-only topic log with
subscription cursors, direct consume and ack operations, durable and ephemeral
subscriptions, and push delivery. That model is valuable, but it is not the
system deployed today. Replacing the existing v1 semantics while calling the
change stabilization would break current users and require a storage migration.

## Decision

Stabilize the existing queue-backed fan-out system as PlainQ pub/sub v1.

The current protobuf and HTTP shapes become compatibility contracts. The CLI
will expose the same six operations. Prometheus and PlainQ telemetry will be fed
from one pub/sub event stream, and Houston will show delivery and subscription
history from the internal telemetry store.

The append-only cursor model is reserved for a future, explicitly versioned
service. It must not silently replace the queue-backed v1 contract.

## Goals

- Declare one stable v1 domain model and delivery contract.
- Support the same operations over gRPC, HTTP, and the `plainq` CLI.
- Preserve compatibility with the already-published protobuf schema.
- Normalize public validation and error behavior across transports.
- Measure every public pub/sub operation and business outcome.
- Make `/metrics` immediately usable by Prometheus, including metadata.
- Persist the operator-facing pub/sub history needed by Houston without an
  external Prometheus server.
- Add useful, accessible graphs to the active Houston Pub/Sub page.
- Replace experimental and HTTP-only documentation with the stable contract.

## Non-Goals

- Append-only topic storage or subscription cursors.
- Direct topic `consume`, `ack`, `nack`, or `seek` operations.
- Push or streaming subscriptions.
- Exactly-once delivery.
- Atomic fan-out across all subscriber queues.
- Publish idempotency or deduplication.
- Topic partitions, ordering keys, filtering, or log compaction.
- Per-topic authorization or a new authentication model.
- Cross-node aggregation inside Houston; Prometheus performs cluster aggregation.
- Migrating queue-backed subscriptions into a future cursor-based service.

## Stable Domain Contract

### Topic

A topic is a named fan-out point. It does not retain message bodies. A topic has:

- a stable XID `topic_id`;
- a non-empty, unique `topic_name`;
- a creation timestamp;
- zero or more queue subscriptions.

Deleting a topic permanently deletes its subscriptions. It does not delete the
queues that were subscribed and does not delete messages already copied into
those queues.

### Subscription

A subscription is a durable binding between one topic and one existing queue.
It has:

- a stable XID `subscription_id`;
- the owning `topic_id`;
- the destination `queue_id` and its display name;
- a creation timestamp.

The pair `(topic_id, queue_id)` is unique. Subscribing the same queue twice is an
`AlreadyExists` conflict. Deleting a subscribed queue removes the binding through
the existing foreign-key cascade.

A subscription is not a consumer cursor. Multiple workers consuming its queue
are competing consumers of the same queue copy. Users create separate queues and
subscriptions when every consumer group must receive its own copy.

### Publish

`Publish` accepts a non-empty batch of byte bodies. For the subscription set read
at the start of the operation, PlainQ attempts to send the full batch to every
destination queue.

- Publishing to a topic with no subscriptions succeeds with zero deliveries.
- Each successful queue send creates distinct queue message IDs.
- Delivery remains at-least-once after the copy enters a queue.
- Fan-out is synchronous and best-effort; it is not atomic across queues.
- PlainQ attempts every subscription even if an earlier destination fails.
- If any destination fails, the public call returns an error after all current
  destinations have been attempted. Copies accepted by earlier queues remain.
- Retrying an errored publish can therefore create duplicate queue messages.

Current releases stop at the first destination error. Stabilization deliberately
changes that behavior before declaring v1 stable: all destinations selected at
the start are attempted, so a failed call can create copies in queues that older
releases would not have reached. The wire shape and error status do not change,
but the release notes and compatibility tests must call out this one-time
behavior correction. It makes delivery accounting deterministic; it does not
make retries idempotent.

The successful response retains its existing fields:

- `topic_id` identifies the topic;
- `queue_ids` lists the destination queues;
- `message_ids` is the flattened set of queue message IDs;
- `delivered_count` is the number of queue messages successfully created.

The flattened arrays do not promise a stable queue-to-message positional mapping.
Clients that need the full machine-readable outcome use the response as counts
and identifiers, not as a relational structure.

## Stable Public Schema

### gRPC

The stable service remains `v1.PlainQService` with these existing methods:

| Method | Request | Response | Effect |
| --- | --- | --- | --- |
| `ListTopics` | `ListTopicsRequest` | `ListTopicsResponse` | read-only |
| `CreateTopic` | `CreateTopicRequest` | `CreateTopicResponse` | mutating |
| `DeleteTopic` | `DeleteTopicRequest` | `DeleteTopicResponse` | destructive |
| `Subscribe` | `SubscribeRequest` | `SubscribeResponse` | mutating |
| `Unsubscribe` | `UnsubscribeRequest` | `UnsubscribeResponse` | destructive |
| `Publish` | `PublishRequest` | `PublishResponse` | mutating |

No existing method, message, field name, field number, enum value, or semantic
meaning may be removed or reused within v1. Compatible additions are allowed.
Removed fields or enum values must reserve both their old numbers and names.

`buf lint` and `buf breaking` remain required. Pull requests compare against
`main`; releases compare against the immutable `buf.build/plainq/schema`
history. Generated Go, gRPC, Connect, validation, JSON, and HTML documentation
artifacts must be regenerated whenever the schema changes.

This stabilization requires authoritative comments and compatibility tests, not
a new protobuf service or duplicate message types.

The gRPC listener retains its current privileged-network model and does not gain
authentication in this work. Stable describes its API compatibility, not its
network exposure. Operators must continue to protect the listener externally.

### HTTP

The stable REST surface remains under `/api/v1/queue/topics`:

| Method and path | Success | gRPC equivalent |
| --- | --- | --- |
| `GET /api/v1/queue/topics/` | `200` | `ListTopics` |
| `POST /api/v1/queue/topics/` | `201` | `CreateTopic` |
| `DELETE /api/v1/queue/topics/{topicID}` | `200` | `DeleteTopic` |
| `POST /api/v1/queue/topics/{topicID}/subscriptions` | `201` | `Subscribe` |
| `DELETE /api/v1/queue/topics/{topicID}/subscriptions/{subscriptionID}` | `200` | `Unsubscribe` |
| `POST /api/v1/queue/topics/{topicID}/publish` | `202` | `Publish` |

HTTP uses camel-case JSON matching the existing DTOs. Byte bodies remain
base64-encoded in JSON. Successful delete and unsubscribe responses remain `{}`.
HTTP and gRPC must call the same service/storage behavior and emit the same
business events.

When server authentication is enabled, the HTTP topic subtree remains protected
by the existing bearer-token middleware. This design adds no per-topic or
per-queue authorization decision.

### Validation and errors

The public mappings are:

| Condition | gRPC | HTTP | CLI exit |
| --- | --- | --- | --- |
| malformed XID, empty topic name, or empty publish batch | `InvalidArgument` | `400` | `2` |
| missing topic, queue, or subscription | `NotFound` | `404` | `1` |
| duplicate topic name or duplicate topic/queue binding | `AlreadyExists` | `409` | `1` |
| unauthenticated or unauthorized HTTP request when auth is enabled | — | `401`/`403` | — |
| typed temporary storage unavailability | `Unavailable` | `503` | `1` |
| unclassified storage or partial fan-out failure | `Internal` | `500` | `1` |

Errors must be normalized from typed causes, not database error strings. Topic
and subscription identifiers receive the same XID validation discipline as
queue identifiers. CLI `NotFound` advice must name the relevant topic command,
not always suggest `plainq list`.

## CLI Contract

Add one nested, non-interactive command group:

```text
plainq topic list
plainq topic create <topic-name>
plainq topic delete <topic-id>
plainq topic subscribe <topic-id> <queue-id>
plainq topic unsubscribe <topic-id> <subscription-id>
plainq topic publish <topic-id> -message=...
```

Grouping under `topic` avoids collisions with the existing queue-oriented root
commands and follows the established `cluster` and `ctx` pattern.

### Shared CLI behavior

Every leaf command accepts:

- `-grpc.addr`, resolved through the existing flag, environment, context, and
  default precedence;
- `-json`, which emits the raw protobuf JSON response to stdout.

Flags may appear before or after positionals and may use one or two leading
dashes. Errors go only to stderr. Exit codes remain `0` for success, `1` for a
server/runtime failure, and `2` for invalid invocation. The command metadata is
the single source for help text and `plainq schema -target=cli`.

### Text output

- `topic list`: one `<topic-id> | <topic-name>` line per topic.
- `topic create`: the new topic ID only.
- `topic delete`: `deleted\t<topic-id>`.
- `topic subscribe`: the new subscription ID only.
- `topic unsubscribe`: `unsubscribed\t<subscription-id>`.
- `topic publish`: `delivered\t<count>`.

`-json` is required when a caller needs embedded subscription objects, queue and
message IDs, timestamps, or other complete response fields.

### Publish input

`topic publish` reuses the queue `send` input contract:

- repeatable `-message` values create a batch;
- `-file=<path>` reads one non-empty message body per line;
- `-file=-` reads from stdin;
- `-message` and `-file` may be combined;
- no implicit stdin read occurs;
- empty input lines are ignored and a single line is limited to 4 MiB;
- at least one message is required.

There is no `topic receive` or `topic ack`. The CLI documentation must show
`plainq receive` and `plainq delete-message` against each subscribed queue.

## Observability Architecture

### One event stream, two sinks

Successfully decoded HTTP and gRPC requests enter one shared pub/sub application
boundary before domain validation and storage access. That boundary owns the
public-request timer and emits each request and business-outcome event once. The
existing observed-storage boundary continues to emit its distinct storage-call
event with its existing meaning. The telemetry observer fans each event to:

1. the process-wide Prometheus registry, whether or not internal telemetry is
   enabled; and
2. the optional PlainQ telemetry collector, which persists history for Houston.

Both sinks describe the current PlainQ process. Prometheus obtains a cluster
view by scraping every node and grouping on its target `instance` label. The
embedded SQLite telemetry store and Houston graphs are node-local, so Houston
labels them **This node** when clustering is enabled rather than presenting them
as cluster totals.

In cluster mode, decoded-request metrics, the outer storage-operation metrics,
and logical publish/lifecycle counters are emitted only on the node that accepted
the public request and use `backend="cluster"`. Replicated follower application
must not re-emit those logical counters. Every replica does reconcile
`plainq_topics_exist` and per-topic subscription gauges from its applied state
after create, delete, subscribe, unsubscribe, queue cascade, snapshot restore,
and catch-up. This keeps follower state gauges correct without multiplying one
logical event by the replica count. The local SQLite observer remains distinct
for genuinely local storage work and retains `backend="sqlite"`.

The observer updates Prometheus and bounded in-memory collector state on the
operation path; SQLite persistence and rollups remain background work. A
telemetry write failure never changes the pub/sub result. The existing
`plainq_telemetry_store_writes_total`, `plainq_telemetry_collections_total`,
`plainq_telemetry_aggregations_total`, and `plainq_telemetry_cleanups_total`
families expose collector failures so a silent or stale dashboard is itself
observable.

Duration/fan-out events and deleted-topic terminal gauge state each use a
65,536-entry bounded queue. Event overflow increments
`plainq_telemetry_event_buffer_dropped_total{metric}`; terminal-state overflow
increments `plainq_telemetry_terminal_state_dropped_total`. The collector writes
no coverage for a dropped value, so Houston reports `notRecorded` rather than a
fabricated zero. A terminal zero is persisted exactly once with exact-series
coverage before its retained topic state is removed; a coverage retry must not
insert a duplicate raw zero.

HTTP, gRPC, CLI-over-gRPC, SQLite, PostgreSQL, and clustered storage therefore
share the same business metric semantics. Transport handlers must not separately
record the same application or storage event, because that creates
protocol-dependent double counting. Request and storage families are
intentionally separate: one decoded request can produce zero or one storage
call.

A body that cannot be decoded as HTTP JSON or protobuf never becomes a pub/sub
business request; the existing HTTP or gRPC transport metrics record it. A
decoded request with an invalid XID, empty name, or empty publish batch does
enter the shared boundary and records an errored pub/sub request, but no storage
operation. Storage observers retain their existing operation timing and provide
the selected fan-out and partial-delivery outcome back to the application
boundary without emitting a second business-outcome event.

Exact topic and subscription gauges are reconciled at collector attachment,
startup/restore, topic deletion, and queue deletion. Create, subscribe, and
unsubscribe update the live values immediately between reconciliations. A
successful topic create increments or reconciles `plainq_topics_exist`. A
successful topic delete decrements or reconciles it, records a terminal zero for
the deleted topic's subscription gauge, and then removes that topic from the
internal current-state map.

Clustered publish apply is additionally fail-closed. A permanent guard-version
bit lives in the Raft stable store, so lost sidecars cannot look like a first
upgrade. Before mutating replicated publish state, each replica durably changes
a clean sidecar beside the Raft log to dirty. It restores clean only after deterministic full success or a
known non-mutating precondition failure. A local partial/unknown result leaves
the guard dirty, quarantines that replica, rejects later public reads/writes, and
survives restart even if writing a secondary diagnostic marker fails. Verified
snapshot restore or full replica wipe/reseed is required to recover. `/live`
remains process liveness while `/health` reports storage, quorum, and quarantine
readiness; orchestration must not erase quarantine by restarting a live process.

Every binding actually removed increments the subscription-deleted lifecycle
counter, whether removal came from explicit unsubscribe, topic deletion, or the
queue foreign-key cascade. The delete path reads affected bindings before the
cascade so it can attribute each removal to its topic. Startup, restore, and
repair reconciliation only rebase current gauges; they never fabricate created
or deleted lifecycle events.

### Coverage matrix

| Event or state | Prometheus | Internal telemetry | Houston |
| --- | --- | --- | --- |
| all six decoded request outcomes | request counter by backend, operation, result | labeled cumulative request outcomes | topic summaries plus system overview |
| all six decoded request duration | request histogram by backend and operation | request-duration samples | topic summaries plus system overview |
| storage calls and duration | existing operation counter/histogram | labeled storage outcomes and duration samples | range-scoped `storageOperationSummaries`, not graphed |
| messages published | per-topic counter | total and per-second rate | delivery chart and summaries |
| published body bytes | per-topic counter | total and per-second rate | range summary |
| successful queue deliveries | per-topic counter | total and per-second rate | delivery chart and summaries |
| failed queue deliveries | per-topic counter | total and per-second rate | retry-tone series and summary |
| fan-out width | per-topic histogram | per-window average and maximum | range summary |
| subscriptions created/deleted | per-topic counters | totals and per-second rates | range summary |
| current subscriptions | per-topic gauge | exact gauge history | subscription chart |
| topics currently present | process gauge | exact system gauge | overview summary |
| HTTP and gRPC request outcomes/latency | existing transport families | not duplicated | not duplicated |

### Prometheus families

The stable exposition adds request-level families:

- `plainq_topic_requests_total{backend,operation,result}`
- `plainq_topic_request_duration_seconds{backend,operation}`

It retains the existing storage-scoped families and wires their missing
lifecycle outcomes without changing their meaning:

- `plainq_topic_operations_total{backend,operation,result}`
- `plainq_topic_operation_duration_seconds{backend,operation}`
- `plainq_topic_messages_published_total{topic}`
- `plainq_topic_published_bytes_total{topic}`
- `plainq_topic_deliveries_total{topic}`
- `plainq_topic_delivery_failures_total{topic}`
- `plainq_topic_fanout{topic}`
- `plainq_topic_subscriptions{topic}`
- `plainq_topic_subscriptions_created_total{topic}`
- `plainq_topic_subscriptions_deleted_total{topic}`
- `plainq_topics_exist`

The same process registry exposes the fail-closed/collector health families:

- `plainq_cluster_replica_quarantined{node_id}`
- `plainq_telemetry_event_buffer_dropped_total{metric}`
- `plainq_telemetry_terminal_state_dropped_total`

These health counters/gauges are intentionally not fed back into the internal
collector, avoiding recursive telemetry about a collector that is already
degraded.

The process enables metric metadata so `/metrics` emits Prometheus-compatible
`# HELP` and `# TYPE` lines. Histograms use classic `le` buckets. The runtime
catalog at `/api/v1/metrics/catalog` is generated from the same declarations.
Topic labels remain bounded by the registry's per-family series cap and overflow
series. Route metrics use route patterns rather than raw resource paths.

Publish accounting is defined as follows:

- a valid publish that begins fan-out increments messages and bytes once,
  including a successful publish to zero subscriptions;
- each accepted queue message increments deliveries;
- queue `Send` is atomic for one destination batch; an errored destination
  therefore increments delivery failures by the publish batch size;
- fan-out observes the number of subscription destinations selected for the
  request;
- a partial fan-out increments the publish operation's error outcome while
  retaining all successful and failed delivery counts.

### Internal telemetry metrics

The collector keeps the existing topic totals/rates and adds the missing
signals required by the coverage matrix. Its stable metric names are:

- `plainq_topic_requests_total`, with `backend`, `operation`, and `result` labels
- `plainq_topic_request_duration_seconds`, with `backend` and `operation` labels
- `plainq_topic_operations_total`, with `backend`, `operation`, and `result` labels
- `plainq_topic_operation_duration_seconds`, with `backend` and `operation` labels
- `plainq_topic_messages_published_total`
- `plainq_topic_published_bytes_total`
- `plainq_topic_deliveries_total`
- `plainq_topic_delivery_failures_total`
- `plainq_topic_subscriptions_created_total`
- `plainq_topic_subscriptions_deleted_total`
- `plainq_topic_subscriptions_current`
- `plainq_topics_exist`
- `plainq_topic_publish_rate`
- `plainq_topic_delivery_rate`
- `plainq_topic_delivery_failure_rate`
- `plainq_topic_published_bytes_rate`
- `plainq_topic_subscriptions_created_rate`
- `plainq_topic_subscriptions_deleted_rate`
- `plainq_topic_fanout`

System-wide series use an empty subject identifier, matching the current
collector convention. Per-topic series use the topic XID. The existing generic
telemetry subject column remains in v1; renaming it is unrelated to stabilizing
pub/sub.

The internal types and dimensions are fixed as follows:

| Metric group | Stored type | Subject and labels | Rollup value |
| --- | --- | --- | --- |
| request and storage operation totals | counter snapshot | always system subject; also topic subject when a topic ID is known; canonical JSON labels `backend`, `operation`, `result` | reset-aware increase |
| request and storage operation duration | event sample | same subject rule; canonical JSON labels `backend`, `operation` | min, max, weighted average, sum, count |
| published, byte, delivery, failure, and subscription lifecycle totals | counter snapshot | topic subject and system subject | reset-aware increase |
| current subscriptions | gauge sample | topic subject and system subject | last value, plus min/max/average metadata |
| topics present | gauge sample | system subject only | last value, plus min/max/average metadata |
| rate series | rate sample | topic subject and system subject | average as chart value, plus min/max/sum/count metadata |
| `plainq_topic_fanout` | event sample | topic subject and system subject | max and weighted average from sum/count |

The six `operation` values are `list_topics`, `create_topic`, `delete_topic`,
`subscribe`, `unsubscribe`, and `publish`; `result` is `ok` or `error`;
`backend` uses the existing bounded values `sqlite`, `postgres`, and `cluster`.
System operation series are always written. A topic operation series is also
written when the request contains a valid topic ID, or, for successful create,
when the response provides the new ID. Failed create and list operations
therefore have no per-topic copy.

Counter snapshots are cumulative within one process epoch. Their rollup stores
a reset-aware increase: a lower value starts a new epoch and contributes its
value rather than a negative delta. Duration samples store seconds. A duration
rollup combines child buckets as `sum(sum) / sum(count)` and preserves the
overall min, max, sum, and count. Labels are serialized in canonical key order
and are part of a series identity.

`plainq_topic_fanout` stores one event sample per publish. No publish produces no
sample; it does not produce a zero. For a publish, the sample is the number of
destinations selected, independently of how many destination writes succeeded.
Rollups retain its sum, count, and maximum, so a range average is `sum/count`
rather than an unweighted average of per-interval averages.

### Retention and resolution

Every computed rate is written both to `rate_snapshots`, for current-value
reads, and to `metrics_raw`, for history. Rate history then uses the same typed
raw, one-minute, hourly, and daily rollups as other telemetry instead of reading
only the short-lived snapshot table.

An additive telemetry migration gives the rollups the information their metric
types require:

- gauge buckets retain first and last values as well as min/max/average/sum/count;
- counter buckets retain reset-aware increase as well as first and last values;
- event-sample buckets retain min/max/weighted-average/sum/count.

A counter bucket is complete only with an immediately adjacent, covered prior
source bucket. An older value across an uncovered gap is never used as the
baseline, because that would smear a multi-bucket delta into one bucket.

The legacy `metrics_5m` table has no producer and lacks the fields needed for
correct typed aggregation. It remains readable for database compatibility, but
the selector does not choose it. The exact automatic mapping is:

| Requested window | Resolution |
| --- | --- |
| up to and including 1 hour | raw, at the configured collection interval |
| over 1 hour through 24 hours | 1 minute |
| over 24 hours through 30 days | 1 hour |
| over 30 days | 1 day |

`--telemetry.sqlite.collection.timeout` retains its existing public name and is
the collection interval despite the legacy `timeout` suffix. The collector uses
that configured interval, divides counter deltas by actual elapsed seconds, and
reports the actual interval in response metadata. Because public timestamps and
sample metadata are integer milliseconds and raw buckets feed exact minute
rollups, the interval must be at least one millisecond, be an exact whole number
of milliseconds, and divide one minute evenly. `--telemetry.sqlite.gc.timeout`
sets the cleanup interval and must be positive.

On restart with a changed collection interval, the collector first rolls all
complete old-grid raw buckets into retained coarse tiers, then transactionally
removes retained raw rows and raw coverage before collecting on the new grid.
An independent singleton collection-state row stores the active raw interval;
coverage is not used as the only grid detector. Its first upgrade initialization
also clears uncovered legacy raw rows. The transition is an explicit
`notRecorded` raw gap; one response never advertises a `sampleIntervalMs` that
disagrees with retained raw coverage or off-grid orphan rows.

`--telemetry.sqlite.retention.period` is the maximum internal-telemetry horizon
and must be at least 24 hours while telemetry is enabled, so every Houston
selector is honest. Cleanup retains raw for `min(1h, retention)`, one-minute data
for `min(24h, retention)`, hourly data for `min(30d, retention)`, and daily data
for the configured retention, plus one completed source bucket at each boundary
so aggregation and cleanup cannot punch a hole at the start of a supported
range. The current 14-day default therefore retains the required 24-hour
one-minute history and hourly/daily history up to 14 days. `rate_snapshots`
remains a latest-value cache and is not a historical chart source.

Aggregation processes only closed buckets, records the last completed bucket,
is idempotent, and catches up all still-retained source buckets at startup. It
must never replace a complete bucket with an overlapping partial tail. Collector
and cleanup workers stop with the server context rather than a detached
background context.

The supported Houston ranges—5m, 15m, 1h, 6h, and 24h—must return retained data
when telemetry was running during that period. The latest-value snapshot table
remains for current-rate reads. A custom query may request an explicitly
available coarser resolution but may not request the unproduced 5-minute tier.

Missing samples remain missing. Server and UI code must not synthesize zeroes
for absent measurements.

## Houston Pub/Sub Dashboard

Implement the graphs in the active `/pubsub` topic detail, not the unused
legacy topic-metrics components.

### Delivery graph

Extend the existing chart into **Publish and delivery outcomes** with three
series:

- published messages per second;
- successful queue deliveries per second;
- failed queue deliveries per second, using the shared `retry` tone.

The existing range selector remains. The summary names the selected window,
sample count, and series values. Publish and delivery counts are intentionally
different when a topic has more than one subscription.

### Subscription graph

Add **Active subscriptions** as a count-over-time chart. The surrounding summary
shows subscriptions created and removed during the selected window and the
current exact count. Creation and removal rates remain available through the
telemetry API even though unlike-unit rate lines are not mixed into the count
chart.

### Data APIs

`GET /api/v1/metrics/topic/{id}/rates` keeps the existing multi-series envelope
and always returns the three series in publish, delivery, failure order. The
additive top-level fields make its exact contract. This schema illustration
expands the first of the three required series objects; the other two have the
same fields:

```json
{
  "topicId": "d7...",
  "metrics": [
    {
      "metricName": "plainq_topic_publish_rate",
      "topicId": "d7...",
      "kind": "rate",
      "unit": "messages_per_second",
      "interpolation": "linear",
      "timeRange": { "from": 0, "to": 0 },
      "resolution": "raw",
      "samples": {
        "expectedPointCount": 0,
        "returnedPointCount": 0,
        "firstSampleAt": null,
        "lastSampleAt": null,
        "complete": false,
        "missingRanges": []
      },
      "dataPoints": []
    }
  ],
  "timeRange": { "from": 0, "to": 0 },
  "effectiveTimeRange": { "from": 0, "to": 0 },
  "resolution": "raw",
  "sampleIntervalMs": 10000,
  "generatedAt": 0
}
```

The other two `metricName` values are `plainq_topic_delivery_rate` and
`plainq_topic_delivery_failure_rate`. All ranges are half-open: `from` is
inclusive and `to` is exclusive. The existing `timeRange` field retains the
exact bounds parsed from `range` or `from`/`to`, and every nested series repeats
it. The new `effectiveTimeRange` is the closed sample range wholly contained
inside the request: for interval `I`, its start is
`ceil(timeRange.from/I)*I` and its end is
`min(floor(timeRange.to/I)*I, floor(generatedAt/I)*I)`. It therefore never
includes an unfinished bucket, a future interval, or an event outside the
request. Every nested series also carries the selected `raw`, `1m`, `1h`, or
`1d` resolution.

`sampleIntervalMs` is the configured raw collection interval, 60000, 3600000,
or 86400000 accordingly; 10000 is the current raw default. The collector aligns
raw sampling to those wall-clock buckets. `generatedAt` is the response time in
Unix milliseconds. A point timestamp is its bucket start and
`expectedPointCount` is exactly
`(effectiveTimeRange.to-effectiveTimeRange.from)/sampleIntervalMs`.

`samples.returnedPointCount` equals `len(dataPoints)`. `complete` is true only
when `expectedPointCount > 0`, the effective range is inside retention, and
telemetry coverage contains every expected bucket. Each `missingRanges` entry uses the same half-open Unix-
millisecond bounds and a `reason` of `notRecorded` or `outsideRetention`. The
first/last sample fields are nullable bucket-start timestamps.

Every data point requires `timestamp` (signed 64-bit Unix milliseconds),
`value` (JSON number), and `source` (`observed`, `aggregated`, or
`carriedForward`). Aggregated points also include `min`, `max`, `avg`, `sum`
and signed 64-bit `count`, even when any of those values is zero. Their `value`
follows the stored type: gauge uses `last`, counter uses reset-aware `increase`,
and rate or event sample uses `avg`. Observed raw points include `count: 1`. A
carried-forward gauge point has no aggregate fields. Empty series and
missing-range arrays encode as `[]`, never `null`.

Add `GET /api/v1/metrics/topic/{id}/subscriptions` with this exact additive
admin response. As above, the schema illustration expands the first of three
required series objects:

```json
{
  "topicId": "d7...",
  "summary": {
    "subscriptionsCurrent": null,
    "createdDuringWindow": null,
    "removedDuringWindow": null,
    "avgCreateRate": null,
    "avgRemoveRate": null,
    "maxCreateRate": null,
    "maxRemoveRate": null,
    "updatedAt": null
  },
  "metrics": [
    {
      "metricName": "plainq_topic_subscriptions_current",
      "topicId": "d7...",
      "kind": "gauge",
      "unit": "subscriptions",
      "interpolation": "stepAfter",
      "timeRange": { "from": 0, "to": 0 },
      "resolution": "raw",
      "samples": {
        "expectedPointCount": 0,
        "returnedPointCount": 0,
        "firstSampleAt": null,
        "lastSampleAt": null,
        "complete": false,
        "missingRanges": []
      },
      "dataPoints": []
    }
  ],
  "timeRange": { "from": 0, "to": 0 },
  "effectiveTimeRange": { "from": 0, "to": 0 },
  "resolution": "raw",
  "sampleIntervalMs": 10000,
  "generatedAt": 0
}
```

`subscriptionsCurrent` is a signed 64-bit JSON number after exact reconciliation
and `null` before it is known. `createdDuringWindow` and
`removedDuringWindow` are signed 64-bit reset-aware counter increases over the
effective range. Summary rates are JSON numbers per second. Any summary value
whose baseline or coverage is insufficient is `null`, never a guessed zero;
`updatedAt` is the nullable Unix-millisecond timestamp of the exact current
count. `metrics` contains three complete series objects in active, created-rate,
removed-rate order, named
`plainq_topic_subscriptions_current`,
`plainq_topic_subscriptions_created_rate`, and
`plainq_topic_subscriptions_deleted_rate` respectively.

For the active gauge, the server queries the last known sample before the
effective range. If that sample is still within uninterrupted telemetry
coverage and there is no covered point already at the range start, it emits one
`carriedForward` point there. A carried value never duplicates a timestamp or
crosses a declared missing range.

The existing topic summary response keeps all current fields and adds:

```json
{
  "totalPublishedBytes": null,
  "totalDeliveryFailures": null,
  "averageFanout": null,
  "maxFanout": null,
  "subscriptionsCreatedDuringWindow": null,
  "subscriptionsRemovedDuringWindow": null,
  "effectiveTimeRange": { "from": 0, "to": 0 },
  "resolution": "raw",
  "generatedAt": 0,
  "operationSummaries": [
    {
      "backend": "sqlite",
      "operation": "publish",
      "ok": 0,
      "error": 0,
      "durationSeconds": {
        "min": 0,
        "max": 0,
        "avg": 0,
        "sum": 0,
        "count": 0
      }
    }
  ],
  "storageOperationSummaries": []
}
```

Its preserved top-level `from` and `to` fields remain the exact requested
half-open bounds, matching `timeRange`; only calculations and
`effectiveTimeRange` use aligned closed-bucket bounds.

Nullable summary numbers are populated only when the effective window has the
baseline or samples needed to calculate them. All totals and operation summaries
are scoped to that effective range, never include an event outside the requested
range, and are not process-lifetime Prometheus counters.
Operation summaries are ordered by backend then by the fixed operation order.
For a topic response they include only operations attributable to that topic.
`operationSummaries` uses request-level families;
`storageOperationSummaries` uses the storage-operation counter/duration families
and has the same nullable array/item schema. Each field independently encodes
`null` when its own coverage is insufficient and `[]` when coverage is complete
but no attributable operation occurred. This makes storage history queryable by
arbitrary supported range without mixing it into request summaries or graphs.

`GET /api/v1/metrics/topics/overview` accepts the same `range` or `from`/`to`
query as topic detail, defaulting to one hour. It preserves the existing
`systemMetrics`, `topicMetrics`, `timeRange`, and `updatedAt` fields and adds
`effectiveTimeRange`, `resolution`, and these exact `systemMetrics` fields:

```json
{
  "publishedBytes": 0,
  "deliveryFailures": 0,
  "topicsExist": 0,
  "operationSummaries": [],
  "storageOperationSummaries": []
}
```

The first three are current process counters/gauge, matching the other existing
overview totals. System request and storage operation summaries are independently
range-scoped and have the same nullable array/item schema as the topic summary,
including system-attributable list and create calls. The overview's `timeRange`
is the requested half-open range and `effectiveTimeRange` uses the closed-bucket
rules above.

These authenticated metrics routes retain the current access model. A future
tenant authorization design must add resource checks before exposing
cross-tenant topic telemetry; this work must not pretend such isolation already
exists.

### UI states and accessibility

Both graphs reuse Houston's shared `SeriesChart`, chart tokens, legends, and
table view. They provide:

- accessible chart descriptions and labelled legends;
- loading skeletons;
- an explicit telemetry-disabled state;
- a true empty-range state distinct from zero traffic;
- a stale last-good view during refresh;
- an error state that does not discard the last valid data;
- responsive sizing through the existing chart component.

The shared chart row type permits `null` for an absent series value. Tooltips,
tables, and accessible summaries render it as unavailable and exclude it from
averages and peaks; they never coerce it to zero. The UI uses the response's
`sampleIntervalMs` rather than guessing from `resolution`. It materializes null
boundary rows for every server-declared missing range so Recharts cannot draw
across even one absent bucket.

Rate series remain linear between adjacent known samples. The active
subscription series uses `stepAfter`, because a subscription count remains at
its last observed value until the next observed change. It carries a value only
between adjacent known samples and never across a detected telemetry gap.

## Data and Failure Flow

### Successful publish

1. Validate topic ID and non-empty batch.
2. Read the topic's subscription set.
3. Record the selected fan-out width.
4. Attempt the batch against every destination queue.
5. Record queue-send events for successful copies.
6. Record published messages, bytes, successful deliveries, and zero or more
   delivery failures through the shared observer.
7. Return the stable publish response when every destination succeeded.

### Partial publish

1. Continue attempting the remaining subscriptions after a destination error.
2. Keep the internal partial outcome even when returning an error publicly.
3. Record successful and failed queue-message counts once.
4. Return a typed storage/transport error after all destinations were attempted.
5. Document that accepted copies remain and a retry can duplicate them.
6. Never serialize the internal partial outcome as a successful response beside
   an error; gRPC and HTTP retain their single error response contract.

### Subscription lifecycle

1. Validate both identifiers before storage access.
2. Create or delete the binding.
3. Emit the operation outcome once.
4. On success, update the exact topic subscription count in both sinks.
5. Before queue or topic deletion, capture affected bindings and emit one
   deletion lifecycle event per binding after the cascade commits.
6. Reconcile all topic counts after cascading queue/topic deletion and restore.

## Documentation

Update the canonical documentation and any published mirrors:

- `docs/guides/advanced.md`: stable model, HTTP/gRPC/CLI routes, delivery and
  retry semantics, and a CLI-first worked example;
- `docs/guides/troubleshooting.md`: replace the experimental answer with the
  production contract and operational caveats;
- `docs/guides/cli.md` and `docs/reference/cli.md`: full `topic` command family;
- website copies of the CLI guide/reference;
- `docs/guides/grpc-api.md`: list the stable pub/sub RPCs;
- `docs/guides/observability.md`: all topic metrics, PromQL examples, internal
  telemetry retention, and Houston graphs;
- generated protobuf Go code and schema HTML after protobuf comment changes;
- CLI discovery tests proving `plainq schema -target=cli` emits the new live
  command metadata (there is no checked-in CLI schema artifact).

Documentation must distinguish server authentication from resource
authorization and must not repeat the old claim that no gRPC surface exists.

## Testing Strategy

### Schema and compatibility

- `buf lint schema`
- pull-request compatibility against
  `https://github.com/marsolab/plainq.git#branch=main,subdir=schema`
- release compatibility against `buf.build/plainq/schema`
- generated-artifact drift checks
- descriptor tests proving all six methods remain discoverable

### CLI

- command-tree/schema coverage for every `topic` leaf;
- effects, arguments, common flags, examples, and help text;
- local XID and required-input failures return exit `2`;
- fake/bufconn gRPC tests for request construction and text/JSON output;
- repeatable message, file, stdin, and mixed publish input tests;
- topic-specific `NotFound` advice.

### Backend and transports

- identical SQLite and PostgreSQL topic/subscription semantics;
- duplicate and missing-resource error normalization;
- zero-subscription, multi-subscription, and partial-failure publish behavior;
- an explicit regression case proving stabilization attempts later destinations
  after the failure that caused older releases to stop;
- HTTP status/JSON and gRPC status/protobuf parity;
- decoded invalid requests count once as business-operation errors, while
  undecodable wire payloads count only in transport metrics;
- request and storage families remain distinct and retain their documented
  meanings;
- cluster ingress uses `backend="cluster"`, logical counters are not multiplied
  by follower apply, and follower gauges reconcile after apply/restore;
- no double counting when the same operation uses either transport.

### Prometheus

- scrape tests for every pub/sub family, label set, `# HELP`, and `# TYPE`;
- successful and failed operation outcomes;
- create/delete topic gauge transitions;
- subscribe/unsubscribe/cascade gauge and lifecycle transitions;
- message, byte, delivery, failure, and fan-out accounting;
- cardinality overflow behavior remains intact.

### Internal telemetry and APIs

- per-topic and system totals/rates for every matrix row;
- exact subscription reconciliation;
- explicit unsubscribe, topic cascade, and queue cascade lifecycle counts;
- typed raw-to-rollup history across 5m, 1h, 6h, and 24h windows;
- counter resets and process restarts;
- gauge last-value and counter-increase rollup semantics;
- rate snapshots and raw history are written together;
- topic summary, delivery-rate, and subscription-history handlers;
- range-scoped system operation summaries including list/create;
- exact response metadata, nullable incomplete summaries, and missing ranges;
- missing data remains absent rather than becoming zero.

### Houston

- active `TopicDetail` graph loading, ready, empty, disabled, stale, and error
  states;
- delivery-failure warning series;
- subscription history and range summaries;
- accessible summaries, legends, and table views;
- Astro check, frontend tests, and production build.

### Final verification

Run the repository's generated-schema checks, Go tests, linters, Houston tests,
Astro type checks, production builds, and `git diff --check`. Any PostgreSQL or
integration test requiring unavailable infrastructure must be reported as an
unverified release gate rather than silently omitted.

## Compatibility and Rollout

This is an in-place pub/sub stabilization with no queue/topic data migration and
no removal of public fields or routes. An additive internal-telemetry migration
may add typed rollup columns or tables; it does not touch queue messages, topics,
or subscriptions. Existing HTTP and gRPC clients continue to work. New CLI
commands, response metadata, and metric series are additive. Existing metric
names keep their meaning; this work fixes event wiring and adds missing internal
history.

The intentional exception is failed fan-out traversal: upgraded servers attempt
every destination selected at the beginning of a publish instead of stopping at
the first error. Release notes must state that an errored publish can therefore
reach more queues after upgrade. Operators already have to treat retries as
duplicate-prone; no new success guarantee or idempotency claim is introduced.

Operators should expect more complete topic series after upgrade. Counters
remain process-lifetime values in Prometheus and restart-aware window deltas in
the internal telemetry store. Historical delivery-failure and subscription
series cannot be reconstructed for time before the upgraded binary began
recording them.

No deployment or release is part of implementation unless separately approved.
