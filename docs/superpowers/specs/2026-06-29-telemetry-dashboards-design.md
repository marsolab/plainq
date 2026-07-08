# Telemetry Dashboards Design

## Status

Approved for spec review.

## Context

PlainQ has internal telemetry groundwork for queue metrics, stored locally without external services. The server already exposes queue-oriented metrics APIs for overview, rates, in-flight counts, available metrics, time ranges, and export. Houston already has an Astro/React UI, queue and pub/sub pages, and unused metrics components built around Recharts.

The requested product outcome is:

- every queue detail page shows useful charts and metrics
- the pub/sub page shows useful charts and metrics
- pub/sub metrics are first-class backend telemetry, not inferred from subscribed queue metrics
- the solution remains internal-only and does not depend on third-party observability services

## Existing Findings

- Queue list links use `/queue/{queueId}`.
- Houston currently has `src/pages/queue.astro`, but no dynamic queue detail route file for `/queue/{id}`.
- `QueueDetailOverview` has a `Metrics` tab with a placeholder.
- `TopicList` manages topics, subscriptions, and publish testing, but has no metrics surface.
- Metrics UI components currently fetch `/api/v1/metrics/...` directly instead of using the shared API client and refresh behavior.
- Backend telemetry currently records queue-oriented metrics and exposes queue-specific endpoints.
- Pub/sub publish, subscribe, and unsubscribe operations have clear HTTP and storage boundaries where successful operations can emit telemetry.

## Goals

- Add topic-scoped telemetry for publish and subscription activity.
- Reuse the existing telemetry collector, SQLite-backed metrics store, aggregation, retention, and chart response patterns.
- Add metrics APIs that are parallel to existing queue metrics APIs.
- Mount queue metrics inside queue detail pages.
- Add pub/sub metrics to the pub/sub page without replacing topic management.
- Preserve graceful behavior when telemetry storage is not configured.
- Keep the first implementation small enough for one implementation plan.

## Non-Goals

- External telemetry export beyond the existing metrics export endpoint.
- Alerting, thresholds, or notification routing.
- Long-term topic retention analytics beyond the existing metrics retention tiers.
- Per-consumer or per-client pub/sub metrics.
- Backend clustering or distributed aggregation.
- Redesigning the entire Houston UI.

## Architecture Options

### Option A: Extend Existing Collector And Store

Add topic metrics to the existing telemetry collector and store. Topic publish, subscribe, and unsubscribe handlers record metrics after successful storage operations. Metrics handlers expose topic overview and topic chart endpoints using the same response shapes as queue metrics.

Pros:

- one metrics pipeline
- one retention and aggregation model
- consistent queue and topic dashboard APIs
- minimal operational surface
- fits the internal-only requirement

Cons:

- the collector grows to support both queue and topic domains

### Option B: Add A Dedicated Topic Metrics Store

Create a separate topic metrics storage layer and API handler.

Pros:

- topic telemetry is isolated
- future topic-specific aggregation can evolve independently

Cons:

- duplicates retention and aggregation logic
- adds unnecessary storage and migration complexity
- makes dashboard APIs less consistent

### Option C: Derive Topic Metrics From Queues

Build pub/sub metrics by summing queue metrics for queues subscribed to a topic.

Pros:

- fewer backend write hooks
- faster to prototype

Cons:

- not first-class telemetry
- historically inaccurate when subscriptions change
- publish and delivery counts become ambiguous
- slow and complex for topic drill-downs

## Decision

Use Option A.

Topic telemetry will be recorded directly by the backend and stored through the current metrics collector/store pipeline. The dashboard will display topic metrics from topic-scoped APIs, while queue dashboards continue to use queue-scoped APIs.

## Backend Design

### Topic Metrics

Add these topic-scoped metrics:

- `plainq_topic_publish_rate`
- `plainq_topic_delivery_rate`
- `plainq_topic_messages_published_total`
- `plainq_topic_deliveries_total`
- `plainq_topic_subscriptions_current`
- `plainq_topic_subscriptions_created_total`
- `plainq_topic_subscriptions_deleted_total`

Metric identity:

- `topic_id` is the primary metric scope.
- `topic_name` may be included in labels for display, but API consumers should not depend on it for identity.
- Queue IDs remain queue metric scope and should not be overloaded as topic scope.

Recording rules:

- Publish records only after storage publish succeeds.
- Publish increments messages published by the number of input messages accepted.
- Publish increments deliveries by the delivered count returned by storage.
- Publish rates are calculated from the counters through the same rate machinery used for queue metrics.
- Subscribe records only after storage subscribe succeeds.
- Unsubscribe records only after storage unsubscribe succeeds.
- Current subscription count is updated from authoritative topic state after subscribe and unsubscribe. If fetching the count fails, counters still record the completed operation and the current gauge is skipped.
- Failed validation, missing topics, and storage errors do not emit success metrics.

### Collector Shape

Extend the collector with topic-level methods rather than pushing topic concerns into HTTP handlers:

- record topic publish
- record topic subscription created
- record topic subscription deleted
- update topic subscription count
- read topic rates
- read topic counters
- read all topic IDs known to telemetry

The collector remains responsible for in-memory current values and persistence. HTTP handlers and queue service code should call clear domain methods rather than writing raw metric names directly.

### Metrics Store

The existing metrics tables already support scoped metrics through `queue_id`. To avoid a broad schema migration, the implementation should generalize this concept at the collector boundary:

- existing queue metrics continue writing the scope value as the queue ID
- topic metrics write the scope value as the topic ID
- metric names disambiguate queue metrics from topic metrics

This keeps the implementation compatible with the existing schema while preserving first-class topic metric names. A future schema can rename the internal column to `resource_id`, but that is not needed for this feature.

### API Endpoints

Add topic endpoints parallel to existing queue endpoints:

- `GET /api/v1/metrics/topics/overview`
- `GET /api/v1/metrics/topic/{id}`
- `GET /api/v1/metrics/topic/{id}/rates`

Responses should mirror the queue metrics style:

- overview returns system-level pub/sub totals and one row per topic
- topic detail returns current publish rate, delivery rate, current subscription count, total published, total deliveries, and time range
- rates returns publish and delivery rate series for charts

Existing endpoints remain compatible.

### Telemetry Disabled Behavior

When telemetry storage is not configured, metrics routes should either remain absent as they do today or return a consistent unavailable response if mounted later. Houston must treat 404 and 503 from metrics endpoints as a non-fatal empty state:

- queue and topic management still work
- dashboard area shows that telemetry is not enabled
- charts do not enter endless loading states

## Houston UI Design

### Queue Detail Page

The queue detail page will keep its current tabs:

- Overview
- Messages
- Metrics
- Settings

The Metrics tab will mount the existing queue metrics experience after it is aligned with local conventions:

- use the shared API client path instead of direct unauthenticated fetches
- show metric cards for send rate, receive rate, delete rate, and in-flight messages
- show throughput and in-flight charts
- support time range selection and manual refresh
- keep auto-refresh opt-in or clearly controllable
- show empty and telemetry-disabled states

The route mismatch should be fixed by adding a dynamic queue detail route for `/queue/{queueId}`. The existing queue list links should continue to work.

### Pub/Sub Page

The pub/sub page will become a combined management and metrics page:

- top summary row for publish rate, delivery rate, messages published, deliveries, and active subscriptions
- chart panel for publish and delivery rate over time
- topic metrics table with topic name, publish rate, delivery rate, total published, total deliveries, active subscriptions, and last updated
- existing topic create, subscribe, unsubscribe, and publish test workflows remain available

Topic cards may include compact inline metrics, but the first implementation should prioritize a page-level dashboard and table so users can compare topics quickly.

### Shared Dashboard Behavior

Queue and pub/sub dashboards should share formatting and data transformation utilities where useful:

- time range presets
- number formatting
- rate formatting
- timestamp formatting
- Recharts payload transformation
- telemetry unavailable and empty states

This should be shared through small utilities or components, not a large dashboard framework.

## Data Flow

### Queue Metrics

Queue operation succeeds -> existing queue telemetry collector records queue metric -> metrics store persists samples -> metrics API returns overview or series -> Houston queue metrics tab renders cards and charts.

### Topic Metrics

Pub/sub operation succeeds -> queue service calls topic telemetry collector method -> collector updates current counters/rates/gauges and persists samples -> topic metrics API returns overview or series -> Houston pub/sub dashboard renders cards, charts, and topic rows.

## Error Handling

- Metrics recording is best effort and must not fail publish, subscribe, or unsubscribe requests.
- Metrics recording errors should be logged at debug or warning level depending on severity.
- Metrics API validation errors return 400 with a clear message.
- Metrics store failures return 500.
- Missing telemetry returns a non-fatal UI state.
- Empty time ranges render empty chart states instead of fake zero lines.

## Testing Strategy

Backend tests:

- topic publish success records published message count and delivered count
- subscribe success records created count and current subscription gauge
- unsubscribe success records deleted count and current subscription gauge
- failed publish/subscribe/unsubscribe does not record success metrics
- topic metrics handlers return expected summary and chart response shapes
- time range parsing and resolution selection continue to work for topic metrics

Frontend tests:

- API client exposes topic and queue metrics methods
- chart transformation maps topic publish and delivery rate series into Recharts rows
- queue detail metrics tab renders cards and empty states from fixture data
- pub/sub dashboard renders summary cards, chart empty state, and topic metric rows from fixture data

Manual verification:

- create a queue
- open `/queue/{queueId}` and confirm the metrics tab loads
- create a topic
- subscribe the queue to the topic
- publish test messages
- confirm topic metrics change on the pub/sub page
- confirm queue metrics remain queue-specific
- run production build for Houston
- run relevant Go tests

## Scope Boundaries

The first implementation should include:

- topic metrics recording
- topic metrics API endpoints
- queue detail metrics tab
- pub/sub metrics dashboard
- route fix for queue detail
- tests around new telemetry and UI data behavior

The first implementation should defer:

- alert rules
- topic-specific export UI
- per-subscription drill-down charts
- historical subscription membership reconstruction
- full visual redesign of Houston

## Spec Self-Review

- Placeholder scan: no placeholders remain.
- Internal consistency: topic metrics are recorded first-class and remain separate from queue metrics.
- Scope check: this is a single implementation plan spanning backend telemetry APIs and the two requested Houston pages.
- Ambiguity check: topic publish and subscription metrics have explicit recording rules, endpoint names, and UI surfaces.
