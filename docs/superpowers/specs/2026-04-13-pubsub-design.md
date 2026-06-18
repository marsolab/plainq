# Pub/Sub Design

## Status

Approved for planning.

## Context

PlainQ currently exposes a durable queue model:

- `queue -> send -> receive -> delete`
- per-queue retention
- per-message visibility timeout
- retry and dead-letter behavior

The goal is to add first-class publish/subscribe functionality that is:

- very clear and understandable for end users
- highly performant
- storage-efficient
- simple to operate

The initial deployment target is a single broker with a single writer. The design must support both SQLite-backed local storage and PostgreSQL-backed production storage.

## Goals

- Introduce a first-class pub/sub model based on `topic`, `subscription`, `publish`, `consume`, and `ack`
- Keep the default user path simpler than Kafka while preserving durable delivery
- Avoid per-subscriber message copying and other fan-out write amplification
- Support durable subscriptions by default
- Support an additional ephemeral mode for low-latency live delivery
- Support both `pull` and `push` delivery modes without splitting the product into two systems
- Keep one consistent behavior model across `litestore` and `pgstore`

## Non-Goals

- Exactly-once delivery in v1
- Multi-broker clustering in v1
- Partitioned topics in v1
- Cross-topic transactions
- Per-subscription server-side filtering
- Log compaction semantics

## Decision Summary

- Pub/sub is a first-class API surface, not a queue compatibility layer.
- `Topic` is the append-only stream.
- `Subscription` is the durable or ephemeral read state attached to a topic.
- Durable subscriptions are the default.
- Ephemeral subscriptions exist as an optimized live-delivery mode.
- Delivery is `at-least-once`.
- `Ack` is required for durable delivery completion.
- A subscription is the fan-out boundary.
- Multiple clients attached to the same durable subscription form one shared-work consumer group.
- If users want fan-out, they create multiple subscriptions.
- Subscriptions start from `latest` by default, but the start position is configurable.
- Topic retention is governed by topic settings.
- If a durable subscription falls behind retention, it automatically resumes from the oldest retained message.
- Topics are single ordered streams by default.
- Partitioning is an advanced future extension, not part of v1.
- Storage is abstracted behind one pub/sub storage interface with `litestore` and `pgstore` implementations.

## User Model

The end-user story should be:

1. Create a topic.
2. Publish messages to the topic.
3. Create a subscription on that topic.
4. Consume with pull or push.
5. Ack when processing is complete.

The primary concepts are:

- `topic`
- `subscription`
- `publish`
- `consume`
- `ack`

Advanced users may see `offset`, but offset should not dominate the mental model.

## Why Not Fan-Out Queues

Materializing per-subscription queues would be easy to reason about internally, but it makes the publish path expensive:

- one write per subscriber
- storage volume grows with subscriber count
- delete and retention become more expensive

That shape does not fit the performance and simplicity goals. The broker should write each published message once and let each subscription track its own progress against retained topic history.

## Architecture Options

### Option A: Append-Only Topic Log Plus Subscription Cursors

Each published message is appended once to a topic log. Durable subscriptions track their own position, inflight deliveries, and ack progress.

Pros:

- cheap publish path
- low storage amplification
- simple durability model
- matches the desired user mental model
- clean support for both pull and push

Cons:

- requires explicit inflight lease bookkeeping
- retention and lag interaction must be designed carefully

### Option B: Materialized Per-Subscription Queues

Each subscription receives its own stored copy of each message.

Pros:

- simple consumer bookkeeping

Cons:

- high write amplification
- high storage amplification
- publish cost scales with subscriber count
- not aligned with the desired performance characteristics

### Option C: Separate Durable Broker And Live Broker

Durable consumers and ephemeral live consumers use separate internal systems.

Pros:

- each path can be highly optimized

Cons:

- two mental models
- two APIs or inconsistent behavior
- more operational and implementation complexity

### Recommendation

Choose Option A and include one optimization from Option C:

- one durable append-only topic engine for all retained delivery
- an in-memory fast path for ephemeral live subscribers

This preserves one product model while still allowing a low-latency ephemeral mode.

## Core Domain Model

### Topic

An append-only ordered stream of messages.

Topic settings in v1:

- name
- retention policy by time and/or size
- ordering mode set to `single_stream`
- default delivery settings where useful

Future topic settings:

- partition count
- publish dedupe window

### Subscription

A named consumer state attached to a topic.

Subscription settings:

- `type`: `durable` or `ephemeral`
- `delivery_mode`: `pull` or `push`
- `start_position`: `latest`, `earliest`, or explicit offset
- `ack_timeout`
- optional max inflight limit per consumer

Default values:

- `type = durable`
- `delivery_mode = pull` for durable subscriptions unless explicitly set otherwise
- `delivery_mode = push` for ephemeral subscriptions
- `start_position = latest`

### Consumer Attachment

Multiple clients may connect to the same durable subscription.

Rule:

- one durable subscription equals one shared-work consumer group
- one message is delivered to one attached client, not all attached clients

If users want every consumer to receive every message, they create separate subscriptions.

## Delivery Semantics

### Durable

Durable subscriptions persist read state and inflight delivery state.

Behavior:

- messages are delivered from retained topic history
- delivery completion requires explicit `ack`
- unacked messages are redelivered after lease expiry
- delivery guarantee is `at-least-once`

### Ephemeral

Ephemeral subscriptions do not persist cursor or inflight state.

Behavior:

- only connected listeners receive messages
- disconnects lose messages
- optimized for live, low-latency consumers

### Pull Vs Push

Both modes are supported on the same object model.

Defaults:

- durable subscriptions should default toward `pull`
- push is opt-in where lower latency matters
- ephemeral subscriptions are naturally best served by `push`

Rationale:

- `pull` is cheaper and simpler for durable delivery
- `pull` provides natural backpressure
- `push` improves latency but requires connection and buffer management

## Storage Model

The broker should be expressed through a storage interface rather than backend-specific service logic.

Suggested records:

- `topics`
- `topic_messages`
- `subscriptions`
- `subscription_state`
- `subscription_inflight`

### Topics

Stores topic metadata and settings.

### Topic Messages

Stores the append-only topic log.

Each record includes:

- topic identifier
- monotonically increasing topic offset
- stable message identifier
- body
- headers or attributes if supported
- publish timestamp
- optional idempotency key for future dedupe

### Subscriptions

Stores subscription metadata and static settings.

### Subscription State

Stores durable progress for a subscription.

Suggested fields:

- last acked offset
- current read head if needed
- lag statistics
- retention skip indicator and timestamp

### Subscription Inflight

Stores leased but unacked deliveries for durable subscriptions.

Suggested fields:

- subscription identifier
- topic offset
- lease owner or consumer token
- lease expiry timestamp
- delivery attempt count

## Data Flow

### Publish

1. Validate topic and publish request.
2. Append a single record to `topic_messages`.
3. Notify connected push consumers.
4. Return to the producer.

Publish cost should not depend on subscriber count.

### Durable Pull Consume

1. Select the next available offsets after the subscription cursor.
2. Create inflight lease records.
3. Return messages to the client.
4. On `ack`, delete inflight records and advance the durable cursor.
5. On lease expiry, make the messages eligible for redelivery.

### Durable Push Consume

Uses the same durable state machine as pull:

- durable read position
- inflight leases
- ack-based completion
- lease-based redelivery

The only difference is transport, not message semantics.

### Ephemeral Push Consume

1. Register connected listener.
2. Deliver newly published messages to connected listeners only.
3. Drop messages for disconnected listeners.

This mode should not modify retained durable history behavior.

## Retention And Lag

Topic retention is configured by topic settings. Retention may be expressed by:

- max age
- max retained bytes
- both

When retention removes messages that a durable subscription has not yet consumed:

- the subscription should not hard-fail by default
- it should automatically resume from the oldest still-retained offset
- the server should record that a retention skip occurred

This preserves operability without requiring manual repair for routine lag.

## Failure Model

### Delivery Guarantee

`At-least-once`.

Duplicates are allowed and clients must be able to handle them. The system should make safe consumption easier by exposing stable message IDs and leaving room for producer idempotency keys later.

### Lease And Redelivery

Each durable delivery gets a lease.

- if the client acks before lease expiry, delivery is complete
- if the client disconnects or times out, the lease expires
- expired leases become eligible for redelivery

An optional `nack` operation may be added to force immediate redelivery instead of waiting for lease expiry.

### Exactly-Once

Not part of v1.

Reason:

- broker-only exactly-once is materially more complex
- end-to-end exactly-once across downstream side effects is much more complex still
- it would complicate the core design without matching the current scope

## Ordering Model

V1 topics are single ordered streams.

Consequences:

- simple end-user story
- simple offset model
- simpler ack and lag handling
- simpler backend implementation for both SQLite and PostgreSQL

Partitioning remains a future extension for high-throughput topics and should be designed so that default single-stream topics remain unchanged.

## API Surface

Pub/sub should be a distinct service surface rather than an overload of existing queue RPCs.

Core topic operations:

- `CreateTopic`
- `DescribeTopic`
- `ListTopics`
- `DeleteTopic`

Core publish operations:

- `Publish`

Core subscription operations:

- `CreateSubscription`
- `DescribeSubscription`
- `ListSubscriptions`
- `DeleteSubscription`

Core consume operations:

- `ConsumePull`
- `ConsumePush`
- `Ack`

Optional but recommended operations:

- `Nack`
- `SeekSubscription`

## Backends

The broker engine should depend on a `pubsub.Storage` interface with two first-class implementations.

### Litestore

Purpose:

- single-binary deployment
- local durability
- simple development and small production setups

### Pgstore

Purpose:

- stronger concurrency handling
- larger retained histories
- production deployment with PostgreSQL as the primary store

Constraint:

- backend differences must not change the public product behavior

The same semantics must apply across both implementations:

- topic and subscription model
- ack and lease behavior
- retention behavior
- durable and ephemeral modes

## Integration With Existing PlainQ

The current queue implementation stores queue properties and queue messages in queue-oriented tables and uses visibility-timeout-style handling. Pub/sub should not be modeled as “queues with new names.”

Instead:

- queue functionality remains as-is
- pub/sub is introduced as a parallel first-class capability
- common server patterns, transport setup, configuration, telemetry, and storage abstractions should be reused where practical

This avoids forcing queue semantics onto topic subscriptions and keeps the new feature easier to understand.

## Recommended V1 Scope

- single ordered topics only
- durable subscriptions
- pull consumption with ack
- push consumption with the same durable semantics
- ephemeral push subscriptions
- retention by age and/or size
- auto-skip to oldest retained message on retention overrun
- storage abstraction with both `litestore` and `pgstore`
- admin APIs for topic and subscription lifecycle

## Excluded From V1

- multi-node broker clustering
- partitioned topics
- exactly-once delivery
- dead-letter topics for pub/sub unless a strong near-term requirement appears
- subscription-level filtering
- compaction

## Design Principles

- Write each published message once.
- Track subscriber progress, not subscriber copies of messages.
- Make the default user path obvious.
- Prefer one durable state machine for both pull and push.
- Treat ephemeral delivery as an optimization, not a second product.
- Keep backend choice invisible to the user.

## Open Follow-On Design Work

The implementation plan should resolve:

- protobuf schema shape for the new service
- REST surface if HTTP support is required alongside gRPC
- exact durable lease claim algorithm
- exact SQL schemas for `litestore` and `pgstore`
- telemetry counters and lag metrics
- auth and RBAC surface for topics and subscriptions
- migration strategy for enabling pub/sub in existing deployments

## Final Recommendation

Implement pub/sub as a first-class append-only topic log with durable subscription cursors, explicit ack, optional push transport, and an ephemeral fast path. Keep v1 single-broker and single-stream. Design storage once behind a shared abstraction and support both SQLite and PostgreSQL from the outset.
