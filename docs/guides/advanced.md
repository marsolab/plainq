# Advanced topics

This guide goes past the basics: pub/sub fan-out, high-throughput tuning, scaling
consumers, tuning the GC sweep, and stronger delivery guarantees. It assumes
you've read [Core concepts](../getting-started/core-concepts.md) and
[Queues & messages](queues-and-messages.md).

- [Pub/sub: topics & fan-out](#pubsub-topics--fan-out)
- [High-throughput tuning](#high-throughput-tuning)
- [Scaling consumers](#scaling-consumers)
- [Tuning the garbage-collection sweep](#tuning-the-garbage-collection-sweep)
- [Toward stronger delivery guarantees](#toward-stronger-delivery-guarantees)
- [SQLite vs PostgreSQL at scale](#sqlite-vs-postgresql-at-scale)

---

## Pub/sub: topics & fan-out

PlainQ has an **experimental** publish/subscribe layer built on top of queues. It
is exposed only over the **HTTP API** today — there is no gRPC or CLI surface for
it yet — so treat it as beta and pin to the behavior described here.

### The model

```
                         ┌──────────────▶ queue A ──▶ consumer group A
   publish ──▶  topic ───┤
                         └──────────────▶ queue B ──▶ consumer group B
```

- A **topic** is a named fan-out point.
- A **subscription** binds an **existing queue** to a topic.
- **Publishing** a message to a topic writes a copy into **every subscribed
  queue**. Each queue is then consumed with the normal
  [at-least-once semantics](queues-and-messages.md#the-delivery-contract) —
  receive, process, delete.

This gives you fan-out (one publish, many independent consumers) while reusing
everything you already know about queues: visibility timeouts, retries,
retention, and dead-letter all apply per subscribed queue. Multiple consumers
draining the same queue form a competing-consumers group; multiple queues
subscribed to the same topic each get their own copy.

### HTTP API

All routes live under the HTTP listener at `/api/v1/queue/topics`. Bodies are
JSON; message bodies are bytes and are **base64-encoded** in JSON.

| Method & path                                                           | Purpose                                   |
| ----------------------------------------------------------------------- | ----------------------------------------- |
| `GET /api/v1/queue/topics/`                                             | List topics and their subscriptions.      |
| `POST /api/v1/queue/topics/`                                            | Create a topic (`{"topicName": "..."}`).  |
| `DELETE /api/v1/queue/topics/{topicID}`                                 | Delete a topic.                           |
| `POST /api/v1/queue/topics/{topicID}/subscriptions`                     | Subscribe a queue (`{"queueId": "..."}`). |
| `DELETE /api/v1/queue/topics/{topicID}/subscriptions/{subscriptionID}`  | Unsubscribe a queue.                       |
| `POST /api/v1/queue/topics/{topicID}/publish`                           | Publish messages (fan-out).               |

### Worked example

```shell
BASE=http://localhost:8081/api/v1/queue

# 1. Create two queues (via gRPC/CLI) that will receive the fan-out.
QA=$(plainq create emails)
QB=$(plainq create analytics)

# 2. Create a topic.
TID=$(curl -sX POST "$BASE/topics/" \
  -H 'content-type: application/json' \
  -d '{"topicName":"signups"}' | jq -r .topicId)

# 3. Subscribe both queues to the topic.
curl -sX POST "$BASE/topics/$TID/subscriptions" \
  -H 'content-type: application/json' -d "{\"queueId\":\"$QA\"}"
curl -sX POST "$BASE/topics/$TID/subscriptions" \
  -H 'content-type: application/json' -d "{\"queueId\":\"$QB\"}"

# 4. Publish — the message lands in BOTH emails and analytics.
#    Body is base64: echo -n '{"user":42}' | base64  →  eyJ1c2VyIjo0Mn0=
curl -sX POST "$BASE/topics/$TID/publish" \
  -H 'content-type: application/json' \
  -d '{"messages":[{"body":"eyJ1c2VyIjo0Mn0="}]}' | jq
```

The publish response reports the fan-out:

```json
{
  "topicId": "…",
  "queueIds": ["<emails-id>", "<analytics-id>"],
  "messageIds": ["…", "…"],
  "deliveredCount": 2
}
```

Consume each queue independently with the usual `receive` + delete loop (see the
[worker loop example](../examples/README.md#a-reliable-worker-loop-go)).

> Because publish fans out by **copying** into each subscribed queue, delivery
> cost scales with the number of subscriptions. The
> [pub/sub design spec](../superpowers/specs/2026-04-13-pubsub-design.md) tracks
> the roadmap (durable vs ephemeral subscriptions, push delivery, ordering
> guarantees); the current HTTP surface is the minimal first cut.

> The HTTP API is **not auth-gated at the server** today — keep the topics API on
> a trusted network. See
> [Deployment → network exposure](deployment.md#network-exposure).

---

## High-throughput tuning

A few levers move the needle most:

1. **Batch on both sides.** `Send` accepts many messages per call and `Receive`
   returns up to 10 per call. Batching amortizes round-trips — it's the single
   biggest throughput win. See the
   [batch producer](../examples/README.md#batch-producer-go) example.

2. **Size the visibility timeout to your p99 processing time.** Too short causes
   duplicate work under load (messages reappear while still being processed); too
   long slows recovery. Measure, then set
   [`--visibility-timeout`](queues-and-messages.md#visibility-timeout) with
   headroom.

3. **Run multiple consumers.** Several workers draining one queue form a
   competing-consumers group — each message goes to one worker at a time because
   receiving hides it. Add workers to scale read throughput.

4. **Use WAL on SQLite.** `--storage.journal-mode=wal` markedly improves
   concurrent read/write performance for the embedded backend.

5. **Keep messages small.** PlainQ stores bodies as-is. For large payloads, put
   the blob in object storage and enqueue a pointer.

---

## Scaling consumers

The receive-hide-delete model makes horizontal consumer scaling straightforward:

```
            ┌─▶ worker 1 ─┐
 queue ─────┼─▶ worker 2 ─┼─▶ each message handled by exactly one worker at a time
            └─▶ worker 3 ─┘
```

- Each `Receive` hides the returned messages for the visibility window, so two
  workers won't get the same message simultaneously.
- A message only returns to the pool if its worker fails to delete it (crash,
  timeout) — then another worker picks it up.
- Scale **out** by adding workers; scale **per-worker** by increasing batch size.

Watch the [in-flight and receive-vs-delete metrics](observability.md#what-to-watch)
to know when consumers are falling behind.

---

## Tuning the garbage-collection sweep

Eviction (drop / dead-letter on exhausted retries or expired retention) is done
by a background sweep, governed by `--storage.gc.timeout` (default ~30 min).

- **Lower it** (e.g. `5m`) if you want poison messages dead-lettered and stale
  messages reclaimed sooner — at the cost of more frequent sweep work.
- **Raise it** if your queues are huge and you'd rather sweep less often.
- Remember eviction is **eventually consistent**: a message that just crossed a
  threshold lingers until the next sweep. Don't design around instant eviction.

Telemetry has its own independent GC (`--telemetry.sqlite.gc.timeout`) and
retention (`--telemetry.sqlite.retention.period`) — see
[Observability](observability.md#telemetry--houston-dashboards).

---

## Toward stronger delivery guarantees

PlainQ is **at-least-once**. You can't get exactly-once from the broker, but you
can make duplicates harmless and rare:

- **Idempotent consumers.** Dedupe on a business key (upsert, or a processed-IDs
  table). This is the load-bearing technique — see the
  [idempotent consumer](../examples/README.md#idempotent-consumer) example.
- **Right-size the visibility timeout** so a slow worker doesn't trigger a
  duplicate mid-process.
- **Delete only after success.** Acknowledge (delete) a message strictly after
  its side effects have committed, so a crash before commit safely redelivers.
- **Dead-letter poison messages** rather than letting them loop — see
  [dead-letter queues](queues-and-messages.md#dead-letter-queues).

---

## SQLite vs PostgreSQL at scale

| Dimension                | SQLite (default)                              | PostgreSQL                                   |
| ------------------------ | --------------------------------------------- | -------------------------------------------- |
| Topology                 | Single node, one embedded file.               | Shared backend many instances can reach.     |
| Concurrency              | Single writer; WAL helps readers.             | Full MVCC concurrency.                        |
| Horizontal server scale  | One server process owns the file.             | Multiple PlainQ instances share one dataset.  |
| Durability / backup      | File-level; pairs with [Litestream](deployment.md#sqlite--litestream). | Your standard PostgreSQL backup tooling.     |
| Best for                 | Local dev, edge, single-node services.        | Multi-instance / shared-backend deployments.  |

Rule of thumb: **start on SQLite + WAL**, and move to PostgreSQL only when you
genuinely need multiple server instances sharing one dataset. The queue model and
every semantic in these docs are identical on both backends.

## Next steps

- [Queues & messages](queues-and-messages.md) — the lifecycle these patterns build on.
- [Observability](observability.md) — the signals that tell you when to scale or tune.
- [Deployment](deployment.md) — running and securing it all.
</content>
