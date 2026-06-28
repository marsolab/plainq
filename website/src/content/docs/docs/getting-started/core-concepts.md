---
title: Core concepts
description: The model behind PlainQ — queues, messages, the message lifecycle, and the four knobs that govern it.
sidebar:
  order: 3
---

This page explains the model behind PlainQ: what a queue is, what happens to a
message from send to acknowledgment, and the knobs that govern its lifecycle.
Read it once and the rest of the docs will click into place.

## Queues

A **queue** is a named, durable collection of messages. Each queue has:

- a **name** (what you pass to `plainq create`), and
- an immutable **queue ID** — an [XID](https://github.com/rs/xid) like
  `cf9k2m3p8q1r4s5t6u7v`, returned when the queue is created. Most CLI and API
  operations take the **ID**, not the name.

Queues are independent: messages in one queue never appear in another (the one
exception is a [dead-letter queue](#eviction-and-dead-letter-queues), which is
just another queue you nominate). Internally each queue is backed by its own
storage table, which keeps queues isolated and makes purging and deleting cheap.

## Messages

A **message** is an opaque blob of bytes plus a generated message ID. PlainQ
does not inspect, parse, or transform the body — JSON, protobuf, plain text,
compressed bytes, it's all the same to the server. Keep messages reasonably
small and put large payloads in object storage with a pointer in the message.

## The message lifecycle

PlainQ implements the classic **competing-consumers** queue with at-least-once
delivery:

```
   Send                 Receive                    Delete
    │                     │                          │
    ▼                     ▼                          ▼
 ┌──────┐   visible   ┌───────────┐  timeout    ┌──────────┐
 │ NEW  │ ──────────▶ │ IN-FLIGHT │ ──────────▶ │ VISIBLE  │ ──▶ (loop)
 └──────┘             └───────────┘ (not acked) └──────────┘
                           │
                           │ Delete (ack)
                           ▼
                       ┌─────────┐
                       │ REMOVED │
                       └─────────┘
```

1. **Send.** A producer enqueues a message. It is immediately visible.
2. **Receive.** A consumer requests a batch. Each returned message is made
   **invisible** for the queue's _visibility timeout_, and its _receive count_
   is incremented. While invisible, no other consumer can receive it.
3. **Process.** The consumer does its work.
4. **Delete (acknowledge).** The consumer deletes the message by ID. This is the
   acknowledgment — the message is gone for good.

If step 4 never happens (the consumer crashed, timed out, or simply didn't
delete), the visibility timeout expires and the message becomes **visible
again**, ready to be redelivered. That's what "at-least-once" means: a message
is delivered until someone acknowledges it.

:::note
The CLI's `plainq receive` intentionally does **not** auto-delete (unless you
pass `-ack`). That's why running it twice within the visibility window hides the
message, and running it again after the window returns the same message. Real
consumers call `Delete` after successful processing.
:::

### Ordering

Within a single queue, messages are delivered in **FIFO order** by creation time
(`ORDER BY created_at`). This is best-effort FIFO, not a strict global total
order guarantee across concurrent producers, and redelivered messages naturally
move later in time. There is **no deduplication** — sending the same body twice
creates two independent messages.

## The four lifecycle knobs

Every queue is configured with four settings at creation time. They are the
heart of PlainQ's behavior.

| Setting              | CLI flag                 | Default   | Controls                                                  |
| -------------------- | ------------------------ | --------- | --------------------------------------------------------- |
| Visibility timeout   | `-visibility-timeout`    | `30` (s)  | How long a received message stays invisible.              |
| Max receive attempts | `-max-receive-attempts`  | `5`       | How many times a message can be received before eviction. |
| Retention period     | `-retention-period`      | `7 days`¹ | How long a message can live before eviction.              |
| Eviction policy      | `-drop-policy`           | `drop`    | What happens on eviction: drop, or dead-letter.           |

¹ The CLI passes `0` for retention by default, which the server interprets as
its built-in default of **7 days** (604,800 seconds).

### Visibility timeout

The window a message is hidden after being received. Set it to comfortably
exceed your processing time:

- **Too short** → the message reappears and gets processed twice while the first
  worker is still busy.
- **Too long** → if a worker dies, the message sits invisible for a long time
  before another worker can retry it.

### Max receive attempts

A _poison message_ — one that always fails processing — would otherwise loop
forever. Each receive bumps the message's retry counter; once it exceeds
`max_receive_attempts`, the message becomes eligible for **eviction**.

### Retention period

An upper bound on a message's lifetime regardless of retries. After
`created_at + retention_period`, the message becomes eligible for eviction even
if it was never received. Use it to keep stale data from accumulating.

### Eviction and dead-letter queues

When a message exceeds its retry budget _or_ its retention period, the
**eviction policy** decides its fate:

- **`drop`** (default) — the message is permanently deleted.
- **`dead-letter`** — the message is moved to another queue you nominate with
  `-dead-letter-queue-id`. This lets you inspect, alert on, and replay failures
  instead of losing them silently.

## Next steps

- [Queues & messages](/docs/guides/cli/) — work with queues from the CLI.
- [Configuration](/docs/guides/configuration/) — server-level tuning.
