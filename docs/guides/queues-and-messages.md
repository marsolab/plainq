# Queues & messages

This is the deep dive on how messages behave: visibility timeouts, retries,
retention, eviction, dead-letter queues, and the garbage-collection sweep. If
you've read [Core concepts](../getting-started/core-concepts.md), this fills in
the timing and edge cases.

## The delivery contract

PlainQ guarantees **at-least-once** delivery:

- A message you `Send` will be delivered to a consumer at least once.
- It may be delivered **more than once** (after a visibility timeout, or a
  redelivery following a crash).
- It is removed only when a consumer explicitly **deletes (acknowledges)** it.

Therefore: **make your consumers idempotent.** Design processing so that handling
the same message twice produces the same result (e.g., dedupe on a business key,
use upserts, or track processed message IDs).

## Anatomy of a message

Each stored message carries:

| Field         | Meaning                                                       |
| ------------- | ------------------------------------------------------------- |
| message ID    | Server-generated unique identifier (returned by `Send`).      |
| body          | Your opaque bytes.                                            |
| created_at    | Enqueue time; drives FIFO ordering and retention.            |
| visible_at    | The instant the message becomes receivable. Set to "now" on send; pushed into the future on each receive. |
| retries       | How many times the message has been received.                |

## Visibility timeout

When a consumer receives a message, the server sets its `visible_at` to
`now + visibility_timeout` and increments `retries`. During that window the
message is **in-flight** and invisible to every consumer.

```
t=0    Send            → visible_at = 0,  retries = 0     (visible)
t=5    Receive         → visible_at = 35, retries = 1     (in-flight, hidden)
t=5..35   ... consumer is processing ...
t=20   Delete (ack)    → message removed                 (done)
```

If the consumer never deletes:

```
t=0    Send            → visible_at = 0,  retries = 0
t=5    Receive         → visible_at = 35, retries = 1     (hidden)
t=35   (timeout)       → message visible again
t=40   Receive         → visible_at = 70, retries = 2     (redelivered)
```

**Default: 30 seconds.** Set it per queue with `--visibility-timeout`.

Tuning guidance:

- Set it to **a comfortable multiple of your p99 processing time**. If jobs take
  up to ~10s, a 30–60s timeout gives headroom.
- Too short ⇒ duplicate processing while the first worker is still running.
- Too long ⇒ slow recovery when a worker dies mid-job.

> PlainQ does not currently support extending the visibility timeout of an
> in-flight message ("heartbeating"). Choose a timeout that covers your worst-case
> processing time, or split long jobs into smaller messages.

## Retries and poison messages

A *poison message* fails every time it's processed. Without a limit it would be
redelivered forever. The `retries` counter, bumped on each receive, bounds this:

- A queue created with `--max-receive-attempts=5` allows a message to be received
  up to its limit; once it exceeds the budget it becomes **eligible for
  eviction**.
- The message isn't evicted the instant you receive it for the last time — it's
  removed (or dead-lettered) by the next [GC sweep](#garbage-collection).

**Default: 5 attempts.**

## Retention period

Retention is a hard ceiling on a message's lifetime, independent of retries.
After `created_at + retention_period`, the message is eligible for eviction even
if it was never received once. It keeps abandoned or never-consumed data from
piling up.

**Default: 7 days** (the CLI sends `0`, which the server maps to its 7-day
default). Set explicitly with `--retention-period=<seconds>`.

## Eviction policies

When a message crosses **either** threshold — retries exhausted **or** retention
exceeded — the queue's eviction policy decides what happens:

| Policy        | CLI value     | Behavior                                                      |
| ------------- | ------------- | ------------------------------------------------------------ |
| Drop          | `drop`        | Permanently delete the message. **Default.**                 |
| Dead-letter   | `dead-letter` | Move the message into the queue named by `--dead-letter-queue-id`. |

> The proto also defines `REORDER` (and an `UNSPECIFIED` zero value treated as
> drop), but only `drop` and `dead-letter` are implemented. The GC sweep rejects
> any other policy.

### Dead-letter queues

A dead-letter queue (DLQ) is just an ordinary queue you nominate as the
destination for a source queue's failures. This is the recommended pattern for
anything where losing a failed message is unacceptable — you get to inspect,
alert on, and replay it.

```shell
# 1. Create the DLQ first.
DLQ=$(plainq create payments-dlq)

# 2. Create the work queue pointing at it.
plainq create payments \
  --max-receive-attempts=3 \
  --drop-policy=dead-letter \
  --dead-letter-queue-id="$DLQ"
```

Now a payment message that fails processing 3 times is moved to `payments-dlq`
on the next GC sweep instead of being dropped. To replay, receive from the DLQ
and re-send to the work queue.

> If you set `--drop-policy=dead-letter`, you **must** provide a valid
> `--dead-letter-queue-id`. Create the DLQ before the source queue.

## Garbage collection

Eviction is performed by a background **GC sweep**, not synchronously:

- The sweeper runs on an interval (**~30 minutes** by default).
- Each pass scans queues that are due and, for each, removes messages where
  `retries` exceeds the limit **or** `created_at + retention` is in the past —
  applying the queue's eviction policy (drop or move to DLQ).
- A message that just crossed a threshold may survive until the next pass — GC is
  eventually-consistent, not instant.

The sweep interval is governed server-wide by `--storage.gc.timeout`. Leave it
at the default unless you have a specific reason to sweep more or less often.

## Batching

`Receive` returns a **batch** of 1–10 messages in one call:

- The gRPC field is `batch_size`; `0` is treated as `1`, and the documented
  maximum is `10`.
- Each message in the batch is independently made invisible and counted.
- Acknowledge each message you successfully process; leave the rest to time out
  and redeliver.

Batching amortizes round-trips and is the easy throughput win for high-volume
consumers.

## A real consumer loop

The CLI's `receive` doesn't acknowledge, so a production consumer uses the gRPC
`Delete` RPC. In Go with the bundled client:

```go
package main

import (
	"context"
	"log"
	"time"

	"github.com/marsolab/plainq/internal/client"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
)

func main() {
	cli, err := client.New("localhost:8080")
	if err != nil {
		log.Fatal(err)
	}

	const queueID = "cf9k2m3p8q1r4s5t6u7v" // from CreateQueue

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		resp, err := cli.Receive(ctx, &v1.ReceiveRequest{
			QueueId:   queueID,
			BatchSize: 10,
		})
		cancel()
		if err != nil {
			log.Printf("receive: %v", err)
			time.Sleep(time.Second)
			continue
		}

		if len(resp.GetMessages()) == 0 {
			time.Sleep(500 * time.Millisecond) // nothing to do; back off
			continue
		}

		var acked []string
		for _, msg := range resp.GetMessages() {
			if err := process(msg.GetBody()); err != nil {
				log.Printf("process %s failed: %v", msg.GetId(), err)
				continue // don't ack → message will be redelivered, retries++
			}
			acked = append(acked, msg.GetId())
		}

		if len(acked) > 0 {
			ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
			if _, err := cli.Delete(ackCtx, &v1.DeleteRequest{
				QueueId:    queueID,
				MessageIds: acked,
			}); err != nil {
				log.Printf("ack: %v", err) // not acked → will redeliver
			}
			ackCancel()
		}
	}
}

func process(body []byte) error {
	// Your idempotent work here.
	return nil
}
```

The key discipline: **only delete after successful processing.** A failed message
goes un-acked, times out, comes back, and eventually dead-letters or drops once it
exhausts its retries.

## Failure-handling cheatsheet

| Situation                                   | What to do                                                     |
| ------------------------------------------- | -------------------------------------------------------------- |
| Transient failure (network blip, lock)      | Don't ack. Let it redeliver after the visibility timeout.      |
| Permanent failure (bad payload)             | Don't ack. It'll exhaust retries and dead-letter/drop.         |
| Want to inspect failures                    | Use `--drop-policy=dead-letter` with a DLQ.                    |
| Processing longer than the visibility window | Increase `--visibility-timeout`, or split the work.           |
| Duplicate deliveries observed               | Expected at-least-once; make the consumer idempotent.         |

## Next steps

- [gRPC API](grpc-api.md) — every RPC including `Delete`.
- [Examples](../examples/README.md) — DLQ replay, worker pools, idempotency.
- [Observability](observability.md) — watch in-flight and rate metrics.
</content>
