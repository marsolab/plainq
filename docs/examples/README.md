# Examples & recipes

Practical, copy-pasteable patterns for working with PlainQ. Each recipe is
self-contained; adapt the queue IDs and addresses to your setup.

- [Producer / consumer with the CLI](#producer--consumer-with-the-cli)
- [A reliable worker loop (Go)](#a-reliable-worker-loop-go)
- [Dead-letter queue with replay](#dead-letter-queue-with-replay)
- [Batch producer (Go)](#batch-producer-go)
- [Idempotent consumer](#idempotent-consumer)
- [Draining a queue with jq](#draining-a-queue-with-jq)
- [Go SDK setup](#go-sdk)

---

## Producer / consumer with the CLI

The simplest end-to-end loop, two terminals.

**Setup:**

```shell
QID=$(plainq create demo)
echo "queue: $QID"
```

**Producer:**

```shell
for i in $(seq 1 20); do
  plainq send "$QID" --message="message-$i"
done
```

**Consumer (peek):**

```shell
plainq receive "$QID" --batch=10 --json | jq -r '.messages[].id'
```

Remember: `receive` does not acknowledge. To actually remove messages you need
the `Delete` RPC — see the Go worker loop below.

---

## A reliable worker loop (Go)

The canonical consumer: receive a batch, process each message, delete only the
ones that succeeded, and let the rest redeliver.

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

	const queueID = "REPLACE_WITH_QUEUE_ID"

	for {
		if err := tick(cli, queueID); err != nil {
			log.Printf("tick: %v", err)
			time.Sleep(time.Second)
		}
	}
}

func tick(cli *client.Client, queueID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := cli.Receive(ctx, &v1.ReceiveRequest{QueueId: queueID, BatchSize: 10})
	if err != nil {
		return err
	}

	if len(resp.GetMessages()) == 0 {
		time.Sleep(500 * time.Millisecond) // idle back-off
		return nil
	}

	var acked []string
	for _, m := range resp.GetMessages() {
		if err := handle(m.GetBody()); err != nil {
			log.Printf("handle %s: %v (will redeliver)", m.GetId(), err)
			continue
		}
		acked = append(acked, m.GetId())
	}

	if len(acked) == 0 {
		return nil
	}

	del, err := cli.Delete(ctx, &v1.DeleteRequest{QueueId: queueID, MessageIds: acked})
	if err != nil {
		return err
	}
	for _, f := range del.GetFailed() {
		log.Printf("ack failed for %s: %s", f.GetMessageId(), f.GetError())
	}
	return nil
}

func handle(body []byte) error {
	// Your idempotent work here.
	return nil
}
```

---

## Dead-letter queue with replay

Route failures to a DLQ, then replay them after fixing the root cause.

**Create the queues:**

```shell
DLQ=$(plainq create orders-dlq)
plainq create orders \
  --max-receive-attempts=3 \
  --visibility-timeout=60 \
  --drop-policy=dead-letter \
  --dead-letter-queue-id="$DLQ"
```

A message that fails processing 3 times in `orders` is moved to `orders-dlq` by
the next GC sweep.

**Inspect the DLQ:**

```shell
plainq receive "$DLQ" --batch=10 --json | jq -r '.messages[] | .body | @base64d'
```

**Replay (Go):** receive from the DLQ, re-send to the work queue, and delete
from the DLQ once the re-send succeeds.

```go
recv, _ := cli.Receive(ctx, &v1.ReceiveRequest{QueueId: dlqID, BatchSize: 10})
for _, m := range recv.GetMessages() {
	if _, err := cli.Send(ctx, &v1.SendRequest{
		QueueId:  ordersID,
		Messages: []*v1.SendMessage{{Body: m.GetBody()}},
	}); err != nil {
		continue // leave it in the DLQ to retry the replay later
	}
	cli.Delete(ctx, &v1.DeleteRequest{QueueId: dlqID, MessageIds: []string{m.GetId()}})
}
```

---

## Batch producer (Go)

The gRPC `Send` accepts many messages per call — far more efficient than one
call per message.

```go
msgs := make([]*v1.SendMessage, 0, 100)
for i := 0; i < 100; i++ {
	msgs = append(msgs, &v1.SendMessage{Body: []byte(fmt.Sprintf("event-%d", i))})
}

resp, err := cli.Send(ctx, &v1.SendRequest{QueueId: queueID, Messages: msgs})
if err != nil {
	log.Fatal(err)
}
log.Printf("enqueued %d messages", len(resp.GetMessageIds()))
```

---

## Idempotent consumer

Because delivery is at-least-once, the same message may arrive twice. Dedupe on a
business key so reprocessing is harmless.

```go
func handle(body []byte) error {
	var evt struct {
		ID   string `json:"id"`   // stable business key
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(body, &evt); err != nil {
		return nil // unparseable → don't retry forever; let it dead-letter/drop
	}

	// Upsert keyed on evt.ID — processing twice is a no-op.
	return db.Exec(ctx,
		`INSERT INTO processed (id, kind) VALUES ($1, $2)
		 ON CONFLICT (id) DO NOTHING`,
		evt.ID, evt.Kind,
	)
}
```

Two rules of thumb:

- **Transient errors** (DB blip, timeout) → return an error, don't ack, let it
  redeliver.
- **Permanent errors** (malformed payload) → don't loop forever; either ack-and-log
  or let retries exhaust so it dead-letters.

---

## Draining a queue with jq

Pull everything currently visible and print decoded bodies:

```shell
#!/usr/bin/env bash
set -euo pipefail
QID="$1"

while :; do
  batch=$(plainq receive "$QID" --batch=10 --json)
  count=$(echo "$batch" | jq '.messages | length')
  [ "$count" -eq 0 ] && break
  echo "$batch" | jq -r '.messages[] | .body | @base64d'
done
```

> This only *reads* messages (they redeliver after the visibility timeout). To
> permanently empty a queue, use `plainq purge "$QID"`.

---

## Go SDK

Two ways to talk to PlainQ from Go:

**1. Generate a client from the Buf registry** (recommended for external
projects):

```shell
buf generate buf.build/plainq/schema
```

Then dial the generated `PlainQServiceClient` over a standard gRPC connection to
`localhost:8080`.

**2. Use the in-repo client** (`internal/client`) if you're working inside this
module. It wraps the generated client with a friendly constructor:

```go
cli, err := client.New("localhost:8080")          // 10s dial timeout, plaintext
cli, err := client.New("localhost:8080", client.WithDialTimeout(3*time.Second))
```

All request/response types are the `v1` protobuf messages documented in the
[gRPC API guide](../guides/grpc-api.md).

## Next steps

- [Queues & messages](../guides/queues-and-messages.md) — the semantics these
  recipes rely on.
- [gRPC API](../guides/grpc-api.md) — the full RPC surface.
- [CLI guide](../guides/cli.md) — every command and flag.
</content>
