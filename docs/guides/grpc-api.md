# gRPC API guide

The gRPC API is PlainQ's canonical wire protocol. The CLI is a thin client over
it, and you can generate a client in any gRPC-supported language.

- **Schema source:** [`schema/v1/schema.proto`](../../schema/v1/schema.proto)
- **Buf Schema Registry:** [`buf.build/plainq/schema`](https://buf.build/plainq/schema)
- **Default address:** `localhost:8080`
- **Service:** `v1.PlainQService`

## The service

`PlainQService` exposes eight RPCs split between queue management and messaging.

| RPC             | Kind          | Purpose                                                  |
| --------------- | ------------- | -------------------------------------------------------- |
| `ListQueues`    | Management    | Paginated queue listing with prefix + sort.              |
| `DescribeQueue` | Management    | Fetch a queue's settings by ID or name.                  |
| `CreateQueue`   | Management    | Create a queue with retention, visibility, eviction.     |
| `PurgeQueue`    | Management    | Remove every message from a queue.                       |
| `DeleteQueue`   | Management    | Delete the queue itself.                                 |
| `Send`          | Messaging     | Enqueue one or more messages.                            |
| `Receive`       | Messaging     | Dequeue a batch (1–10) with visibility semantics.        |
| `Delete`        | Messaging     | Acknowledge (remove) messages by ID.                     |

## Generating a client

The schema is published to the Buf Schema Registry, so the fastest path is to
generate against it.

**Pull a prebuilt SDK** for a supported language directly from the registry:
<https://buf.build/plainq/schema/sdks/main>.

**Or generate locally** with a `buf.gen.yaml` pointing at your plugins:

```yaml
# buf.gen.yaml
version: v2
plugins:
  - remote: buf.build/protocolbuffers/go
    out: gen
    opt: paths=source_relative
  - remote: buf.build/grpc/go
    out: gen
    opt: paths=source_relative
```

```shell
buf generate buf.build/plainq/schema
```

Swap the plugins for `python`, `ts`, `java`, etc. to target other languages.

## Message reference

### Queue settings

`CreateQueue` and `DescribeQueue` share the same settings vocabulary:

| Field                          | Type             | Notes                                                       |
| ------------------------------ | ---------------- | ----------------------------------------------------------- |
| `queue_name`                   | string           | Human-friendly name.                                        |
| `retention_period_seconds`     | uint64           | `0` → server default (7 days).                              |
| `visibility_timeout_seconds`   | uint64           | `0` → server default (30s).                                 |
| `max_receive_attempts`         | uint32           | `0` → server default (5).                                   |
| `eviction_policy`              | enum             | `DROP`, `DEAD_LETTER` (`REORDER`/`UNSPECIFIED` not implemented). |
| `dead_letter_queue_id`         | string           | Required when policy is `DEAD_LETTER`.                       |

`EvictionPolicy` enum values:

```proto
EVICTION_POLICY_UNSPECIFIED = 0;  // treated as drop; prefer an explicit value
EVICTION_POLICY_DROP        = 1;  // delete on eviction (default behavior)
EVICTION_POLICY_DEAD_LETTER = 2;  // move to dead_letter_queue_id
EVICTION_POLICY_REORDER     = 3;  // defined but NOT implemented
```

### Messaging

```proto
message SendMessage    { bytes body = 1; }
message ReceiveMessage { string id = 1; bytes body = 2; }
```

- `Send` takes a `repeated SendMessage` — batch as many as you like in one call —
  and returns the list of generated `message_ids`.
- `Receive` takes a `batch_size` of 1–10 (`0` becomes `1`) and returns up to that
  many `ReceiveMessage`s.
- `Delete` takes a `repeated string message_ids` and returns `successful` and
  `failed` lists (`failed` entries carry a per-message error).

## End-to-end example (Go)

Using the bundled client at `internal/client`:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/marsolab/plainq/internal/client"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
)

func main() {
	ctx := context.Background()

	cli, err := client.New("localhost:8080")
	if err != nil {
		log.Fatal(err)
	}

	// Create a queue.
	created, err := cli.CreateQueue(ctx, &v1.CreateQueueRequest{
		QueueName:                "events",
		VisibilityTimeoutSeconds: 60,
		MaxReceiveAttempts:       3,
		EvictionPolicy:           v1.EvictionPolicy_EVICTION_POLICY_DROP,
	})
	if err != nil {
		log.Fatal(err)
	}
	qid := created.GetQueueId()

	// Send a batch.
	sent, err := cli.Send(ctx, &v1.SendRequest{
		QueueId: qid,
		Messages: []*v1.SendMessage{
			{Body: []byte(`{"event":"signup"}`)},
			{Body: []byte(`{"event":"login"}`)},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("sent:", sent.GetMessageIds())

	// Receive and acknowledge.
	recv, err := cli.Receive(ctx, &v1.ReceiveRequest{QueueId: qid, BatchSize: 10})
	if err != nil {
		log.Fatal(err)
	}

	var ids []string
	for _, m := range recv.GetMessages() {
		fmt.Printf("got %s: %s\n", m.GetId(), m.GetBody())
		ids = append(ids, m.GetId())
	}

	if len(ids) > 0 {
		if _, err := cli.Delete(ctx, &v1.DeleteRequest{QueueId: qid, MessageIds: ids}); err != nil {
			log.Fatal(err)
		}
	}
}
```

> The bundled `internal/client` package is internal to this module. From an
> external project, generate a client from the [Buf registry](https://buf.build/plainq/schema)
> and dial `PlainQServiceClient` directly — the request/response messages are
> identical.

## Pagination

`ListQueues` is cursor-paginated:

- Send `limit` (1–100, default 10) and an optional `queue_prefix`,
  `order_by` (`ID`, `NAME`, `CREATED_AT`), and `sort_by` (`ASC`, `DESC`).
- The response carries `next_cursor`, `has_more`, and `total_count`.
- Pass `next_cursor` back as `cursor` to fetch the next page; stop when
  `has_more` is false.

## Transport notes

- The bundled Go client dials with **insecure (plaintext) transport** and a 10s
  dial timeout. The gRPC port is intended to sit on a trusted network or behind a
  proxy that terminates TLS — see [Deployment](deployment.md#network-exposure).
- The gRPC surface today does not enforce the JWT auth used by the HTTP/Houston
  API. Treat `:8080` as a privileged port and restrict who can reach it.
- PlainQ registers the
  [vtprotobuf](https://github.com/planetscale/vtprotobuf) codec for faster
  marshaling; generated clients interoperate normally over standard protobuf.

## Next steps

- [Queues & messages](queues-and-messages.md) — the semantics behind the RPCs.
- [CLI guide](cli.md) — the same operations from the terminal.
- [Deployment](deployment.md) — securing the gRPC port.
</content>
