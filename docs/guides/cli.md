# CLI guide

The `plainq` binary is both the **server** and the **client**. The server lives
behind `plainq serve`; every other command is a client that talks to a running
server over gRPC.

This guide covers the client commands. For server flags see
[Configuration](configuration.md); for a terse lookup table see the
[CLI reference](../reference/cli.md).

## Conventions

Every client command accepts two common flags:

| Flag          | Default            | Meaning                                              |
| ------------- | ------------------ | ---------------------------------------------------- |
| `--grpc.addr` | `localhost:8080`   | Address of the PlainQ gRPC server.                   |
| `--json`      | `false`            | Emit the raw gRPC response as JSON instead of text.  |

`--json` is what you want for scripting — it gives you stable, parseable output
you can pipe into `jq`.

Run any command with `-h` to see its flags:

```shell
./plainq create -h
```

## Command map

```
plainq
├── serve          Run the server (see Configuration guide)
├── version        Print build branch, commit, and time
├── ctx            Manage local client contexts
│   ├── init       Create a context config file
│   └── list       Show configured contexts
├── list           List queues
├── create         Create a queue
├── describe       Describe a queue by ID
├── purge          Delete all messages in a queue
├── delete         Delete a queue
├── send           Send one or more messages to a queue
├── receive        Receive messages from a queue
├── delete-message Acknowledge (delete) messages by ID
├── tui            Launch the interactive terminal UI
└── schema         Print the gRPC API surface (text or --json)
```

> **Flag ordering.** Client commands take their flags **before** the positional
> queue id, e.g. `plainq send -message hi <queue-id>` (not
> `plainq send <queue-id> -message hi`). Flags placed after the positional
> argument are ignored.

## Queue management

### `create` — create a queue

```shell
plainq create <queue-name> [flags]
```

Prints the new **queue ID** on success (or the full response with `--json`).

| Flag                       | Default   | Purpose                                                            |
| -------------------------- | --------- | ------------------------------------------------------------------ |
| `--visibility-timeout`     | `30`      | Seconds a received message stays invisible.                        |
| `--max-receive-attempts`   | `5`       | Receives allowed before a message is evicted.                      |
| `--retention-period`       | `0`       | Seconds before a message expires. `0` → server default (7 days).   |
| `--drop-policy`            | `drop`    | Eviction policy: `drop` or `dead-letter`.                          |
| `--dead-letter-queue-id`   | _(empty)_ | Target queue when `--drop-policy=dead-letter`.                     |

Examples:

```shell
# Simple queue with defaults.
QID=$(plainq create orders)

# A queue tuned for slow jobs that dead-letters failures.
DLQ=$(plainq create orders-dlq)
plainq create orders \
  --visibility-timeout=300 \
  --max-receive-attempts=3 \
  --drop-policy=dead-letter \
  --dead-letter-queue-id="$DLQ"
```

### `list` — list queues

```shell
plainq list [--limit N] [--json]
```

Prints one `queue-id | queue-name` per line. `--limit` sets the page size
(default 500).

```shell
plainq list
plainq list --json | jq -r '.queues[].queueName'
```

### `describe` — inspect a queue

```shell
plainq describe <queue-id> [--json]
```

Returns the queue's settings: retention, visibility timeout, max receive
attempts, eviction policy, and dead-letter target. Use `--json` to read the
fields programmatically — the human-readable output is minimal.

```shell
plainq describe "$QID" --json | jq
```

### `purge` — empty a queue

```shell
plainq purge <queue-id>
```

Deletes **all messages** from the queue but keeps the queue itself. With
`--json`, the response includes the number of messages removed. There is no
confirmation prompt — purge is immediate.

### `delete` — remove a queue

```shell
plainq delete <queue-id> [--force]
```

Deletes the queue itself. By default a non-empty queue is protected; pass
`--force` to delete a queue that still holds messages.

## Messaging

### `send` — enqueue one or more messages

```shell
plainq send -message='...' <queue-id>
```

Prints the new message ID(s), one per line (or the full response with `-json`).
You can send a **batch** in a single call:

```shell
# Repeat -message to batch several bodies.
plainq send -message='{"order_id":42}' -message='{"order_id":43}' "$QID"

# Read newline-delimited bodies from a file...
plainq send -file=payloads.ndjson "$QID"

# ...or from stdin ("-").
generate-events | plainq send -file=- "$QID"
```

Each non-empty line of a `-file` source becomes one message. Bodies are sent
verbatim as bytes.

### `receive` — dequeue messages

```shell
plainq receive -batch=N [-ack] [-json] <queue-id>
```

Receives up to `-batch` messages (default 1; the server caps a batch at 10).
Each received message is hidden for the queue's visibility timeout and its retry
counter is incremented.

```shell
plainq receive "$QID"
plainq receive -batch=10 -json "$QID" | jq '.messages[].id'
```

By default `receive` does **not** delete — delivery is at-least-once. Two ways
to acknowledge:

- `-ack` deletes each received message right after printing it (handy for
  draining a queue in scripts):

  ```shell
  plainq receive -batch=10 -ack "$QID"
  ```

- `delete-message` acknowledges specific IDs (e.g. after your worker finishes):

  ```shell
  plainq delete-message "$QID" <message-id> [<message-id>...]
  ```

### `delete-message` — acknowledge messages

```shell
plainq delete-message <queue-id> <message-id> [<message-id>...]
```

Deletes (acknowledges) the given messages so they are not redelivered. Text
output prints `deleted\t<id>` per success and `failed\t<id>\t<error>` per
failure; `-json` returns the full `DeleteResponse`.

## Introspection

### `schema` — print the gRPC API surface

```shell
plainq schema          # human-readable
plainq schema -json    # machine-readable, for AI agents and codegen
```

Lists every gRPC service and method (with input/output message names) straight
from the embedded protobuf descriptor — no network call required.

### `tui` — interactive terminal UI

```shell
plainq tui -grpc.addr localhost:8080
```

Opens the [Bubble Tea TUI](tui.md) to browse queues and send/receive messages
interactively.

## Contexts

Contexts let you save named server endpoints so you don't repeat `--grpc.addr`.

```shell
plainq ctx init    # create the context config file
plainq ctx list    # show current + available contexts
```

> Context support is early. `ctx init`/`list` currently target a
> macOS config path (`~/.config/plainq/context.json`) and the saved endpoint is
> not yet auto-applied to client commands — keep using `--grpc.addr` for now on
> all platforms. Track this in the project's issues if you depend on it.

## Scripting patterns

**Create, send, drain — fully scripted:**

```shell
#!/usr/bin/env bash
set -euo pipefail

ADDR="${PLAINQ_ADDR:-localhost:8080}"
QID=$(plainq create -grpc.addr="$ADDR" jobs)

# Batch all 100 jobs into a single send via stdin.
for i in $(seq 1 100); do echo "job-$i"; done \
  | plainq send -grpc.addr="$ADDR" -file=- "$QID" >/dev/null

echo "Enqueued 100 jobs to $QID"
plainq describe -grpc.addr="$ADDR" -json "$QID" | jq
```

**Pull a batch and extract IDs:**

```shell
plainq receive -batch=10 -json "$QID" \
  | jq -r '.messages[] | "\(.id)\t\(.body | @base64d)"'
```

> Message bodies are bytes; in JSON output they are base64-encoded. Decode with
> `@base64d` in `jq` (as above) or your language's base64 decoder.

## Exit codes

On error, the CLI prints the error and exits with status **2**. On success it
exits **0**. Check `$?` in scripts, or rely on `set -e`.

## Next steps

- [Queues & messages](queues-and-messages.md) — the behavior behind the commands.
- [gRPC API](grpc-api.md) — for batched sends and message acknowledgment.
- [CLI reference](../reference/cli.md) — quick-lookup tables.
</content>
