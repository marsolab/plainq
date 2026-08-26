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

These rules hold everywhere:

- **Flags may go before or after the positional arguments.**
  `plainq send -message=hi <queue-id>` and `plainq send <queue-id> -message=hi`
  do the same thing.
- Flags accept `-flag value` and `-flag=value`, with one or two leading dashes.
- Errors go to **stderr**; stdout carries only command output, so `--json` is
  always safe to parse.
- Nothing prompts for confirmation. Every command except `tui` is safe to run
  unattended; `tui` needs a terminal and runs until quit, and is the only
  command marked `"interactive": true` in `plainq schema -target=cli`.
- `--json` output is protobuf JSON: zero-valued fields are omitted, 64-bit
  integers are quoted strings, and byte fields such as a message body are
  base64.

Run any command with `-h` to see its description, arguments, flags with their
defaults, and worked examples:

```shell
./plainq create -h
```

### Server address

`--grpc.addr` is resolved in this order, first match wins:

1. the `--grpc.addr` flag
2. the `PLAINQ_ADDR` environment variable
3. the current [context](#contexts)
4. `localhost:8080`

### Exit codes

| Code | Meaning                                                                 |
| ---- | ----------------------------------------------------------------------- |
| `0`  | Success.                                                                |
| `1`  | The command ran but failed: server unreachable, queue not found, request rejected. |
| `2`  | Usage error: unknown flag, missing or malformed argument. Retrying unchanged will not help. |

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
├── topic          Manage stable queue-backed publish/subscribe
│   ├── list       List topics and subscriptions
│   ├── create     Create a uniquely named topic
│   ├── delete     Delete a topic and its subscriptions
│   ├── subscribe  Subscribe an existing queue
│   ├── unsubscribe Remove a subscription
│   └── publish    Fan a batch out to every subscribed queue
├── cluster        Inspect and administer the cluster
│   ├── status     Show this node's view of the cluster
│   ├── members    List cluster members
│   ├── join       Add a node to the cluster
│   ├── leave      Remove a node from the cluster
│   └── snapshot   Force a state snapshot
├── tui            Launch the interactive terminal UI
└── schema         Print the CLI and gRPC surfaces (text or --json)
```

Each command is classified by what running it does to server state —
`read-only`, `mutating`, or `destructive` — and the classification appears in
its `-h` output and in `plainq schema -target=cli`. The destructive ones
(`purge`, `delete`, `delete-message`, `cluster leave`) take effect immediately,
with no confirmation prompt.

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
plainq receive -batch=10 -json "$QID" | jq -r '.messages[].id'
```

Text output is one `<message-id>\t<body>` line per message, which assumes bodies
contain no tabs or newlines. Use `-json` for bodies that might — but remember
that a body is *bytes*, so JSON carries it base64-encoded:

```shell
plainq receive -batch=10 -json "$QID" | jq -r '.messages[].body | @base64d'
```

Receiving from an empty queue is not an error: it prints nothing and exits `0`.

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

## Publish/subscribe

The stable `topic` group uses the same gRPC address and JSON flags as the queue
commands. Topic IDs, queue IDs, and subscription IDs are 20-character XIDs.
Topic names must be nonblank and unique. Flags can appear before or after the
positional arguments.

### `plainq topic list`

```shell
plainq topic list [--json]
```

Text output is one `<topic-id> | <topic-name>` line. `--json` includes each
topic's complete subscription objects and timestamps, which is how scripts find
the subscription ID required by `unsubscribe`.

### `plainq topic create`

```shell
TID=$(plainq topic create <topic-name>)
```

Prints the new topic ID. With `--json`, the response is
`{"topicId":"..."}`.

### `plainq topic delete`

```shell
plainq topic delete <topic-id>
```

Deletes the topic and all of its subscriptions, but never deletes the queues or
messages already delivered to them. Text output is `deleted<TAB><topic-id>`.

### `plainq topic subscribe`

```shell
SID=$(plainq topic subscribe <topic-id> <queue-id>)
```

The queue must already exist. A queue may have only one subscription to a given
topic. Text output is the new subscription ID.

### `plainq topic unsubscribe`

```shell
plainq topic unsubscribe <topic-id> <subscription-id>
```

Stops future deliveries through that subscription. Existing queue messages stay
available. Text output is `unsubscribed<TAB><subscription-id>`.

### `plainq topic publish`

```shell
plainq topic publish -message='{"order_id":42}' <topic-id>
plainq topic publish -message=one -message=two <topic-id>
plainq topic publish -file=messages.ndjson <topic-id>
generate-events | plainq topic publish -file=- <topic-id>
```

At least one body is required. Repeat `--message`, use a newline-delimited
`--file`, or combine both. Empty file lines are ignored, each non-empty line is
one message, and stdin is read only when `--file=-` is explicit. Text output is
`delivered<TAB><count>`; `--json` returns the stable protobuf JSON response.

Publishing to a topic with no subscribers succeeds with zero deliveries. With
subscribers, PlainQ synchronously attempts the complete batch for every selected
queue. The operation is not atomic across queues: a nonzero exit can still mean
some queues retained copies, so an unchanged retry can create duplicates.

A complete CLI-first flow is:

```shell
QA=$(plainq create email-workers)
QB=$(plainq create analytics-workers)
TID=$(plainq topic create signups)
plainq topic subscribe "$TID" "$QA"
plainq topic subscribe "$TID" "$QB"
plainq topic publish -message='{"user":42}' "$TID"
plainq receive -batch=10 "$QA"
plainq delete-message "$QA" <message-id>
```

All six leaves use the normal exit codes: `0` success, `1` an attempted command
failed, and `2` invalid flags, arity, IDs, or publish input. Treat an exit `1`
from `publish` as a possibly partial delivery, not proof that nothing happened.

## Introspection

### `schema` — describe PlainQ to a program

```shell
plainq schema                   # both surfaces, human-readable
plainq schema -json             # both surfaces, machine-readable
plainq schema -target=cli       # just the command line
plainq schema -target=grpc      # just the gRPC API
```

Two surfaces, from one command:

- **`cli`** — every command with its call signature, positional arguments,
  flags (type, default, usage), effect classification, worked examples, the
  global conventions, and the exit-code contract.
- **`grpc`** — every gRPC service and method with its input and output message
  names, read straight from the embedded protobuf descriptor.

Neither needs a running server or any configuration, which makes `schema` the
right first call when you are working out how to drive PlainQ:

```shell
# Which commands change state? (recurse to reach nested subcommands)
plainq schema -target=cli -json \
  | jq -r '.cli.commands[] | recurse(.subcommands[]?) | select(.effect != "read-only") | .path'

# What flags does send take?
plainq schema -target=cli -json \
  | jq -r '.cli.commands[] | select(.name == "send") | .flags[] | "\(.name) \(.type) = \(.default)"'
```

See [Driving PlainQ from an agent](agents.md) for the full discovery loop.

### `tui` — interactive terminal UI

```shell
plainq tui -grpc.addr localhost:8080
```

Opens the [Bubble Tea TUI](tui.md) to browse queues and send/receive messages
interactively.

## Contexts

A context is a named server endpoint, saved so you don't repeat `--grpc.addr`.
The current context supplies the default for every client command.

```shell
plainq ctx init          # create the context file
plainq ctx list          # show current + available contexts
plainq ctx list -json    # ...machine-readably
```

The file lives at `~/.config/plainq/context.json` on every platform; set
`PLAINQ_CONTEXT_FILE` to put it somewhere else (useful in containers and CI,
where there may be no writable home directory).

> Context support is still minimal: `init` writes a single `default` context
> and `list` shows what is there. Adding or switching contexts means editing the
> JSON file. For a one-off override, `PLAINQ_ADDR` or `--grpc.addr` is simpler.

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
