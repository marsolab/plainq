---
title: CLI guide
description: Every PlainQ command and the flags you'll actually use.
sidebar:
  order: 1
---

The `plainq` binary is both the server and the client. Every client command
talks gRPC and accepts `-grpc.addr` (default `localhost:8080`) and `-json` for
machine-readable output.

:::tip
**Flags may go before or after the positional arguments.**
`plainq send -message hi <queue-id>` and `plainq send <queue-id> -message hi`
are the same command. Both `-flag value` and `-flag=value` work, with one or two
leading dashes.
:::

## Commands

| Command                                    | Description                                                                                                                                                       |
| ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `plainq serve`                             | Run the PlainQ server (gRPC + HTTP + Houston UI).                                                                                                                |
| `plainq version`                           | Print the build version, commit, and build time.                                                                                                                |
| `plainq ctx`                               | Manage local client contexts.                                                                                                                                   |
| `plainq list`                              | List queues.                                                                                                                                                    |
| `plainq create <queue-name>`               | Create a queue. Supports `-retention-period`, `-visibility-timeout`, `-max-receive-attempts`, `-drop-policy` (`drop` or `dead-letter`), `-dead-letter-queue-id`. |
| `plainq describe <queue-id>`               | Describe a queue.                                                                                                                                               |
| `plainq purge <queue-id>`                  | Delete all messages from a queue.                                                                                                                               |
| `plainq delete <queue-id>`                 | Delete a queue (`-force` to skip safety checks).                                                                                                                |
| `plainq send <queue-id>`                   | Send one or more messages (`-message=...` repeatable, or `-file=-` for stdin).                                                                                  |
| `plainq receive <queue-id>`                | Receive messages (`-batch=N` up to 10, `-ack` to delete after read).                                                                                            |
| `plainq delete-message <queue-id> <id>...` | Acknowledge (delete) messages by ID.                                                                                                                            |
| `plainq topic list`                        | List topics and subscription objects.                                                                                                                          |
| `plainq topic create <name>`               | Create a uniquely named topic.                                                                                                                                 |
| `plainq topic delete <topic-id>`            | Delete a topic and its subscriptions.                                                                                                                          |
| `plainq topic subscribe <topic-id> <queue-id>` | Subscribe an existing queue.                                                                                                                               |
| `plainq topic unsubscribe <topic-id> <subscription-id>` | Remove a subscription.                                                                                                                     |
| `plainq topic publish <topic-id>`           | Fan a batch out to all subscribed queues.                                                                                                                      |
| `plainq tui`                               | Launch the interactive terminal UI.                                                                                                                             |
| `plainq schema`                            | Print the CLI and gRPC surfaces (`-target=all\|cli\|grpc`, text or `-json`).                                                                                    |

Run any command with `-h` for its description, arguments, flags with their
defaults, worked examples, and exit codes.

Commands exit `0` on success, `1` when the command ran but failed, and `2` on a
usage error. Errors go to stderr, so `-json` output on stdout is always
parseable.

## Everyday recipes

### Create a queue with a dead-letter policy

Durations are given as whole seconds.

```shell
DLQ=$(plainq create my-queue-dlq)
plainq create \
  -visibility-timeout=30 \
  -max-receive-attempts=5 \
  -drop-policy=dead-letter \
  -dead-letter-queue-id="$DLQ" \
  my-queue
```

### Send messages

```shell
# One or more inline messages
plainq send -message='hello' -message='world' "$QID"

# From stdin
cat payload.json | plainq send -file=- "$QID"
```

### Receive and acknowledge

```shell
# Receive a batch of up to 10 and delete them on read
plainq receive -batch=10 -ack "$QID"

# Receive without acking, then delete explicitly by ID
plainq receive "$QID"
plainq delete-message "$QID" <message-id>
```

## Stable topic workflow

Topic, queue, and subscription IDs are 20-character XIDs. All six commands
accept `-grpc.addr` and `-json`, and flags may appear before or after IDs.

### `plainq topic list`

Lists `<topic-id> | <topic-name>` in text. `-json` includes subscriptions and
timestamps.

### `plainq topic create`

`TID=$(plainq topic create signups)` creates a nonblank, uniquely named topic
and prints its ID.

### `plainq topic delete`

`plainq topic delete "$TID"` deletes the topic and subscriptions, but preserves
the queues and messages already delivered to them.

### `plainq topic subscribe`

`SID=$(plainq topic subscribe "$TID" "$QID")` binds an existing queue and
prints the subscription ID.

### `plainq topic unsubscribe`

`plainq topic unsubscribe "$TID" "$SID"` stops future delivery through that
subscription. Existing queue messages remain.

### `plainq topic publish`

```shell
plainq topic publish -message='{"user":42}' "$TID"
generate-events | plainq topic publish -file=- "$TID"
```

Repeat `-message`, use newline-delimited `-file`, or combine them. Empty lines
are ignored and stdin is read only with `-file=-`. Zero subscribers succeeds
with zero deliveries. A failed fan-out may already have retained copies in some
queues, so retry can duplicate them. Consume and acknowledge with `plainq
receive` and `plainq delete-message`.

### Script-friendly output

Every client command accepts `-json`:

The `-json` output is protobuf JSON, so field names are lower camel case (for
example `queueName`, `visibilityTimeoutSeconds`, and `topicId`):

```shell
plainq list -json | jq '.queues[].queueName'
plainq describe -json "$QID" | jq '.visibilityTimeoutSeconds'
```

## See also

- [Configuration](/docs/guides/configuration/) — server flags.
- [CLI reference](/docs/reference/cli/) — the complete command table.
