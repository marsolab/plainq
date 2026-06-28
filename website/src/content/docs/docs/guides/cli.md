---
title: CLI guide
description: Every PlainQ command and the flags you'll actually use.
sidebar:
  order: 1
---

The `plainq` binary is both the server and the client. Every client command
talks gRPC and accepts `-grpc.addr` (default `localhost:8080`) and `-json` for
machine-readable output.

:::caution
**Flags go before the positional queue id.** For example:
`plainq send -message hi <queue-id>`.
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
| `plainq tui`                               | Launch the interactive terminal UI.                                                                                                                             |
| `plainq schema`                            | Print the gRPC API surface (text or `-json`).                                                                                                                   |

Run any command with `-h` for its full flag list.

## Everyday recipes

### Create a queue with a dead-letter policy

Remember: **flags go before the positional queue name**, and durations are given
as whole seconds.

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

### Script-friendly output

Every client command accepts `-json`:

The `-json` output is the JSON encoding of the gRPC response, so its keys are the
schema's snake_case field names (e.g. `queue_name`, `visibility_timeout_seconds`):

```shell
plainq list -json | jq '.queues[].queue_name'
plainq describe -json "$QID" | jq '.visibility_timeout_seconds'
```

## See also

- [Configuration](/docs/guides/configuration/) — server flags.
- [CLI reference](/docs/reference/cli/) — the complete command table.
