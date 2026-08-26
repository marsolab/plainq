# CLI reference

Quick-lookup tables for every `plainq` command. For narrative usage and
examples, see the [CLI guide](../guides/cli.md). The binary's `-h` output is
always authoritative.

## Commands

| Command                        | Description                                                  |
| ------------------------------ | ------------------------------------------------------------ |
| `plainq serve`                 | Run the server (gRPC + HTTP + Houston). See [Configuration](configuration.md). |
| `plainq version`               | Print build branch, commit, and time.                       |
| `plainq ctx init`              | Create a client context config file.                        |
| `plainq ctx list`              | Show current and available contexts.                        |
| `plainq list`                  | List queues.                                                |
| `plainq create <name>`         | Create a queue.                                             |
| `plainq describe <queue-id>`   | Describe a queue.                                           |
| `plainq purge <queue-id>`      | Delete all messages in a queue.                            |
| `plainq delete <queue-id>`     | Delete a queue.                                             |
| `plainq send <queue-id>`       | Send one or more messages.                                |
| `plainq receive <queue-id>`    | Receive messages.                                          |
| `plainq delete-message <queue-id> <id>...` | Acknowledge (delete) messages by ID.          |
| `plainq topic list`             | List topics and their subscription objects.                 |
| `plainq topic create <name>`    | Create a uniquely named topic.                              |
| `plainq topic delete <topic-id>` | Delete a topic and its subscriptions.                       |
| `plainq topic subscribe <topic-id> <queue-id>` | Subscribe an existing queue.                 |
| `plainq topic unsubscribe <topic-id> <subscription-id>` | Remove a subscription.          |
| `plainq topic publish <topic-id>` | Publish one batch to every subscribed queue.               |
| `plainq tui`                   | Launch the interactive terminal UI.                       |
| `plainq schema`                | Print the CLI and gRPC surfaces (`-target=all\|cli\|grpc`, text or `-json`). |

> Flags may be written **before or after** the positional arguments:
> `plainq send -message hi <queue-id>` and `plainq send <queue-id> -message hi`
> are equivalent. Both `-flag value` and `-flag=value` work, with one or two
> leading dashes.

## Common client flags

Accepted by every client command (`list`, `create`, `describe`, `purge`,
`delete`, `send`, `receive`, `delete-message`, every `topic` leaf, and `tui`):

| Flag          | Default          | Meaning                              |
| ------------- | ---------------- | ------------------------------------ |
| `--grpc.addr` | `localhost:8080` | gRPC server address.                 |
| `--json`      | `false`          | Emit the raw response as JSON.       |

## Environment variables

| Variable              | Meaning                                                       |
| --------------------- | ------------------------------------------------------------- |
| `PLAINQ_ADDR`         | Default for `--grpc.addr`. Overrides the current context.      |
| `PLAINQ_CONTEXT_FILE` | Path of the context file (default `~/.config/plainq/context.json`). |
| `PLAINQ_TOKEN`        | Default bearer token for `plainq cluster` admin calls.         |

`--grpc.addr` resolves in this order: flag, `PLAINQ_ADDR`, current context,
`localhost:8080`.

## Command effects

Every command declares what running it does to server state. The value appears
in `-h` output and in `plainq schema -target=cli`.

| Effect        | Commands                                                       |
| ------------- | -------------------------------------------------------------- |
| `read-only`   | `list`, `describe`, `topic list`, `schema`, `version`, `ctx list`, `cluster status`, `cluster members` |
| `mutating`    | `serve`, `create`, `send`, `receive`, `topic create`, `topic subscribe`, `topic publish`, `tui`, `ctx init`, `cluster join`, `cluster snapshot` |
| `destructive` | `purge`, `delete`, `delete-message`, `topic delete`, `topic unsubscribe`, `cluster leave` |

Destructive commands take effect immediately: no confirmation prompt, no undo.
`serve` and `tui` are also marked *blocking* — they run until interrupted.

## Per-command flags

### `create`

| Flag                       | Default   | Meaning                                                |
| -------------------------- | --------- | ------------------------------------------------------ |
| `--visibility-timeout`     | `30`      | Seconds a received message stays invisible.            |
| `--max-receive-attempts`   | `5`       | Receives allowed before eviction.                      |
| `--retention-period`       | `0`       | Seconds before expiry. `0` → server default (7 days).  |
| `--drop-policy`            | `drop`    | `drop` or `dead-letter`.                               |
| `--dead-letter-queue-id`   | _(empty)_ | DLQ target when `--drop-policy=dead-letter`.           |

### `list`

| Flag      | Default | Meaning                          |
| --------- | ------- | -------------------------------- |
| `--limit` | `500`   | Page size for pagination.        |

### `send`

| Flag        | Default   | Meaning                                                  |
| ----------- | --------- | -------------------------------------------------------- |
| `-message`  | _(empty)_ | Message body. Repeat the flag to send a batch.           |
| `-file`     | _(empty)_ | Read newline-delimited bodies from a file (`-` = stdin). |

### `receive`

| Flag      | Default | Meaning                                       |
| --------- | ------- | --------------------------------------------- |
| `-batch`  | `1`     | Number of messages to receive (server max 10).|
| `-ack`    | `false` | Delete each received message after printing.   |

### `delete`

| Flag      | Default | Meaning                                  |
| --------- | ------- | ---------------------------------------- |
| `--force` | `false` | Delete a queue even if it has messages.  |

## Topic commands

Topic names are nonblank and unique. Every topic, queue, and subscription
identifier below is a 20-character XID. All leaves accept `--grpc.addr` and
`--json`; flags may appear before or after positional arguments.

### `plainq topic list`

Usage: `plainq topic list [flags]`. Text is one
`<topic-id> | <topic-name>` line. JSON includes subscriptions and timestamps.

### `plainq topic create`

Usage: `plainq topic create [flags] <topic-name>`. Text output is the created
topic ID; JSON returns `topicId`.

### `plainq topic delete`

Usage: `plainq topic delete [flags] <topic-id>`. Deletes the topic and its
subscriptions, not the queues or already-delivered messages. Text output is
`deleted<TAB><topic-id>`.

### `plainq topic subscribe`

Usage: `plainq topic subscribe [flags] <topic-id> <queue-id>`. The queue must
exist and can be bound to the topic once. Text output is the subscription ID.

### `plainq topic unsubscribe`

Usage: `plainq topic unsubscribe [flags] <topic-id> <subscription-id>`. Existing
queue messages are retained. Text output is
`unsubscribed<TAB><subscription-id>`.

### `plainq topic publish`

Usage: `plainq topic publish [flags] <topic-id>`.

| Flag        | Default   | Meaning                                                        |
| ----------- | --------- | -------------------------------------------------------------- |
| `--message` | _(empty)_ | Message body; repeat to publish a batch.                        |
| `--file`    | _(empty)_ | Newline-delimited bodies; `-` explicitly reads stdin.          |

At least one non-empty body is required. Inline messages and file lines may be
combined; empty file lines are ignored and every non-empty line is limited to
4 MiB. Text output is
`delivered<TAB><count>`. Zero subscribers is a successful zero. Fan-out attempts
all selected destinations synchronously but is non-atomic, so exit `1` may be a
partial delivery and a retry may duplicate retained copies.

## Arguments

| Command    | Positional argument | Notes                                  |
| ---------- | ------------------- | -------------------------------------- |
| `create`   | `<queue-name>`      | Required.                              |
| `describe` | `<queue-id>`        | Required; validated as an XID.         |
| `purge`    | `<queue-id>`        | Required; validated as an XID.         |
| `delete`   | `<queue-id>`        | Required; validated as an XID.         |
| `send`     | `<queue-id>`        | Required; validated as an XID.         |
| `receive`  | `<queue-id>`        | Required; validated as an XID.         |
| `topic create` | `<topic-name>` | Required, nonblank, and unique.        |
| `topic delete` | `<topic-id>` | Required; validated as an XID.          |
| `topic subscribe` | `<topic-id> <queue-id>` | Both required XIDs.          |
| `topic unsubscribe` | `<topic-id> <subscription-id>` | Both required XIDs. |
| `topic publish` | `<topic-id>` | Required XID plus message input.        |

## Exit codes

Errors are written to stderr; stdout carries only command output.

| Code | Meaning                                                                    |
| ---- | -------------------------------------------------------------------------- |
| `0`  | Success.                                                                   |
| `1`  | The command ran but failed: server unreachable, queue not found, request rejected. |
| `2`  | Usage error: unknown flag, missing or malformed argument. Retrying unchanged will not help. |
</content>
