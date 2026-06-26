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
| `plainq tui`                   | Launch the interactive terminal UI.                       |
| `plainq schema`                | Print the gRPC API surface (text or `-json`).             |

> Client commands take flags **before** the positional queue id, e.g.
> `plainq send -message hi <queue-id>`. Flags after the positional are ignored.

## Common client flags

Accepted by every client command (`list`, `create`, `describe`, `purge`,
`delete`, `send`, `receive`):

| Flag          | Default          | Meaning                              |
| ------------- | ---------------- | ------------------------------------ |
| `--grpc.addr` | `localhost:8080` | gRPC server address.                 |
| `--json`      | `false`          | Emit the raw response as JSON.       |

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

## Arguments

| Command    | Positional argument | Notes                                  |
| ---------- | ------------------- | -------------------------------------- |
| `create`   | `<queue-name>`      | Required.                              |
| `describe` | `<queue-id>`        | Required; validated as an XID.         |
| `purge`    | `<queue-id>`        | Required; validated as an XID.         |
| `delete`   | `<queue-id>`        | Required; validated as an XID.         |
| `send`     | `<queue-id>`        | Required; validated as an XID.         |
| `receive`  | `<queue-id>`        | Required; validated as an XID.         |

## Exit codes

| Code | Meaning            |
| ---- | ------------------ |
| `0`  | Success.           |
| `2`  | Error (printed to output). |
</content>
