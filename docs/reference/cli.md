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
| `plainq schema`                | Print the CLI and gRPC surfaces (`-target=all\|cli\|grpc`, text or `-json`). |

> Flags may be written **before or after** the positional arguments:
> `plainq send -message hi <queue-id>` and `plainq send <queue-id> -message hi`
> are equivalent. Both `-flag value` and `-flag=value` work, with one or two
> leading dashes.

## Common client flags

Accepted by every client command (`list`, `create`, `describe`, `purge`,
`delete`, `send`, `receive`, `delete-message`, `tui`):

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
| `read-only`   | `list`, `describe`, `schema`, `version`, `ctx list`, `cluster status`, `cluster members` |
| `mutating`    | `serve`, `create`, `send`, `receive`, `tui`, `ctx init`, `cluster join`, `cluster snapshot` |
| `destructive` | `purge`, `delete`, `delete-message`, `cluster leave`            |

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

Errors are written to stderr; stdout carries only command output.

| Code | Meaning                                                                    |
| ---- | -------------------------------------------------------------------------- |
| `0`  | Success.                                                                   |
| `1`  | The command ran but failed: server unreachable, queue not found, request rejected. |
| `2`  | Usage error: unknown flag, missing or malformed argument. Retrying unchanged will not help. |
</content>
