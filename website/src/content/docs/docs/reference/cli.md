---
title: CLI reference
description: The complete PlainQ command surface and global flags.
sidebar:
  order: 1
---

A complete reference of the `plainq` command surface. For task-oriented
walkthroughs, see the [CLI guide](/docs/guides/cli/).

## Global client flags

These apply to every command that talks to a server:

| Flag         | Default            | Description                       |
| ------------ | ------------------ | --------------------------------- |
| `-grpc.addr` | `localhost:8080`   | Address of the PlainQ gRPC server. |
| `-json`      | `false`            | Emit machine-readable JSON output. |
| `-h`, `-help`| —                  | Print command help.               |

:::tip
Flags may go **before or after** the positional queue id:
`plainq send -message hi <queue-id>` and `plainq send <queue-id> -message hi`
are equivalent.
:::

## Commands

### `plainq serve`

Run the PlainQ server (gRPC + HTTP + Houston UI). See the
[Configuration reference](/docs/reference/configuration/) for every `serve` flag.

### `plainq version`

Print the build version, commit, and build time.

### `plainq ctx`

Manage local client contexts (saved server addresses and settings).

### `plainq list`

List queues. Supports pagination, an optional name prefix, and sort order.

### `plainq create <queue-name>`

Create a queue. Prints the new queue ID.

All values are whole numbers of seconds where applicable. Flags may appear
before or after the positional queue name.

| Flag                     | Default   | Description                                    |
| ------------------------ | --------- | ---------------------------------------------- |
| `-visibility-timeout`    | `30`      | Seconds a received message stays invisible.    |
| `-max-receive-attempts`  | `5`       | Receives allowed before eviction.              |
| `-retention-period`      | `0` (→7d) | Seconds a message may live before eviction.    |
| `-drop-policy`           | `drop`    | Eviction policy: `drop` or `dead-letter`.      |
| `-dead-letter-queue-id`  | —         | Target queue when `-drop-policy=dead-letter`.  |

### `plainq describe <queue-id>`

Describe a queue's settings.

### `plainq purge <queue-id>`

Delete all messages from a queue (the queue itself remains).

### `plainq delete <queue-id>`

Delete the queue. Pass `-force` to skip safety checks.

### `plainq send <queue-id>`

Send one or more messages.

| Flag        | Description                                          |
| ----------- | ---------------------------------------------------- |
| `-message`  | Message body (repeatable for multiple messages).     |
| `-file`     | Read the body from a file; `-file=-` reads stdin.    |

### `plainq receive <queue-id>`

Receive a batch of messages.

| Flag      | Default | Description                                  |
| --------- | ------- | -------------------------------------------- |
| `-batch`  | `1`     | Number of messages to receive (1–10).        |
| `-ack`    | `false` | Delete messages immediately after reading.   |

### `plainq delete-message <queue-id> <id>...`

Acknowledge (delete) one or more messages by ID.

## Stable topic commands

Every leaf accepts `-grpc.addr` and `-json`. Topic, queue, and subscription IDs
are validated as 20-character XIDs, and topic names must be nonblank and unique.

### `plainq topic list`

`plainq topic list [flags]` prints `<topic-id> | <topic-name>` lines. JSON also
contains full subscription objects and timestamps.

### `plainq topic create`

`plainq topic create [flags] <topic-name>` prints the new topic ID.

### `plainq topic delete`

`plainq topic delete [flags] <topic-id>` deletes the topic and subscriptions,
not the queues or already delivered messages. Text output is
`deleted<TAB><topic-id>`.

### `plainq topic subscribe`

`plainq topic subscribe [flags] <topic-id> <queue-id>` binds an existing queue
and prints the subscription ID.

### `plainq topic unsubscribe`

`plainq topic unsubscribe [flags] <topic-id> <subscription-id>` removes the
binding while preserving existing queue messages. Text output is
`unsubscribed<TAB><subscription-id>`.

### `plainq topic publish`

`plainq topic publish [flags] <topic-id>` requires at least one body.

| Flag       | Default | Description                                                   |
| ---------- | ------- | ------------------------------------------------------------- |
| `-message` | —       | Message body; repeat for a batch.                              |
| `-file`    | —       | Newline-delimited bodies; `-` explicitly reads standard input. |

Inline and file input may be combined; empty file lines are ignored and every
non-empty line is limited to 4 MiB. Text is `delivered<TAB><count>`. Zero
subscribers succeeds. Fan-out attempts every selected queue but is not atomic,
so a failed command may be partial and retry may duplicate retained copies.

### `plainq tui`

Launch the interactive Bubble Tea terminal UI.

### `plainq schema`

Print PlainQ's surfaces as text, or as JSON with `-json`. `-target` selects
which: `all` (the default), `cli`, or `grpc`.

The `cli` surface lists every command with its call signature, positional
arguments, flags (type, default, usage), effect classification, and worked
examples. Neither surface contacts a server, which makes `schema` the right
first call when working out how to drive PlainQ from a script or an agent.

```shell
plainq schema -target=cli -json \
  | jq -r '.cli.commands[] | recurse(.subcommands[]?) | select(.effect != "read-only") | .path'
```

## Environment variables

| Variable              | Meaning                                                             |
| --------------------- | ------------------------------------------------------------------- |
| `PLAINQ_ADDR`         | Default for `-grpc.addr`. Overrides the current context.            |
| `PLAINQ_CONTEXT_FILE` | Path of the context file (default `~/.config/plainq/context.json`). |
| `PLAINQ_TOKEN`        | Default bearer token for `plainq cluster` admin calls.              |

`-grpc.addr` resolves in this order: flag, `PLAINQ_ADDR`, current context,
`localhost:8080`.

## Exit codes

Errors are written to stderr; stdout carries only command output.

| Code | Meaning                                                                            |
| ---- | ---------------------------------------------------------------------------------- |
| `0`  | Success.                                                                           |
| `1`  | The command ran but failed: server unreachable, queue not found, request rejected.  |
| `2`  | Usage error: unknown flag, missing or malformed argument. Retrying unchanged will not help. |

## gRPC service

The wire API is defined in `schema/v1/schema.proto` and published to the
[Buf Schema Registry](https://buf.build/plainq/schema). It exposes the eight
queue/message RPCs plus stable `ListTopics`, `CreateTopic`, `DeleteTopic`,
`Subscribe`, `Unsubscribe`, and `Publish`. Use `buf generate` to produce a
client SDK in your language of choice.
