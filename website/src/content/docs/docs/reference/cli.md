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

:::caution
Flags go **before** the positional queue id:
`plainq send -message hi <queue-id>`.
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

| Flag                     | Default  | Description                                     |
| ------------------------ | -------- | ----------------------------------------------- |
| `-visibility-timeout`    | `30s`    | How long a received message stays invisible.    |
| `-max-receive-attempts`  | `5`      | Receives allowed before eviction.               |
| `-retention-period`      | `0` (→7d)| Max message lifetime before eviction.           |
| `-drop-policy`           | `drop`   | Eviction policy: `drop` or `dead-letter`.       |
| `-dead-letter-queue-id`  | —        | Target queue when `-drop-policy=dead-letter`.   |

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

### `plainq tui`

Launch the interactive Bubble Tea terminal UI.

### `plainq schema`

Print the gRPC API surface as text, or as JSON with `-json`.

## gRPC service

The wire API is defined in `schema/v1/schema.proto` and published to the
[Buf Schema Registry](https://buf.build/plainq/schema). It exposes eight RPCs:
`ListQueues`, `DescribeQueue`, `CreateQueue`, `PurgeQueue`, `DeleteQueue`,
`Send`, `Receive`, and `Delete`. Use `buf generate` to produce a client SDK in
your language of choice.
