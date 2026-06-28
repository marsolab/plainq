---
title: Quick start
description: Go from a fresh clone to a message round-trip in about a minute.
sidebar:
  order: 1
---

Go from a fresh clone to a message round-trip in about a minute.

## Prerequisites

`make build` compiles the embedded Houston UI and generates the gRPC code, so a
fresh-clone build needs:

- **Go 1.26.1** or later
- **Bun** (to build the Houston admin UI that gets embedded into the binary)
- **[buf](https://buf.build/docs/installation)** (to generate the gRPC code that
  `make build` regenerates via its `schema` step)

## 1. Build the binary

```shell
make build
```

`make build` builds Houston into `internal/houston/ui/dist`, regenerates the
gRPC code, and produces a `./plainq` binary at the repository root.

## 2. Start the server

PlainQ ships with authentication **on by default**, and the JWT signing secret
is required. Generate one inline:

```shell
./plainq serve --auth.jwt.secret="$(openssl rand -hex 32)"
```

You'll see startup logs and:

- a **gRPC** listener on `:8080` (queue operations, used by the CLI),
- an **HTTP** listener on `:8081` (Houston UI, `/health`, `/metrics`),
- a SQLite database created at `./plainq.db`.

:::caution
In the current wiring, **neither** the gRPC API **nor** the HTTP API routes are
gated by auth middleware at the server. The JWT secret powers Houston's
login/onboarding and the account subsystem, but the queue, RBAC, and OAuth REST
endpoints are reachable without a token. Treat **both** the gRPC (`:8080`) and
HTTP (`:8081`) ports as privileged — keep them on a trusted network.
:::

## 3. Send and receive a message

In another shell:

```shell
# Create a queue — prints the new queue ID (an XID like cf9k2m...).
QID=$(./plainq create my-queue)

# Send a message.
./plainq send -message='hello, plainq' "$QID"

# Receive it back.
./plainq receive "$QID"
```

That's the whole loop: **create → send → receive**.

## 4. Open Houston

Point a browser at <http://localhost:8081>. The first time you visit, Houston
walks you through **onboarding** — creating the first admin account. From there
you can browse queues, manage accounts and roles, and watch metrics.

## What just happened

```
plainq create my-queue   ──▶  gRPC CreateQueue  ──▶  queue row in plainq.db
plainq send   $QID ...   ──▶  gRPC Send         ──▶  message row, visible now
plainq receive $QID      ──▶  gRPC Receive      ──▶  message returned,
                                                     hidden for 30s, retries++
```

The message you received is **not gone**. PlainQ uses at-least-once delivery:
the message is hidden for a **visibility timeout** (30s by default) so you can
process it, and you must explicitly acknowledge it with a delete to remove it.
The CLI's `receive` doesn't auto-delete, so if you run `receive` again after 30
seconds, the same message comes back. To remove it on read, pass `-ack`.

## Next steps

- [Core concepts](/docs/getting-started/core-concepts/) — the model behind
  queues and messages.
- [CLI guide](/docs/guides/cli/) — every command and useful flags.
- [Configuration](/docs/guides/configuration/) — tune storage, auth, listeners.
