# Quick start

Go from a fresh clone to a message round-trip in about a minute.

## Prerequisites

- **Go 1.26.1** or later
- **Bun** (to build the Houston admin UI that gets embedded into the binary)

> Don't have Bun and only want the server + CLI? See
> [Installation](installation.md#building-without-houston) for a Houston-free
> build.

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

> **Heads up:** the gRPC API the CLI talks to is currently unauthenticated — the
> JWT secret protects the **HTTP/Houston** surface (accounts, RBAC, the admin
> UI). See [Authentication & RBAC](../authentication-rbac.md) for the full
> picture and [Deployment](../guides/deployment.md#network-exposure) for how to
> keep the gRPC port private.

## 3. Send and receive a message

In another shell:

```shell
# Create a queue — prints the new queue ID (an XID like cf9k2m...).
QID=$(./plainq create my-queue)

# Send a message.
./plainq send "$QID" --message='hello, plainq'

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
plainq create my-queue   ──▶  gRPC CreateQueue   ──▶  queue row in plainq.db
plainq send   $QID ...    ──▶  gRPC Send          ──▶  message row, visible now
plainq receive $QID       ──▶  gRPC Receive       ──▶  message returned,
                                                       hidden for 30s, retries++
```

The message you received is **not gone**. PlainQ uses at-least-once delivery:
the message is hidden for a **visibility timeout** (30s by default) so you can
process it, and you must explicitly acknowledge it with a delete to remove it.
The CLI's `receive` doesn't auto-delete, so if you run `receive` again after 30
seconds, the same message comes back. To understand this fully, read
[Queues & messages](../guides/queues-and-messages.md).

## Next steps

- [Core concepts](core-concepts.md) — the model behind queues and messages.
- [CLI guide](../guides/cli.md) — every command and useful flags.
- [Queues & messages](../guides/queues-and-messages.md) — visibility, retries,
  retention, and dead-letter queues.
- [Configuration](../guides/configuration.md) — tune storage, auth, listeners.
</content>
