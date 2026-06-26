# Troubleshooting & FAQ

Common errors, what they mean, and how to fix them — plus answers to the
questions that come up most.

## Errors

### `auth.jwt.secret is required for session issuance`

The server won't start because auth is enabled (the default) but no signing
secret was supplied. Provide one:

```shell
./plainq serve --auth.jwt.secret="$(openssl rand -hex 32)"
```

In production, inject it from a secret manager rather than the command line. See
[Configuration → Authentication](configuration.md#authentication).

### `pattern all:ui/dist: no matching files found`

A direct `go build ./cmd` failed because the server embeds the Houston UI from
`internal/houston/ui/dist`, which is gitignored and absent on a fresh checkout.
Either build the UI or create a placeholder bundle:

```shell
make houston                       # build the real UI (needs Bun), or…
mkdir -p internal/houston/ui/dist  # …a placeholder so the embed resolves
echo '<!doctype html><title>Houston disabled</title>' > internal/houston/ui/dist/index.html
go build -o plainq ./cmd
```

See [Installation → building without the Houston toolchain](../getting-started/installation.md#building-without-the-houston-toolchain).

### `buf: command not found` during `make build`

`make build` runs `make schema`, which calls `buf generate`. Install
[`buf`](https://buf.build/docs/installation) (and [Bun](https://bun.sh) for
`make houston`) before building from a clean checkout. See
[Installation → requirements](../getting-started/installation.md#requirements).

### `validate queue id: ...` from a CLI command

`describe`, `purge`, `delete`, `send`, and `receive` validate that their
argument is a queue **ID** (an XID), not a queue **name**. Get the ID from
`plainq create` (it prints it) or `plainq list`:

```shell
plainq list --json | jq -r '.queues[] | "\(.queueId)\t\(.queueName)"'
```

### `connect to server: ...` / connection refused

The client can't reach the gRPC server. Check that:

- the server is running and its gRPC listener is up (default `:8080`);
- you passed the right `--grpc.addr` (default `localhost:8080`);
- nothing (firewall, container networking) blocks the port.

### A message I received keeps coming back

That's at-least-once delivery working as designed. `receive` does **not**
acknowledge — you must delete the message by ID after processing (via the gRPC
`Delete` RPC). Until then it reappears after the visibility timeout. See the
[consumer loop](queues-and-messages.md#a-real-consumer-loop).

### `unknown drop policy: "..."`

`--drop-policy` accepts only `drop` or `dead-letter`. If you use `dead-letter`,
also pass a valid `--dead-letter-queue-id` (create that queue first).

## FAQ

### Is delivery exactly-once?

No — it's **at-least-once**. Make consumers idempotent. See
[stronger delivery guarantees](advanced.md#toward-stronger-delivery-guarantees).

### Are messages ordered?

Best-effort **FIFO** by creation time within a queue. Redelivered messages move
later in time, and there's no strict global total order across concurrent
producers. There is no deduplication.

### How big can a message be?

PlainQ stores the body as-is and doesn't impose a documented size limit, but
queues aren't blob stores. Keep messages small; for large payloads, store the
blob elsewhere and enqueue a pointer.

### Can I send more than one message at once?

Yes — the gRPC `Send` RPC takes a batch. The CLI `send` sends one at a time; use
the [gRPC API](grpc-api.md) or [Go SDK](../examples/README.md#go-sdk) for batches.

### Why does the CLI `receive` not delete messages?

So you can process a message before acknowledging it. Acknowledgment is an
explicit `Delete` after successful processing — that's what makes redelivery on
failure possible.

### Is the HTTP/REST API authenticated?

Not at the server today. PlainQ ships a JWT/RBAC subsystem (used by Houston's
login), but the middleware isn't wired onto the `/api/v1` routes in the current
build. Treat both the HTTP and gRPC listeners as privileged and front them with
your own access control. See
[Deployment → network exposure](deployment.md#network-exposure).

### Is pub/sub ready for production?

It's **experimental** and HTTP-only (no gRPC/CLI yet). The fan-out model works
(see [Advanced → pub/sub](advanced.md#pubsub-topics--fan-out)), but pin to the
documented behavior and expect the surface to evolve.

### How do I move from SQLite to PostgreSQL?

Switch `--storage.driver=postgres` and provide `--storage.postgres.dsn`. The
server migrates its schema on startup. There's no built-in data migration tool —
plan a cutover. See [Deployment → PostgreSQL](deployment.md#postgresql).

### Where does my data live?

SQLite: the file at `--storage.path` (default `./plainq.db`), plus a sibling
`*_telemetry.db` for metrics. PostgreSQL: your database. Back these up — see
[Deployment](deployment.md).

## Still stuck?

- Re-read the relevant guide — most behavior is covered in
  [Queues & messages](queues-and-messages.md) and [Configuration](configuration.md).
- Turn on debug logs: `./plainq serve --log.level=debug ...`.
- Open a [GitHub issue](https://github.com/marsolab/plainq/issues) or ask in
  [Discussions](https://github.com/marsolab/plainq/discussions).
</content>
