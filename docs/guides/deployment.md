# Deployment

PlainQ is a single binary, which makes deployment refreshingly boring. This guide
covers choosing a storage backend, running under a process manager and in
containers, replicating SQLite with Litestream, and hardening the network
surface.

## Choosing a storage backend

| Use case                                         | Backend       | Why                                                       |
| ------------------------------------------------ | ------------- | --------------------------------------------------------- |
| Local dev, CI, small single-node service         | **SQLite**    | Zero dependencies, one file, fast.                        |
| Single node that needs durable off-box backups   | **SQLite + Litestream** | Continuous replication to object storage.       |
| Multiple server instances sharing one dataset    | **PostgreSQL**| A shared backend many replicas can talk to.               |

The queue model and semantics are identical on both. Start with SQLite; move to
PostgreSQL when you genuinely need a shared backend.

## Running with systemd

A minimal unit for a SQLite deployment:

```ini
# /etc/systemd/system/plainq.service
[Unit]
Description=PlainQ
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=plainq
Group=plainq
WorkingDirectory=/var/lib/plainq
Environment=PLAINQ_JWT_SECRET=     # set via a drop-in or systemd credential
ExecStart=/usr/local/bin/plainq serve \
  --storage.path=/var/lib/plainq/plainq.db \
  --storage.journal-mode=wal \
  --grpc.addr=127.0.0.1:8080 \
  --http.addr=:8081 \
  --auth.jwt.secret=${PLAINQ_JWT_SECRET}
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

Provide the secret out-of-band (a systemd `EnvironmentFile`,
`LoadCredential=`, or your secret manager) — never bake it into the unit.

```shell
sudo systemctl daemon-reload
sudo systemctl enable --now plainq
journalctl -u plainq -f
```

The process handles `SIGINT`/`SIGTERM` and shuts down gracefully, so
`systemctl stop` is clean.

## Running in a container

There's no official image yet; build a small one yourself. A multi-stage build
keeps it lean:

```dockerfile
# Build stage
FROM golang:1.26 AS build
WORKDIR /src
COPY . .
# Build the server + CLI. (Add `make houston` + bun if you want the UI embedded.)
RUN CGO_ENABLED=0 go build -o /out/plainq ./cmd

# Runtime stage
FROM gcr.io/distroless/base-debian12
COPY --from=build /out/plainq /usr/local/bin/plainq
EXPOSE 8080 8081
VOLUME ["/data"]
ENTRYPOINT ["plainq"]
CMD ["serve", "--storage.path=/data/plainq.db", "--http.addr=:8081", "--grpc.addr=:8080"]
```

```shell
docker build -t plainq:local .
docker run --rm -p 8081:8081 -p 8080:8080 \
  -v plainq-data:/data \
  -e PLAINQ_JWT_SECRET \
  plainq:local serve \
  --storage.path=/data/plainq.db \
  --auth.jwt.secret="$PLAINQ_JWT_SECRET"
```

Mount a **persistent volume** for the SQLite file (and its `-wal`/`-shm`
siblings) so data survives container restarts.

> The above builds without Houston for simplicity. To embed the admin UI, run
> `make houston` before `go build`, or add a Bun build stage — see
> [Installation](../getting-started/installation.md).

## SQLite + Litestream

SQLite's single-file design pairs perfectly with
[Litestream](https://litestream.io) for continuous replication to S3-compatible
object storage — point-in-time durability without a database server.

1. Run PlainQ with **WAL** journal mode (`--storage.journal-mode=wal`), which
   Litestream requires.
2. Configure Litestream to replicate the database file:

```yaml
# litestream.yml
dbs:
  - path: /var/lib/plainq/plainq.db
    replicas:
      - type: s3
        bucket: my-plainq-backups
        path: plainq
        region: us-east-1
```

3. Run `litestream replicate` alongside PlainQ (separate process/sidecar).

To restore, stop PlainQ and run `litestream restore` before starting it again.

## PostgreSQL

Point the server at your database and let it migrate its own schema on startup:

```shell
./plainq serve \
  --storage.driver=postgres \
  --storage.postgres.dsn='postgres://plainq:secret@pg.internal:5432/plainq?sslmode=require' \
  --auth.jwt.secret="$PLAINQ_JWT_SECRET"
```

On boot the server connects (30s timeout), pings, and applies pending schema
migrations automatically. Provision a dedicated database/role; standard
PostgreSQL connection-pool sizing and backup practices apply.

## Network exposure

PlainQ has two listeners with different trust assumptions:

- **gRPC (`:8080`)** — the queue API. It does **not** currently enforce the JWT
  auth used by the HTTP surface, and the bundled client dials in plaintext. Treat
  it as privileged: bind it to loopback or a private interface
  (`--grpc.addr=127.0.0.1:8080`) and reach it over a trusted network, a service
  mesh, or a TLS-terminating proxy.
- **HTTP (`:8081`)** — Houston, REST APIs, `/health`, `/metrics`. Protected by
  JWT sessions and RBAC, but you should still front it with a reverse proxy
  (TLS, rate limiting, sane timeouts).

A typical layout:

```
            Internet
               │  TLS
        ┌──────▼───────┐
        │ reverse proxy │  (nginx / Caddy / Traefik)
        └──────┬───────┘
               │ :8081 (HTTP / Houston)
        ┌──────▼───────────────────────┐
        │           plainq             │
        │  :8080 gRPC ← private only    │
        └──────────────────────────────┘
```

Producers and consumers on the trusted network connect to gRPC directly;
operators reach Houston through the proxy.

## Pre-flight checklist

- [ ] `--auth.jwt.secret` supplied from a secret manager, not the command line history.
- [ ] gRPC bound to a private interface or fronted by mTLS/proxy.
- [ ] HTTP behind a TLS-terminating reverse proxy with timeouts.
- [ ] Persistent volume for the SQLite file (or a managed PostgreSQL).
- [ ] Backups: Litestream (SQLite) or your PostgreSQL backup tooling.
- [ ] `/health` wired to your orchestrator's liveness/readiness probes.
- [ ] `/metrics` scraped by Prometheus.
- [ ] Onboarding completed (first admin created) — see [Houston](houston.md).

## Next steps

- [Observability](observability.md) — health checks and metrics to monitor.
- [Configuration](configuration.md) — every flag in context.
- [Authentication & RBAC](../authentication-rbac.md) — securing access.
</content>
