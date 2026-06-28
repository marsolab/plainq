---
title: Deployment
description: Run PlainQ as a single binary, a Docker container, or a Helm release on Kubernetes.
sidebar:
  order: 3
---

PlainQ is a single binary, so deployment is mostly about where you run it and
how you persist its database.

## Single binary

The simplest deployment: copy `./plainq` to a host and run it. With SQLite, the
entire state lives in one file.

```shell
./plainq serve \
  -storage.path=/var/lib/plainq/plainq.db \
  -auth.jwt.secret="$(openssl rand -hex 32)"
```

Pair it with [Litestream](https://litestream.io) to continuously replicate the
SQLite file to object storage for cheap durability.

## Docker

```shell
docker run --rm -p 8080:8080 -p 8081:8081 -v plainq-data:/data \
  plainq:dev serve -storage.path=/data/plainq.db \
  -auth.jwt.secret="$(openssl rand -hex 32)"
```

Mount a volume at `/data` and point `-storage.path` at it for a durable
database.

## Kubernetes (Helm)

The chart in `deploy/helm/plainq` deploys:

- a **StatefulSet + PVC** for the SQLite backend, or
- a **Deployment + HPA** when `storage.driver=postgres`.

```shell
helm install plainq deploy/helm/plainq \
  --set auth.jwtSecret="$(openssl rand -hex 32)"
```

The JWT secret is sourced from a Kubernetes Secret. See the chart README in the
repository for the full set of values.

## Network exposure

:::danger
In the current wiring, neither the gRPC API nor the HTTP API routes are gated by
auth middleware at the server. The JWT secret powers Houston's login and the
account subsystem, but the queue, RBAC, and OAuth REST endpoints are reachable
without a token.

**Treat both the gRPC (`:8080`) and HTTP (`:8081`) ports as privileged.** Keep
them on a trusted network — behind a VPN, service mesh, or an authenticating
reverse proxy — and never expose them directly to the public internet.
:::

## Health & metrics

- `GET /health` — liveness/readiness probe (configurable via `-health.route`).
- `GET /metrics` — Prometheus-style metrics (configurable via `-metrics.route`).

Wire these into your orchestrator's probes and your monitoring stack.
