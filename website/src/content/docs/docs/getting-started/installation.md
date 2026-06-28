---
title: Installation
description: Build PlainQ from source, run it with Docker, or deploy it on Kubernetes with Helm.
sidebar:
  order: 2
---

PlainQ is a single Go binary. You can build it from source, run the prebuilt
Docker image, or deploy the Helm chart on Kubernetes.

## Build from source

### Requirements

- Go **1.26.1** or later
- [Bun](https://bun.sh) (for building the Houston admin UI)
- [`buf`](https://buf.build/docs/installation) and
  [`sqlc`](https://docs.sqlc.dev) if you plan to regenerate code

```shell
make build
```

`make houston` builds the admin UI into `internal/houston/ui/dist`, which the
server embeds at compile time. `make build` then produces a `./plainq` binary at
the repo root.

### Building without Houston

If you only want the server and CLI and don't have Bun installed, build the Go
binary directly — the embedded UI assets fall back to an empty directory:

```shell
go build -o plainq ./cmd/plainq
```

## Docker

The optimized multi-stage image builds Houston with Bun, compiles a static Go
binary, and ships it on `distroless:nonroot`:

```shell
make docker IMAGE=plainq VERSION=dev
# or directly:
docker build -t plainq:dev .

docker run --rm -p 8080:8080 -p 8081:8081 -v plainq-data:/data \
  plainq:dev serve -storage.path=/data/plainq.db \
  -auth.jwt.secret="$(openssl rand -hex 32)"
```

The image exposes `8080` (gRPC) and `8081` (HTTP/Houston). A bare
`docker run plainq:dev` prints usage — pass an explicit `serve ...` command to
start the server, pointing `-storage.path` at the mounted `/data` volume for a
durable SQLite database.

## Kubernetes (Helm)

A production-grade chart lives in `deploy/helm/plainq`:

```shell
helm install plainq deploy/helm/plainq \
  --set auth.jwtSecret="$(openssl rand -hex 32)"
```

It deploys a StatefulSet + PVC for SQLite (or a Deployment + HPA when
`storage.driver=postgres`) and sources the JWT secret from a Kubernetes Secret.
See the [Deployment guide](/docs/guides/deployment/) for the full story.

## Verify the install

```shell
./plainq version
./plainq schema   # print the gRPC API surface
```

## Next steps

- [Quick start](/docs/getting-started/quickstart/) — your first message
  round-trip.
- [Configuration](/docs/guides/configuration/) — every `serve` flag.
