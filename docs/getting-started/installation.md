# Installation

PlainQ is distributed as source today. Prebuilt binaries and an official Docker
image aren't published yet — building from source is the supported path.

## Requirements

| Tool                                  | Version    | Needed for                                  |
| ------------------------------------- | ---------- | ------------------------------------------- |
| [Go](https://go.dev/dl/)              | 1.26.1+    | Building the server and CLI.                |
| [Bun](https://bun.sh)                 | latest     | Building the Houston admin UI.              |
| [buf](https://buf.build/docs/installation) | latest | Regenerating gRPC code (`make schema`).     |
| [sqlc](https://docs.sqlc.dev)         | latest     | Regenerating SQL access code (`make sqlc-generate`). |

`buf` and `sqlc` are only required if you regenerate code; a plain `make build`
of a clean checkout does not need them beyond what's vendored.

## Build from source

```shell
git clone https://github.com/marsolab/plainq.git
cd plainq
make build
```

This runs three steps in order:

1. **`make houston`** — `bun install` + `bun run build` produces the admin UI in
   `internal/houston/ui/dist`, which the Go build embeds into the binary.
2. **`make schema`** — regenerates the gRPC code from the Buf Schema Registry.
3. **`go build -o plainq ./cmd`** — compiles the `./plainq` binary.

The result is a single self-contained `./plainq` executable: server, CLI, and
admin UI in one file.

## Building without Houston

If you only need the server and CLI (for a headless deployment, CI, or a quick
test), you can skip the UI build and compile directly:

```shell
go build -o plainq ./cmd
```

The binary still starts and serves the gRPC + HTTP APIs. The Houston routes will
serve whatever is embedded (an empty bundle if `internal/houston/ui/dist` was
never built), but `/health`, `/metrics`, the gRPC API, and the REST API all work
normally.

## Embedding the build version

The `plainq version` command reports the branch, commit, and build time. These
are injected at build time via `-ldflags`:

```shell
GOOS=linux GOARCH=amd64 go build \
  -ldflags="-X main.Branch=$(git rev-parse --abbrev-ref HEAD) \
            -X main.Commit=$(git rev-parse --short HEAD)" \
  -o plainq ./cmd
```

Without these flags the version command falls back to `local` / `unknown`.

## Verifying the install

```shell
./plainq version
./plainq -h          # top-level command list
./plainq serve -h    # all server flags
```

## Cross-compiling

PlainQ uses servekit's `litekit` for SQLite. Standard Go cross-compilation
applies:

```shell
GOOS=linux   GOARCH=arm64 go build -o plainq-linux-arm64   ./cmd
GOOS=darwin  GOARCH=arm64 go build -o plainq-darwin-arm64  ./cmd
```

If a build pulls in a CGo-based SQLite driver, set `CGO_ENABLED=1` and provide a
matching cross C toolchain. For most targets a plain `go build` works.

## Next steps

- [Quick start](quickstart.md) — first message round-trip.
- [Deployment](../guides/deployment.md) — running it for real.
</content>
