# Installation

PlainQ is distributed as source today. Prebuilt binaries and an official Docker
image aren't published yet — building from source is the supported path.

## Requirements

| Tool                                  | Version    | Needed for                                  |
| ------------------------------------- | ---------- | ------------------------------------------- |
| [Go](https://go.dev/dl/)              | 1.26.1+    | Building the server and CLI.                |
| [Bun](https://bun.sh)                 | latest     | Building the Houston admin UI (`make houston`). |
| [buf](https://buf.build/docs/installation) | latest | Generating gRPC code — `make build` runs `make schema`, which calls `buf generate`. |
| [sqlc](https://docs.sqlc.dev)         | latest     | Regenerating SQL access code (`make sqlc-generate`, run on demand). |

`make build` depends on `make houston` **and** `make schema`, so a clean
`make build` needs both **Bun** and **buf** on your `PATH`. `sqlc` is only needed
when you regenerate the SQL layer.

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

## Building without the Houston toolchain

If you don't want to install Bun, you can build the server and CLI without
producing a real admin UI — but you **cannot** skip the embed entirely. The
server embeds the UI with `//go:embed all:ui/dist`
(`internal/houston/houston.go`), and `internal/houston/ui/dist` is gitignored, so
it's **absent on a fresh checkout**. A direct `go build` then fails at compile
time with:

```
pattern all:ui/dist: no matching files found
```

You have two options:

```shell
# Option A — build the real UI once (needs Bun), then compile.
make houston
go build -o plainq ./cmd

# Option B — no Bun: create a placeholder bundle so the embed resolves.
mkdir -p internal/houston/ui/dist
echo '<!doctype html><title>Houston disabled</title>' > internal/houston/ui/dist/index.html
go build -o plainq ./cmd
```

Either way the resulting binary serves the gRPC + HTTP APIs, `/health`, and
`/metrics` normally; with Option B the Houston dashboard is a placeholder page
instead of the real app.

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
