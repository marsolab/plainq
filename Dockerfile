# syntax=docker/dockerfile:1

# PlainQ multi-stage build.
#
# Stage 1 builds the embedded Houston admin UI (Astro + React) with Bun.
# Stage 2 compiles the Go binary with the UI bundle embedded. The SQLite
# backend (mattn/go-sqlite3) requires cgo, so we link a fully static binary
# against musl on Alpine and ship it on a distroless base.
# Stage 3 is the minimal runtime image.

# ---------------------------------------------------------------------------
# Stage 1: build the Houston UI bundle.
# ---------------------------------------------------------------------------
FROM oven/bun:1.3.13-alpine AS ui

WORKDIR /ui

# Install dependencies first so the layer is cached across source changes.
COPY internal/houston/ui/package.json internal/houston/ui/bun.lock ./
RUN bun install --frozen-lockfile

# Build the static bundle into ui/dist.
COPY internal/houston/ui/ ./
RUN bun run build

# ---------------------------------------------------------------------------
# Stage 2: compile the Go binary with the UI embedded.
# ---------------------------------------------------------------------------
FROM golang:1.26-alpine AS build

# build-base provides gcc/musl-dev needed by cgo (mattn/go-sqlite3).
RUN apk add --no-cache build-base git ca-certificates tzdata

WORKDIR /src

# Download modules first for better layer caching.
COPY go.mod go.sum ./
RUN go mod download

# Copy the source and the pre-built UI bundle (required by //go:embed).
COPY . .
COPY --from=ui /ui/dist ./internal/houston/ui/dist

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

# Statically link so the binary runs on a distroless/scratch base.
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 GOOS=linux go build \
    -tags "sqlite_omit_load_extension" \
    -trimpath \
    -ldflags="-s -w -linkmode external -extldflags '-static' \
      -X main.Branch=${VERSION} \
      -X main.Commit=${COMMIT} \
      -X 'main.BuildTime=${BUILD_TIME}'" \
    -o /out/plainq ./cmd

# Informational: confirm the binary is statically linked (musl ldd output
# varies, so this is logged rather than enforced).
RUN ldd /out/plainq 2>&1 || true

# ---------------------------------------------------------------------------
# Stage 3: minimal runtime image.
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="PlainQ" \
      org.opencontainers.image.description="Truly Simple Queue Service" \
      org.opencontainers.image.source="https://github.com/marsolab/plainq" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /out/plainq /usr/local/bin/plainq

# distroless:nonroot already runs as uid 65532.
USER nonroot:nonroot

# gRPC API and HTTP (Houston UI, /health, /metrics).
EXPOSE 8080 8081

# A writable location for the embedded SQLite database when no volume is
# mounted. Mount a volume here in production.
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/plainq"]
CMD ["serve", "-grpc.addr=:8080", "-http.addr=:8081", "-storage.path=/data/plainq.db"]
