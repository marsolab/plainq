# Build context is the repository root, so the operator module can see the
# rest of the tree if it ever needs to.
FROM golang:1.26-alpine AS build

WORKDIR /src/operator

# Dependencies first, so a source-only change reuses the layer.
COPY operator/go.mod operator/go.sum ./
RUN go mod download

COPY operator/ ./

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/manager ./cmd/manager

# Distroless nonroot, matching how the server itself ships.
FROM gcr.io/distroless/static:nonroot

WORKDIR /
COPY --from=build /out/manager /manager

USER 65532:65532

ENTRYPOINT ["/manager"]
