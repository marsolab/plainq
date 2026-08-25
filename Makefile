.PHONY: deps
deps:
	go mod tidy && go mod download

.PHONY: schema schema-local schema-public-check schema-published schema-check
schema: schema-local

schema-local:
	buf generate schema --template internal/server/schema/buf.gen.yaml --output internal/server/schema
	cd schema && buf generate . --template buf.docs.gen.yaml

schema-public-check:
	@tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	buf generate schema --template schema/buf.gen.yaml --output "$$tmp"; \
	test -s "$$tmp/go/v1/schema.pb.go"; \
	test -s "$$tmp/go/v1/schema.pb.json.go"; \
	test -s "$$tmp/go/v1/schema.pb.validate.go"; \
	test -s "$$tmp/go/v1/schema_grpc.pb.go"; \
	test -s "$$tmp/go/v1/v1connect/schema.connect.go"; \
	cd "$$tmp/go"; \
	go mod init github.com/plainq/go; \
	go mod tidy; \
	go test ./...

schema-published:
	cd internal/server/schema && buf generate buf.build/plainq/schema

schema-check: schema-local schema-public-check
	git diff --exit-code -- internal/server/schema/v1 schema/docs

.PHONY: sqlc-generate
sqlc-generate:
	sqlc generate

.PHONY: houston
houston:
	cd internal/houston/ui && bun install --frozen-lockfile && bun run build

.PHONY: build
build: deps houston schema
	go build -o plainq ./cmd

.PHONY: test
test:
	go test -v -race ./...

.PHONY: test-cover
test-cover:
	go test -v -race -coverprofile=coverage.out ./...

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: fmt
fmt:
	golangci-lint fmt ./...

# IMAGE and VERSION can be overridden, e.g. make docker IMAGE=ghcr.io/marsolab/plainq VERSION=v0.1.0
IMAGE ?= plainq
VERSION ?= dev

.PHONY: docker
docker:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(shell git rev-parse --short HEAD) \
		-t $(IMAGE):$(VERSION) .

.PHONY: helm-lint
helm-lint:
	helm lint deploy/helm/plainq --set auth.jwtSecret=ci-test-secret
