.PHONY: deps
deps:
	go mod tidy && go mod download

.PHONY: schema
schema:
	cd internal/server/schema && buf generate buf.build/plainq/schema

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
