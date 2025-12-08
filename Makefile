.PHONY: deps
deps:
	go mod tidy && go mod download

.PHONY: schema
schema:
	cd internal/server/schema && buf generate buf.build/plainq/schema

.PHONY: houston
houston:
	cd internal/houston && npm install && npm run build

.PHONY: build
build: deps schema
	go build -o plainq ./cmd

.PHONY: test
test:
	go test -v -race ./...

.PHONY: test-cover
test-cover:
	go test -v -race -coverprofile=coverage.out ./...
