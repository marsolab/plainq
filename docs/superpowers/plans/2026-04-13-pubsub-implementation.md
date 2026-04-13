# Pub/Sub Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add first-class pub/sub to PlainQ with single-stream topics, durable subscriptions by default, optional ephemeral push subscriptions, `ack`-based at-least-once delivery, and both SQLite and PostgreSQL storage backends.

**Architecture:** Implement a dedicated `pubsub` service alongside the existing queue service. Persist one append-only topic log plus per-subscription state, use durable pull semantics as the core delivery engine, layer push delivery on top of the same durable leasing rules, and keep ephemeral delivery as an in-memory fast path. Expose the new feature over gRPC first; defer HTTP and Houston UI work until semantics are stable.

**Tech Stack:** Go, gRPC/protobuf, Buf, SQLite via `litekit`, PostgreSQL via `pgxpool`, sqlc, VictoriaMetrics metrics, `go-testdeep`.

---

## Preflight

- This repo already has unrelated staged and unstaged work. Execute this plan in a fresh worktree before touching code.
- Use `git worktree add ../plainq-pubsub -b feat/pubsub-v1` from the main repo root unless the user requests a different location.
- Run every command from the worktree root unless a step says otherwise.

## File Map

### Existing Files To Modify

- `Makefile`
- `schema/v1/schema.proto`
- `internal/client/client.go`
- `internal/client/client_test.go`
- `internal/server/server.go`
- `cmd/server.go`
- `internal/server/service/telemetry/observer.go`
- `internal/server/mutations/storage/sqlite/1_schema.sql`
- `internal/server/mutations/storage/postgres/1_schema.sql`
- `sqlc/sqlite/schema.sql`
- `sqlc/postgres/schema.sql`
- `internal/server/schema/v1/schema.pb.go`
- `internal/server/schema/v1/schema.pb.json.go`
- `internal/server/schema/v1/schema_grpc.pb.go`
- `internal/server/schema/v1/schema_vtproto.pb.go`
- `README.md`
- `schema/README.md`

### New Service Files

- `internal/server/service/pubsub/service.go`
- `internal/server/service/pubsub/grpc_transport.go`
- `internal/server/service/pubsub/validation.go`
- `internal/server/service/pubsub/runtime.go`
- `internal/server/service/pubsub/service_test.go`
- `internal/server/service/pubsub/validation_test.go`
- `internal/server/service/pubsub/runtime_test.go`

### New SQLite Backend Files

- `internal/server/service/pubsub/litestore/storage.go`
- `internal/server/service/pubsub/litestore/query.go`
- `internal/server/service/pubsub/litestore/gc.go`
- `internal/server/service/pubsub/litestore/storage_test.go`
- `internal/server/service/pubsub/litestore/query_test.go`
- `internal/server/service/pubsub/litestore/queries/pubsub.sql`
- `internal/server/service/pubsub/litestore/sqlcgen/db.go`
- `internal/server/service/pubsub/litestore/sqlcgen/models.go`
- `internal/server/service/pubsub/litestore/sqlcgen/pubsub.sql.go`

### New PostgreSQL Backend Files

- `internal/server/service/pubsub/pgstore/storage.go`
- `internal/server/service/pubsub/pgstore/query.go`
- `internal/server/service/pubsub/pgstore/gc.go`
- `internal/server/service/pubsub/pgstore/storage_test.go`
- `internal/server/service/pubsub/pgstore/query_test.go`
- `internal/server/service/pubsub/pgstore/queries/pubsub.sql`
- `internal/server/service/pubsub/pgstore/sqlcgen/db.go`
- `internal/server/service/pubsub/pgstore/sqlcgen/models.go`
- `internal/server/service/pubsub/pgstore/sqlcgen/pubsub.sql.go`

### Generated And Supporting Artifacts

- `docs/pubsub.md`

## Working Assumptions Locked By This Plan

- gRPC is the only transport shipped in this plan.
- Topics are single ordered streams only.
- Durable subscriptions default to `pull`.
- Ephemeral subscriptions are `push` only, persist metadata only, and keep cursor/inflight state in runtime memory.
- Topic-level auth and RBAC remain out of scope for v1.
- CLI commands remain a follow-up; the shared Go client gains pub/sub methods now.

### Task 1: Add The Pub/Sub gRPC Contract And Client Bindings

**Files:**
- Modify: `Makefile`
- Modify: `schema/v1/schema.proto`
- Modify: `internal/client/client.go`
- Modify: `internal/client/client_test.go`
- Modify: `internal/server/schema/v1/schema.pb.go`
- Modify: `internal/server/schema/v1/schema.pb.json.go`
- Modify: `internal/server/schema/v1/schema_grpc.pb.go`
- Modify: `internal/server/schema/v1/schema_vtproto.pb.go`

- [ ] **Step 1: Write the failing client smoke test**

Create `internal/client/client_test.go` with:

```go
package client

import (
	"testing"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
)

func TestClient_PubSubMethodsCompile(t *testing.T) {
	_ = (*Client).CreateTopic
	_ = (*Client).CreateSubscription
	_ = (*Client).Publish
	_ = (*Client).ConsumePull
	_ = (*Client).Ack

	_ = &v1.CreateTopicRequest{}
	_ = &v1.CreateSubscriptionRequest{}
	_ = &v1.PublishRequest{}
	_ = &v1.ConsumePullRequest{}
	_ = &v1.AckRequest{}
}
```

- [ ] **Step 2: Run the test to verify the contract is missing**

Run: `go test ./internal/client -run TestClient_PubSubMethodsCompile -count=1`

Expected: FAIL with build errors such as `undefined: v1.CreateTopicRequest` and `(*Client).CreateTopic undefined`.

- [ ] **Step 3: Add local schema generation commands and define the pub/sub API**

Update `Makefile` so local schema edits regenerate both the public schema artifacts and the in-repo server bindings:

```make
.PHONY: schema-public
schema-public:
	cd schema && buf generate

.PHONY: schema-internal
schema-internal:
	cd internal/server/schema && buf generate ../../schema --template buf.gen.yaml

.PHONY: schema
schema: schema-public schema-internal
```

Append the new service and messages to `schema/v1/schema.proto`:

```proto
service PubSubService {
  rpc ListTopics(ListTopicsRequest) returns (ListTopicsResponse) {}
  rpc DescribeTopic(DescribeTopicRequest) returns (DescribeTopicResponse) {}
  rpc CreateTopic(CreateTopicRequest) returns (CreateTopicResponse) {}
  rpc DeleteTopic(DeleteTopicRequest) returns (DeleteTopicResponse) {}
  rpc Publish(PublishRequest) returns (PublishResponse) {}

  rpc ListSubscriptions(ListSubscriptionsRequest) returns (ListSubscriptionsResponse) {}
  rpc DescribeSubscription(DescribeSubscriptionRequest) returns (DescribeSubscriptionResponse) {}
  rpc CreateSubscription(CreateSubscriptionRequest) returns (CreateSubscriptionResponse) {}
  rpc DeleteSubscription(DeleteSubscriptionRequest) returns (DeleteSubscriptionResponse) {}

  rpc ConsumePull(ConsumePullRequest) returns (ConsumePullResponse) {}
  rpc ConsumePush(ConsumePushRequest) returns (stream ConsumePushResponse) {}
  rpc Ack(AckRequest) returns (AckResponse) {}
}

enum SubscriptionType {
  SUBSCRIPTION_TYPE_UNSPECIFIED = 0;
  SUBSCRIPTION_TYPE_DURABLE = 1;
  SUBSCRIPTION_TYPE_EPHEMERAL = 2;
}

enum DeliveryMode {
  DELIVERY_MODE_UNSPECIFIED = 0;
  DELIVERY_MODE_PULL = 1;
  DELIVERY_MODE_PUSH = 2;
}

enum StartPosition {
  START_POSITION_UNSPECIFIED = 0;
  START_POSITION_LATEST = 1;
  START_POSITION_EARLIEST = 2;
  START_POSITION_EXPLICIT_OFFSET = 3;
}

message Topic {
  string topic_id = 1;
  string topic_name = 2;
  google.protobuf.Timestamp created_at = 3;
  uint64 retention_period_seconds = 4;
  uint64 retention_bytes = 5;
}

message Subscription {
  string subscription_id = 1;
  string subscription_name = 2;
  string topic_id = 3;
  SubscriptionType type = 4;
  DeliveryMode delivery_mode = 5;
  StartPosition start_position = 6;
  uint64 start_offset = 7;
  uint64 ack_timeout_seconds = 8;
  google.protobuf.Timestamp created_at = 9;
}

message PubSubMessage {
  string message_id = 1;
  uint64 offset = 2;
  bytes body = 3;
  google.protobuf.Timestamp published_at = 4;
}

message PublishMessage {
  bytes body = 1;
}

message ConsumeMessage {
  string message_id = 1;
  uint64 offset = 2;
  bytes body = 3;
  string lease_token = 4;
}

message ListTopicsRequest {
  uint32 limit = 1;
  uint32 offset = 2;
}

message ListTopicsResponse {
  repeated DescribeTopicResponse topics = 1;
}

message DescribeTopicRequest {
  string topic_id = 1;
  string topic_name = 2;
}

message DescribeTopicResponse {
  string topic_id = 1;
  string topic_name = 2;
  google.protobuf.Timestamp created_at = 3;
  uint64 retention_period_seconds = 4;
  uint64 retention_bytes = 5;
}

message CreateTopicRequest {
  string topic_name = 1;
  uint64 retention_period_seconds = 2;
  uint64 retention_bytes = 3;
}

message CreateTopicResponse {
  string topic_id = 1;
}

message DeleteTopicRequest {
  string topic_id = 1;
}

message DeleteTopicResponse {}

message ListSubscriptionsRequest {
  string topic_id = 1;
}

message ListSubscriptionsResponse {
  repeated DescribeSubscriptionResponse subscriptions = 1;
}

message DescribeSubscriptionRequest {
  string subscription_id = 1;
}

message DescribeSubscriptionResponse {
  string subscription_id = 1;
  string subscription_name = 2;
  string topic_id = 3;
  SubscriptionType type = 4;
  DeliveryMode delivery_mode = 5;
  StartPosition start_position = 6;
  uint64 start_offset = 7;
  uint64 ack_timeout_seconds = 8;
  uint64 acked_offset = 9;
  uint64 next_read_offset = 10;
  google.protobuf.Timestamp created_at = 11;
}

message CreateSubscriptionRequest {
  string topic_id = 1;
  string subscription_name = 2;
  SubscriptionType type = 3;
  DeliveryMode delivery_mode = 4;
  StartPosition start_position = 5;
  uint64 start_offset = 6;
  uint64 ack_timeout_seconds = 7;
}

message CreateSubscriptionResponse {
  string subscription_id = 1;
  uint64 start_offset = 2;
}

message DeleteSubscriptionRequest {
  string subscription_id = 1;
}

message DeleteSubscriptionResponse {}

message PublishRequest {
  string topic_id = 1;
  repeated PublishMessage messages = 2;
}

message PublishResponse {
  repeated string message_ids = 1;
  uint64 last_offset = 2;
}

message ConsumePullRequest {
  string subscription_id = 1;
  uint32 batch_size = 2;
  string consumer_token = 3;
}

message ConsumePullResponse {
  repeated ConsumeMessage messages = 1;
}

message ConsumePushRequest {
  string subscription_id = 1;
  uint32 batch_size = 2;
  string consumer_token = 3;
}

message ConsumePushResponse {
  ConsumeMessage message = 1;
}

message AckRequest {
  string subscription_id = 1;
  repeated string message_ids = 2;
}

message AckResponse {
  uint32 acked_count = 1;
}
```

Run:

- `make schema`

- [ ] **Step 4: Extend the shared gRPC client with pub/sub methods**

Update `internal/client/client.go`:

```go
type Client struct {
	conn          *grpc.ClientConn
	queueClient   v1.PlainQServiceClient
	pubSubClient  v1.PubSubServiceClient
}

func New(addr string, options ...Option) (*Client, error) {
	opts := Options{
		dialTimeout:  dialTimeout,
		interceptors: make([]grpc.UnaryClientInterceptor, 0, 10),
	}

	for _, option := range options {
		option(&opts)
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.dialTimeout)
	defer cancel()

	conn, dialErr := grpc.DialContext(ctx, addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUserAgent(opts.userAgent),
		grpc.WithChainUnaryInterceptor(opts.interceptors...),
	)
	if dialErr != nil {
		return nil, fmt.Errorf("connect to server: %w", dialErr)
	}

	return &Client{
		conn:         conn,
		queueClient:  v1.NewPlainQServiceClient(conn),
		pubSubClient: v1.NewPubSubServiceClient(conn),
	}, nil
}

func (c *Client) CreateTopic(ctx context.Context, in *v1.CreateTopicRequest, opts ...grpc.CallOption) (*v1.CreateTopicResponse, error) {
	return c.pubSubClient.CreateTopic(ctx, in, opts...)
}

func (c *Client) CreateSubscription(ctx context.Context, in *v1.CreateSubscriptionRequest, opts ...grpc.CallOption) (*v1.CreateSubscriptionResponse, error) {
	return c.pubSubClient.CreateSubscription(ctx, in, opts...)
}

func (c *Client) Publish(ctx context.Context, in *v1.PublishRequest, opts ...grpc.CallOption) (*v1.PublishResponse, error) {
	return c.pubSubClient.Publish(ctx, in, opts...)
}

func (c *Client) ConsumePull(ctx context.Context, in *v1.ConsumePullRequest, opts ...grpc.CallOption) (*v1.ConsumePullResponse, error) {
	return c.pubSubClient.ConsumePull(ctx, in, opts...)
}

func (c *Client) Ack(ctx context.Context, in *v1.AckRequest, opts ...grpc.CallOption) (*v1.AckResponse, error) {
	return c.pubSubClient.Ack(ctx, in, opts...)
}
```

- [ ] **Step 5: Run the client smoke test and commit**

Run:

- `go test ./internal/client -run TestClient_PubSubMethodsCompile -count=1`

Expected: PASS

Commit:

```bash
git add Makefile schema/v1/schema.proto internal/client/client.go internal/client/client_test.go internal/server/schema/v1/schema.pb.go internal/server/schema/v1/schema.pb.json.go internal/server/schema/v1/schema_grpc.pb.go internal/server/schema/v1/schema_vtproto.pb.go
git commit -m "feat: add pubsub protobuf contract"
```

### Task 2: Add The Pub/Sub Service Shell, Validation, And Unary gRPC Handlers

**Files:**
- Create: `internal/server/service/pubsub/service.go`
- Create: `internal/server/service/pubsub/grpc_transport.go`
- Create: `internal/server/service/pubsub/validation.go`
- Create: `internal/server/service/pubsub/service_test.go`
- Create: `internal/server/service/pubsub/validation_test.go`

- [ ] **Step 1: Write failing validation and delegation tests**

Create `internal/server/service/pubsub/validation_test.go`:

```go
package pubsub

import (
	"testing"

	"github.com/maxatome/go-testdeep/td"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/idkit"
)

func TestValidateTopicID(t *testing.T) {
	td.CmpNoError(t, validateTopicID(idkit.XID()))
	td.CmpErrorIs(t, validateTopicID(""), pqerr.ErrInvalidID)
	td.CmpErrorIs(t, validateTopicID("bad-topic"), pqerr.ErrInvalidID)
}

func TestValidateSubscriptionIDFromRequest(t *testing.T) {
	td.CmpNoError(t, validateSubscriptionIDFromRequest(&v1.AckRequest{SubscriptionId: idkit.XID()}))
	td.CmpErrorIs(t, validateSubscriptionIDFromRequest(&v1.AckRequest{SubscriptionId: "bad-sub"}), pqerr.ErrInvalidID)
}
```

Create `internal/server/service/pubsub/service_test.go`:

```go
package pubsub

import (
	"context"
	"errors"
	"testing"

	"github.com/maxatome/go-testdeep/td"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mockStorage struct {
	Storage
	createTopic func(context.Context, *v1.CreateTopicRequest) (*v1.CreateTopicResponse, error)
	publish     func(context.Context, *v1.PublishRequest) (*v1.PublishResponse, error)
}

func (m *mockStorage) CreateTopic(ctx context.Context, in *v1.CreateTopicRequest) (*v1.CreateTopicResponse, error) {
	return m.createTopic(ctx, in)
}

func (m *mockStorage) Publish(ctx context.Context, in *v1.PublishRequest) (*v1.PublishResponse, error) {
	return m.publish(ctx, in)
}

func TestService_CreateTopic(t *testing.T) {
	svc := NewService(nil, &mockStorage{
		createTopic: func(context.Context, *v1.CreateTopicRequest) (*v1.CreateTopicResponse, error) {
			return &v1.CreateTopicResponse{TopicId: "c5g8v4j4f4a1n8ncb4q0n6k4mq"}, nil
		},
	})

	out, err := svc.CreateTopic(context.Background(), &v1.CreateTopicRequest{TopicName: "orders"})
	td.CmpNoError(t, err)
	td.Cmp(t, out.GetTopicId(), "c5g8v4j4f4a1n8ncb4q0n6k4mq")
}

func TestService_PublishWrapsStorageErrors(t *testing.T) {
	svc := NewService(nil, &mockStorage{
		publish: func(context.Context, *v1.PublishRequest) (*v1.PublishResponse, error) {
			return nil, errors.New("boom")
		},
	})

	_, err := svc.Publish(context.Background(), &v1.PublishRequest{TopicId: "c5g8v4j4f4a1n8ncb4q0n6k4mq"})
	td.Cmp(t, status.Code(err), codes.Internal)
}
```

- [ ] **Step 2: Run the new package tests and verify they fail**

Run: `go test ./internal/server/service/pubsub -count=1`

Expected: FAIL with compile errors because `pubsub` does not exist yet.

- [ ] **Step 3: Create the service package and validation helpers**

Create `internal/server/service/pubsub/service.go`:

```go
package pubsub

import (
	"context"
	"log/slog"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"google.golang.org/grpc"
)

type Storage interface {
	CreateTopic(context.Context, *v1.CreateTopicRequest) (*v1.CreateTopicResponse, error)
	DescribeTopic(context.Context, *v1.DescribeTopicRequest) (*v1.DescribeTopicResponse, error)
	ListTopics(context.Context, *v1.ListTopicsRequest) (*v1.ListTopicsResponse, error)
	DeleteTopic(context.Context, *v1.DeleteTopicRequest) (*v1.DeleteTopicResponse, error)
	CreateSubscription(context.Context, *v1.CreateSubscriptionRequest) (*v1.CreateSubscriptionResponse, error)
	DescribeSubscription(context.Context, *v1.DescribeSubscriptionRequest) (*v1.DescribeSubscriptionResponse, error)
	ListSubscriptions(context.Context, *v1.ListSubscriptionsRequest) (*v1.ListSubscriptionsResponse, error)
	DeleteSubscription(context.Context, *v1.DeleteSubscriptionRequest) (*v1.DeleteSubscriptionResponse, error)
	Publish(context.Context, *v1.PublishRequest) (*v1.PublishResponse, error)
	ConsumePull(context.Context, *v1.ConsumePullRequest) (*v1.ConsumePullResponse, error)
	Ack(context.Context, *v1.AckRequest) (*v1.AckResponse, error)
	ReadMessages(context.Context, string, uint64, uint32) ([]*v1.ConsumeMessage, error)
}

type Service struct {
	v1.UnimplementedPubSubServiceServer

	logger  *slog.Logger
	storage Storage
}

func NewService(logger *slog.Logger, storage Storage) *Service {
	return &Service{
		logger:  logger,
		storage: storage,
	}
}

func (s *Service) Mount(server *grpc.Server) {
	v1.RegisterPubSubServiceServer(server, s)
}
```

Create `internal/server/service/pubsub/validation.go`:

```go
package pubsub

import (
	"strings"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/idkit"
)

func validateTopicID(topicID string) error {
	if topicID == "" {
		return pqerr.ErrInvalidID
	}

	if err := idkit.ValidateXID(strings.ToLower(topicID)); err != nil {
		return pqerr.ErrInvalidID
	}

	return nil
}

func validateSubscriptionID(subscriptionID string) error {
	if subscriptionID == "" {
		return pqerr.ErrInvalidID
	}

	if err := idkit.ValidateXID(strings.ToLower(subscriptionID)); err != nil {
		return pqerr.ErrInvalidID
	}

	return nil
}

func validateSubscriptionIDFromRequest(r interface{ GetSubscriptionId() string }) error {
	if r == nil {
		return pqerr.ErrInvalidID
	}

	return validateSubscriptionID(r.GetSubscriptionId())
}

func validateDescribeTopicRequest(r *v1.DescribeTopicRequest) error {
	if r == nil {
		return pqerr.ErrInvalidID
	}

	if r.GetTopicId() != "" {
		return validateTopicID(r.GetTopicId())
	}

	if r.GetTopicName() == "" {
		return pqerr.ErrInvalidID
	}

	return nil
}
```

- [ ] **Step 4: Add gRPC handlers mirroring the queue service style**

Create `internal/server/service/pubsub/grpc_transport.go`:

```go
package pubsub

import (
	"context"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/servekit/grpckit"
)

func (s *Service) CreateTopic(ctx context.Context, in *v1.CreateTopicRequest) (*v1.CreateTopicResponse, error) {
	out, err := s.storage.CreateTopic(ctx, in)
	if err != nil {
		return grpckit.ErrorGRPC[*v1.CreateTopicResponse](ctx, err)
	}

	return out, nil
}

func (s *Service) DescribeTopic(ctx context.Context, in *v1.DescribeTopicRequest) (*v1.DescribeTopicResponse, error) {
	if err := validateDescribeTopicRequest(in); err != nil {
		return grpckit.ErrorGRPC[*v1.DescribeTopicResponse](ctx, err)
	}

	out, err := s.storage.DescribeTopic(ctx, in)
	if err != nil {
		return grpckit.ErrorGRPC[*v1.DescribeTopicResponse](ctx, err)
	}

	return out, nil
}

func (s *Service) ListTopics(ctx context.Context, in *v1.ListTopicsRequest) (*v1.ListTopicsResponse, error) {
	out, err := s.storage.ListTopics(ctx, in)
	if err != nil {
		return grpckit.ErrorGRPC[*v1.ListTopicsResponse](ctx, err)
	}

	return out, nil
}

func (s *Service) DeleteTopic(ctx context.Context, in *v1.DeleteTopicRequest) (*v1.DeleteTopicResponse, error) {
	if err := validateTopicID(in.GetTopicId()); err != nil {
		return grpckit.ErrorGRPC[*v1.DeleteTopicResponse](ctx, err)
	}

	out, err := s.storage.DeleteTopic(ctx, in)
	if err != nil {
		return grpckit.ErrorGRPC[*v1.DeleteTopicResponse](ctx, err)
	}

	return out, nil
}

func (s *Service) CreateSubscription(ctx context.Context, in *v1.CreateSubscriptionRequest) (*v1.CreateSubscriptionResponse, error) {
	if err := validateTopicID(in.GetTopicId()); err != nil {
		return grpckit.ErrorGRPC[*v1.CreateSubscriptionResponse](ctx, err)
	}

	out, err := s.storage.CreateSubscription(ctx, in)
	if err != nil {
		return grpckit.ErrorGRPC[*v1.CreateSubscriptionResponse](ctx, err)
	}

	return out, nil
}

func (s *Service) DescribeSubscription(ctx context.Context, in *v1.DescribeSubscriptionRequest) (*v1.DescribeSubscriptionResponse, error) {
	if err := validateSubscriptionID(in.GetSubscriptionId()); err != nil {
		return grpckit.ErrorGRPC[*v1.DescribeSubscriptionResponse](ctx, err)
	}

	out, err := s.storage.DescribeSubscription(ctx, in)
	if err != nil {
		return grpckit.ErrorGRPC[*v1.DescribeSubscriptionResponse](ctx, err)
	}

	return out, nil
}

func (s *Service) ListSubscriptions(ctx context.Context, in *v1.ListSubscriptionsRequest) (*v1.ListSubscriptionsResponse, error) {
	if err := validateTopicID(in.GetTopicId()); err != nil {
		return grpckit.ErrorGRPC[*v1.ListSubscriptionsResponse](ctx, err)
	}

	out, err := s.storage.ListSubscriptions(ctx, in)
	if err != nil {
		return grpckit.ErrorGRPC[*v1.ListSubscriptionsResponse](ctx, err)
	}

	return out, nil
}

func (s *Service) DeleteSubscription(ctx context.Context, in *v1.DeleteSubscriptionRequest) (*v1.DeleteSubscriptionResponse, error) {
	if err := validateSubscriptionID(in.GetSubscriptionId()); err != nil {
		return grpckit.ErrorGRPC[*v1.DeleteSubscriptionResponse](ctx, err)
	}

	out, err := s.storage.DeleteSubscription(ctx, in)
	if err != nil {
		return grpckit.ErrorGRPC[*v1.DeleteSubscriptionResponse](ctx, err)
	}

	return out, nil
}

func (s *Service) Publish(ctx context.Context, in *v1.PublishRequest) (*v1.PublishResponse, error) {
	if err := validateTopicID(in.GetTopicId()); err != nil {
		return grpckit.ErrorGRPC[*v1.PublishResponse](ctx, err)
	}

	out, err := s.storage.Publish(ctx, in)
	if err != nil {
		return grpckit.ErrorGRPC[*v1.PublishResponse](ctx, err)
	}

	return out, nil
}

func (s *Service) ConsumePull(ctx context.Context, in *v1.ConsumePullRequest) (*v1.ConsumePullResponse, error) {
	if err := validateSubscriptionID(in.GetSubscriptionId()); err != nil {
		return grpckit.ErrorGRPC[*v1.ConsumePullResponse](ctx, err)
	}

	out, err := s.storage.ConsumePull(ctx, in)
	if err != nil {
		return grpckit.ErrorGRPC[*v1.ConsumePullResponse](ctx, err)
	}

	return out, nil
}

func (s *Service) Ack(ctx context.Context, in *v1.AckRequest) (*v1.AckResponse, error) {
	if err := validateSubscriptionIDFromRequest(in); err != nil {
		return grpckit.ErrorGRPC[*v1.AckResponse](ctx, err)
	}

	out, err := s.storage.Ack(ctx, in)
	if err != nil {
		return grpckit.ErrorGRPC[*v1.AckResponse](ctx, err)
	}

	return out, nil
}
```

- [ ] **Step 5: Run the package tests and commit**

Run:

- `go test ./internal/server/service/pubsub -count=1`

Expected: PASS

Commit:

```bash
git add internal/server/service/pubsub/service.go internal/server/service/pubsub/grpc_transport.go internal/server/service/pubsub/validation.go internal/server/service/pubsub/service_test.go internal/server/service/pubsub/validation_test.go
git commit -m "feat: add pubsub service shell"
```

### Task 3: Implement SQLite Topic, Subscription, And Publish Persistence

**Files:**
- Modify: `internal/server/mutations/storage/sqlite/1_schema.sql`
- Modify: `sqlc/sqlite/schema.sql`
- Create: `internal/server/service/pubsub/litestore/queries/pubsub.sql`
- Create: `internal/server/service/pubsub/litestore/query.go`
- Create: `internal/server/service/pubsub/litestore/storage.go`
- Create: `internal/server/service/pubsub/litestore/query_test.go`
- Create: `internal/server/service/pubsub/litestore/storage_test.go`
- Create: `internal/server/service/pubsub/litestore/sqlcgen/db.go`
- Create: `internal/server/service/pubsub/litestore/sqlcgen/models.go`
- Create: `internal/server/service/pubsub/litestore/sqlcgen/pubsub.sql.go`

- [ ] **Step 1: Write the failing SQLite storage tests**

Create `internal/server/service/pubsub/litestore/storage_test.go`:

```go
package litestore

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/maxatome/go-testdeep/td"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/mutations"
	"github.com/marsolab/servekit/dbkit/litekit"
)

func newTestStorage(t *testing.T) *Storage {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "pubsub.db")
	conn, err := litekit.New(dbPath)
	td.CmpNoError(t, err)

	evolver, err := litekit.NewEvolver(conn, mutations.SqliteStorageMutations())
	td.CmpNoError(t, err)
	td.CmpNoError(t, evolver.MutateSchema())

	store, err := New(conn)
	td.CmpNoError(t, err)

	t.Cleanup(func() {
		td.CmpNoError(t, store.Close())
		td.CmpNoError(t, conn.Close())
	})

	return store
}

func TestStorage_CreateTopicAndPublish(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage(t)

	topic, err := store.CreateTopic(ctx, &v1.CreateTopicRequest{
		TopicName:              "orders",
		RetentionPeriodSeconds: uint64((24 * time.Hour).Seconds()),
	})
	td.CmpNoError(t, err)

	pub, err := store.Publish(ctx, &v1.PublishRequest{
		TopicId: topic.GetTopicId(),
		Messages: []*v1.PublishMessage{
			{Body: []byte("one")},
			{Body: []byte("two")},
		},
	})
	td.CmpNoError(t, err)
	td.CmpLen(t, pub.GetMessageIds(), 2)
	td.Cmp(t, pub.GetLastOffset(), uint64(2))
}

func TestStorage_CreateSubscriptionStartsAtLatest(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage(t)

	topic, err := store.CreateTopic(ctx, &v1.CreateTopicRequest{TopicName: "invoices"})
	td.CmpNoError(t, err)

	_, err = store.Publish(ctx, &v1.PublishRequest{
		TopicId: topic.GetTopicId(),
		Messages: []*v1.PublishMessage{
			{Body: []byte("before")},
		},
	})
	td.CmpNoError(t, err)

	sub, err := store.CreateSubscription(ctx, &v1.CreateSubscriptionRequest{
		TopicId:           topic.GetTopicId(),
		SubscriptionName:  "billing-worker",
		Type:              v1.SubscriptionType_SUBSCRIPTION_TYPE_DURABLE,
		DeliveryMode:      v1.DeliveryMode_DELIVERY_MODE_PULL,
		StartPosition:     v1.StartPosition_START_POSITION_LATEST,
		AckTimeoutSeconds: 30,
	})
	td.CmpNoError(t, err)
	td.Cmp(t, sub.GetStartOffset(), uint64(1))
}

func TestStorage_DescribeTopicAndListSubscriptions(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage(t)

	topic, err := store.CreateTopic(ctx, &v1.CreateTopicRequest{TopicName: "support"})
	td.CmpNoError(t, err)

	_, err = store.CreateSubscription(ctx, &v1.CreateSubscriptionRequest{
		TopicId:           topic.GetTopicId(),
		SubscriptionName:  "support-worker",
		Type:              v1.SubscriptionType_SUBSCRIPTION_TYPE_DURABLE,
		DeliveryMode:      v1.DeliveryMode_DELIVERY_MODE_PULL,
		StartPosition:     v1.StartPosition_START_POSITION_LATEST,
		AckTimeoutSeconds: 30,
	})
	td.CmpNoError(t, err)

	desc, err := store.DescribeTopic(ctx, &v1.DescribeTopicRequest{TopicId: topic.GetTopicId()})
	td.CmpNoError(t, err)
	td.Cmp(t, desc.GetTopicName(), "support")

	subs, err := store.ListSubscriptions(ctx, &v1.ListSubscriptionsRequest{TopicId: topic.GetTopicId()})
	td.CmpNoError(t, err)
	td.CmpLen(t, subs.GetSubscriptions(), 1)
}
```

- [ ] **Step 2: Run the SQLite storage tests and verify they fail**

Run: `go test ./internal/server/service/pubsub/litestore -run 'TestStorage_(CreateTopicAndPublish|CreateSubscriptionStartsAtLatest|DescribeTopicAndListSubscriptions)' -count=1`

Expected: FAIL because the schema, queries, and storage package do not exist yet.

- [ ] **Step 3: Add SQLite runtime schema and sqlc metadata queries**

Extend `internal/server/mutations/storage/sqlite/1_schema.sql` and `sqlc/sqlite/schema.sql` with:

```sql
CREATE TABLE pubsub_topics
(
    topic_id                  TEXT      NOT NULL,
    topic_name                TEXT      NOT NULL,
    created_at                TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    next_offset               INTEGER   NOT NULL DEFAULT 0,
    retention_period_seconds  INTEGER   NOT NULL DEFAULT 604800,
    retention_bytes           INTEGER   NOT NULL DEFAULT 0,
    CONSTRAINT pubsub_topics_pk PRIMARY KEY (topic_id),
    CONSTRAINT pubsub_topics_name_uq UNIQUE (topic_name)
);

CREATE TABLE pubsub_subscriptions
(
    subscription_id        TEXT      NOT NULL,
    subscription_name      TEXT      NOT NULL,
    topic_id               TEXT      NOT NULL,
    subscription_type      INTEGER   NOT NULL,
    delivery_mode          INTEGER   NOT NULL,
    start_position         INTEGER   NOT NULL,
    start_offset           INTEGER   NOT NULL DEFAULT 0,
    ack_timeout_seconds    INTEGER   NOT NULL DEFAULT 30,
    acked_offset           INTEGER   NOT NULL DEFAULT 0,
    next_read_offset       INTEGER   NOT NULL DEFAULT 1,
    retention_skip_count   INTEGER   NOT NULL DEFAULT 0,
    created_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pubsub_subscriptions_pk PRIMARY KEY (subscription_id),
    CONSTRAINT pubsub_subscriptions_name_uq UNIQUE (topic_id, subscription_name)
);

CREATE TABLE pubsub_messages
(
    topic_id      TEXT      NOT NULL,
    topic_offset  INTEGER   NOT NULL,
    message_id    TEXT      NOT NULL,
    body          BLOB      NOT NULL,
    published_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    size_bytes    INTEGER   NOT NULL,
    CONSTRAINT pubsub_messages_pk PRIMARY KEY (topic_id, topic_offset),
    CONSTRAINT pubsub_messages_id_uq UNIQUE (message_id)
);

CREATE TABLE pubsub_inflight
(
    subscription_id     TEXT      NOT NULL,
    topic_id            TEXT      NOT NULL,
    topic_offset        INTEGER   NOT NULL,
    consumer_token      TEXT      NOT NULL,
    lease_expires_at    TIMESTAMP NOT NULL,
    delivery_attempts   INTEGER   NOT NULL DEFAULT 1,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pubsub_inflight_pk PRIMARY KEY (subscription_id, topic_offset)
);
```

Create `internal/server/service/pubsub/litestore/queries/pubsub.sql`:

```sql
-- name: InsertTopic :exec
INSERT INTO pubsub_topics (
    topic_id,
    topic_name,
    retention_period_seconds,
    retention_bytes
) VALUES (?, ?, ?, ?);

-- name: GetTopicByID :one
SELECT * FROM pubsub_topics WHERE topic_id = ?;

-- name: GetTopicByName :one
SELECT * FROM pubsub_topics WHERE topic_name = ?;

-- name: ListTopics :many
SELECT * FROM pubsub_topics ORDER BY created_at DESC LIMIT ? OFFSET ?;

-- name: DeleteTopic :execrows
DELETE FROM pubsub_topics WHERE topic_id = ?;

-- name: InsertSubscription :exec
INSERT INTO pubsub_subscriptions (
    subscription_id,
    subscription_name,
    topic_id,
    subscription_type,
    delivery_mode,
    start_position,
    start_offset,
    ack_timeout_seconds,
    acked_offset,
    next_read_offset
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetSubscriptionByID :one
SELECT * FROM pubsub_subscriptions WHERE subscription_id = ?;

-- name: ListSubscriptionsByTopic :many
SELECT * FROM pubsub_subscriptions WHERE topic_id = ? ORDER BY created_at DESC;

-- name: DeleteSubscription :execrows
DELETE FROM pubsub_subscriptions WHERE subscription_id = ?;
```

Run:

- `make sqlc-generate`

- [ ] **Step 4: Implement topic creation, subscription creation, and publish in the SQLite store**

Create `internal/server/service/pubsub/litestore/storage.go` with the core transaction shape:

```go
package litestore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/pubsub/litestore/sqlcgen"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/marsolab/servekit/idkit"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Storage struct {
	db      *litekit.Conn
	queries *sqlcgen.Queries
	stop    func()
}

func New(db *litekit.Conn) (*Storage, error) {
	s := &Storage{
		db:      db,
		queries: sqlcgen.New(db),
		stop:    func() {},
	}

	return s, nil
}

func (s *Storage) Close() error {
	s.stop()
	return nil
}

func (s *Storage) CreateTopic(ctx context.Context, in *v1.CreateTopicRequest) (*v1.CreateTopicResponse, error) {
	retentionSeconds := in.GetRetentionPeriodSeconds()
	if retentionSeconds == 0 {
		retentionSeconds = uint64((7 * 24 * time.Hour).Seconds())
	}

	topicID := idkit.XID()
	if err := s.queries.InsertTopic(ctx, sqlcgen.InsertTopicParams{
		TopicID:                topicID,
		TopicName:              in.GetTopicName(),
		RetentionPeriodSeconds: int64(retentionSeconds),
		RetentionBytes:         int64(in.GetRetentionBytes()),
	}); err != nil {
		return nil, fmt.Errorf("insert topic: %w", err)
	}

	return &v1.CreateTopicResponse{TopicId: topicID}, nil
}

func (s *Storage) DescribeTopic(ctx context.Context, in *v1.DescribeTopicRequest) (*v1.DescribeTopicResponse, error) {
	var (
		row sqlcgen.PubsubTopic
		err error
	)

	switch {
	case in.GetTopicId() != "":
		row, err = s.queries.GetTopicByID(ctx, in.GetTopicId())
	case in.GetTopicName() != "":
		row, err = s.queries.GetTopicByName(ctx, in.GetTopicName())
	default:
		return nil, fmt.Errorf("get topic: missing topic identifier")
	}
	if err != nil {
		return nil, fmt.Errorf("get topic: %w", err)
	}

	return &v1.DescribeTopicResponse{
		TopicId:                row.TopicID,
		TopicName:              row.TopicName,
		CreatedAt:              timestamppb.New(row.CreatedAt),
		RetentionPeriodSeconds: uint64(row.RetentionPeriodSeconds),
		RetentionBytes:         uint64(row.RetentionBytes),
	}, nil
}

func (s *Storage) ListTopics(ctx context.Context, in *v1.ListTopicsRequest) (*v1.ListTopicsResponse, error) {
	rows, err := s.queries.ListTopics(ctx, sqlcgen.ListTopicsParams{
		Limit:  int64(in.GetLimit()),
		Offset: int64(in.GetOffset()),
	})
	if err != nil {
		return nil, fmt.Errorf("list topics: %w", err)
	}

	out := &v1.ListTopicsResponse{Topics: make([]*v1.DescribeTopicResponse, 0, len(rows))}
	for _, row := range rows {
		out.Topics = append(out.Topics, &v1.DescribeTopicResponse{
			TopicId:                row.TopicID,
			TopicName:              row.TopicName,
			CreatedAt:              timestamppb.New(row.CreatedAt),
			RetentionPeriodSeconds: uint64(row.RetentionPeriodSeconds),
			RetentionBytes:         uint64(row.RetentionBytes),
		})
	}

	return out, nil
}

func (s *Storage) DeleteTopic(ctx context.Context, in *v1.DeleteTopicRequest) (*v1.DeleteTopicResponse, error) {
	if _, err := s.queries.DeleteTopic(ctx, in.GetTopicId()); err != nil {
		return nil, fmt.Errorf("delete topic: %w", err)
	}

	return &v1.DeleteTopicResponse{}, nil
}

func (s *Storage) CreateSubscription(ctx context.Context, in *v1.CreateSubscriptionRequest) (*v1.CreateSubscriptionResponse, error) {
	topic, err := s.queries.GetTopicByID(ctx, in.GetTopicId())
	if err != nil {
		return nil, fmt.Errorf("get topic: %w", err)
	}

	subscriptionType := in.GetType()
	if subscriptionType == v1.SubscriptionType_SUBSCRIPTION_TYPE_UNSPECIFIED {
		subscriptionType = v1.SubscriptionType_SUBSCRIPTION_TYPE_DURABLE
	}

	deliveryMode := in.GetDeliveryMode()
	if deliveryMode == v1.DeliveryMode_DELIVERY_MODE_UNSPECIFIED {
		if subscriptionType == v1.SubscriptionType_SUBSCRIPTION_TYPE_EPHEMERAL {
			deliveryMode = v1.DeliveryMode_DELIVERY_MODE_PUSH
		} else {
			deliveryMode = v1.DeliveryMode_DELIVERY_MODE_PULL
		}
	}

	startPosition := in.GetStartPosition()
	if startPosition == v1.StartPosition_START_POSITION_UNSPECIFIED {
		startPosition = v1.StartPosition_START_POSITION_LATEST
	}

	ackTimeoutSeconds := in.GetAckTimeoutSeconds()
	if ackTimeoutSeconds == 0 {
		ackTimeoutSeconds = 30
	}

	startOffset := int64(topic.NextOffset)
	if startPosition == v1.StartPosition_START_POSITION_EARLIEST {
		startOffset = 0
	}
	if startPosition == v1.StartPosition_START_POSITION_EXPLICIT_OFFSET {
		startOffset = int64(in.GetStartOffset())
	}

	subscriptionID := idkit.XID()
	if err := s.queries.InsertSubscription(ctx, sqlcgen.InsertSubscriptionParams{
		SubscriptionID:     subscriptionID,
		SubscriptionName:   in.GetSubscriptionName(),
		TopicID:            in.GetTopicId(),
		SubscriptionType:   int64(subscriptionType),
		DeliveryMode:       int64(deliveryMode),
		StartPosition:      int64(startPosition),
		StartOffset:        startOffset,
		AckTimeoutSeconds:  int64(ackTimeoutSeconds),
		AckedOffset:        startOffset,
		NextReadOffset:     startOffset + 1,
	}); err != nil {
		return nil, fmt.Errorf("insert subscription: %w", err)
	}

	return &v1.CreateSubscriptionResponse{
		SubscriptionId: subscriptionID,
		StartOffset:    uint64(startOffset),
	}, nil
}

func (s *Storage) DescribeSubscription(ctx context.Context, in *v1.DescribeSubscriptionRequest) (*v1.DescribeSubscriptionResponse, error) {
	row, err := s.queries.GetSubscriptionByID(ctx, in.GetSubscriptionId())
	if err != nil {
		return nil, fmt.Errorf("get subscription: %w", err)
	}

	return &v1.DescribeSubscriptionResponse{
		SubscriptionId:    row.SubscriptionID,
		SubscriptionName:  row.SubscriptionName,
		TopicId:           row.TopicID,
		Type:              v1.SubscriptionType(row.SubscriptionType),
		DeliveryMode:      v1.DeliveryMode(row.DeliveryMode),
		StartPosition:     v1.StartPosition(row.StartPosition),
		StartOffset:       uint64(row.StartOffset),
		AckTimeoutSeconds: uint64(row.AckTimeoutSeconds),
		AckedOffset:       uint64(row.AckedOffset),
		NextReadOffset:    uint64(row.NextReadOffset),
		CreatedAt:         timestamppb.New(row.CreatedAt),
	}, nil
}

func (s *Storage) ListSubscriptions(ctx context.Context, in *v1.ListSubscriptionsRequest) (*v1.ListSubscriptionsResponse, error) {
	rows, err := s.queries.ListSubscriptionsByTopic(ctx, in.GetTopicId())
	if err != nil {
		return nil, fmt.Errorf("list subscriptions: %w", err)
	}

	out := &v1.ListSubscriptionsResponse{
		Subscriptions: make([]*v1.DescribeSubscriptionResponse, 0, len(rows)),
	}
	for _, row := range rows {
		out.Subscriptions = append(out.Subscriptions, &v1.DescribeSubscriptionResponse{
			SubscriptionId:    row.SubscriptionID,
			SubscriptionName:  row.SubscriptionName,
			TopicId:           row.TopicID,
			Type:              v1.SubscriptionType(row.SubscriptionType),
			DeliveryMode:      v1.DeliveryMode(row.DeliveryMode),
			StartPosition:     v1.StartPosition(row.StartPosition),
			StartOffset:       uint64(row.StartOffset),
			AckTimeoutSeconds: uint64(row.AckTimeoutSeconds),
			AckedOffset:       uint64(row.AckedOffset),
			NextReadOffset:    uint64(row.NextReadOffset),
			CreatedAt:         timestamppb.New(row.CreatedAt),
		})
	}

	return out, nil
}

func (s *Storage) DeleteSubscription(ctx context.Context, in *v1.DeleteSubscriptionRequest) (*v1.DeleteSubscriptionResponse, error) {
	if _, err := s.queries.DeleteSubscription(ctx, in.GetSubscriptionId()); err != nil {
		return nil, fmt.Errorf("delete subscription: %w", err)
	}

	return &v1.DeleteSubscriptionResponse{}, nil
}

func (s *Storage) ReadMessages(ctx context.Context, topicID string, fromOffset uint64, limit uint32) ([]*v1.ConsumeMessage, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT topic_offset, message_id, body
		FROM pubsub_messages
		WHERE topic_id = ?
		  AND topic_offset >= ?
		ORDER BY topic_offset
		LIMIT ?
	`, topicID, fromOffset, limit)
	if err != nil {
		return nil, fmt.Errorf("read topic messages: %w", err)
	}
	defer rows.Close()

	out := make([]*v1.ConsumeMessage, 0, limit)
	for rows.Next() {
		var (
			offset    int64
			messageID string
			body      []byte
		)

		if err := rows.Scan(&offset, &messageID, &body); err != nil {
			return nil, fmt.Errorf("scan topic message: %w", err)
		}

		out = append(out, &v1.ConsumeMessage{
			MessageId: messageID,
			Offset:    uint64(offset),
			Body:      body,
		})
	}

	return out, nil
}

func (s *Storage) Publish(ctx context.Context, in *v1.PublishRequest) (_ *v1.PublishResponse, sErr error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}

	defer func() { _ = tx.Rollback() }()

	var nextOffset int64
	if err := tx.QueryRowContext(ctx, `
		UPDATE pubsub_topics
		SET next_offset = next_offset + ?
		WHERE topic_id = ?
		RETURNING next_offset
	`, len(in.GetMessages()), in.GetTopicId()).Scan(&nextOffset); err != nil {
		return nil, fmt.Errorf("reserve offsets: %w", err)
	}

	firstOffset := nextOffset - int64(len(in.GetMessages())) + 1
	messageIDs := make([]string, 0, len(in.GetMessages()))

	for idx, msg := range in.GetMessages() {
		messageID := idkit.XID()
		offset := firstOffset + int64(idx)

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO pubsub_messages (topic_id, topic_offset, message_id, body, size_bytes)
			VALUES (?, ?, ?, ?, ?)
		`, in.GetTopicId(), offset, messageID, msg.GetBody(), len(msg.GetBody())); err != nil {
			return nil, fmt.Errorf("insert message %d: %w", idx, err)
		}

		messageIDs = append(messageIDs, messageID)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit publish: %w", err)
	}

	return &v1.PublishResponse{
		MessageIds: messageIDs,
		LastOffset: uint64(nextOffset),
	}, nil
}
```

- [ ] **Step 5: Run the SQLite storage tests and commit**

Run:

- `go test ./internal/server/service/pubsub/litestore -run 'TestStorage_(CreateTopicAndPublish|CreateSubscriptionStartsAtLatest|DescribeTopicAndListSubscriptions)' -count=1`

Expected: PASS

Commit:

```bash
git add internal/server/mutations/storage/sqlite/1_schema.sql sqlc/sqlite/schema.sql internal/server/service/pubsub/litestore/queries/pubsub.sql internal/server/service/pubsub/litestore/query.go internal/server/service/pubsub/litestore/storage.go internal/server/service/pubsub/litestore/query_test.go internal/server/service/pubsub/litestore/storage_test.go internal/server/service/pubsub/litestore/sqlcgen/db.go internal/server/service/pubsub/litestore/sqlcgen/models.go internal/server/service/pubsub/litestore/sqlcgen/pubsub.sql.go
git commit -m "feat: add sqlite pubsub topic storage"
```

### Task 4: Implement SQLite Durable Pull, Ack, Redelivery, And Retention Skip

**Files:**
- Modify: `internal/server/service/pubsub/litestore/storage.go`
- Create: `internal/server/service/pubsub/litestore/gc.go`
- Modify: `internal/server/service/pubsub/litestore/storage_test.go`

- [ ] **Step 1: Write the failing durable-delivery SQLite tests**

Append to `internal/server/service/pubsub/litestore/storage_test.go`:

```go
func TestStorage_ConsumePullAndAckAdvancesCursor(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage(t)

	topic, err := store.CreateTopic(ctx, &v1.CreateTopicRequest{TopicName: "shipping"})
	td.CmpNoError(t, err)

	sub, err := store.CreateSubscription(ctx, &v1.CreateSubscriptionRequest{
		TopicId:           topic.GetTopicId(),
		SubscriptionName:  "shipper",
		Type:              v1.SubscriptionType_SUBSCRIPTION_TYPE_DURABLE,
		DeliveryMode:      v1.DeliveryMode_DELIVERY_MODE_PULL,
		StartPosition:     v1.StartPosition_START_POSITION_EARLIEST,
		AckTimeoutSeconds: 30,
	})
	td.CmpNoError(t, err)

	_, err = store.Publish(ctx, &v1.PublishRequest{
		TopicId: topic.GetTopicId(),
		Messages: []*v1.PublishMessage{
			{Body: []byte("a")},
		},
	})
	td.CmpNoError(t, err)

	pull, err := store.ConsumePull(ctx, &v1.ConsumePullRequest{
		SubscriptionId: sub.GetSubscriptionId(),
		BatchSize:      1,
		ConsumerToken:  "worker-1",
	})
	td.CmpNoError(t, err)
	td.CmpLen(t, pull.GetMessages(), 1)

	ack, err := store.Ack(ctx, &v1.AckRequest{
		SubscriptionId: sub.GetSubscriptionId(),
		MessageIds:     []string{pull.GetMessages()[0].GetMessageId()},
	})
	td.CmpNoError(t, err)
	td.Cmp(t, ack.GetAckedCount(), uint32(1))
}

func TestStorage_LeaseExpiryRedeliversMessage(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage(t)

	topic, _ := store.CreateTopic(ctx, &v1.CreateTopicRequest{TopicName: "returns"})
	sub, _ := store.CreateSubscription(ctx, &v1.CreateSubscriptionRequest{
		TopicId:           topic.GetTopicId(),
		SubscriptionName:  "returns-worker",
		Type:              v1.SubscriptionType_SUBSCRIPTION_TYPE_DURABLE,
		DeliveryMode:      v1.DeliveryMode_DELIVERY_MODE_PULL,
		StartPosition:     v1.StartPosition_START_POSITION_EARLIEST,
		AckTimeoutSeconds: 1,
	})

	_, _ = store.Publish(ctx, &v1.PublishRequest{
		TopicId: topic.GetTopicId(),
		Messages: []*v1.PublishMessage{
			{Body: []byte("retry-me")},
		},
	})

	first, err := store.ConsumePull(ctx, &v1.ConsumePullRequest{
		SubscriptionId: sub.GetSubscriptionId(),
		BatchSize:      1,
		ConsumerToken:  "worker-1",
	})
	td.CmpNoError(t, err)
	td.CmpLen(t, first.GetMessages(), 1)

	time.Sleep(1100 * time.Millisecond)

	second, err := store.ConsumePull(ctx, &v1.ConsumePullRequest{
		SubscriptionId: sub.GetSubscriptionId(),
		BatchSize:      1,
		ConsumerToken:  "worker-2",
	})
	td.CmpNoError(t, err)
	td.CmpLen(t, second.GetMessages(), 1)
	td.Cmp(t, second.GetMessages()[0].GetMessageId(), first.GetMessages()[0].GetMessageId())
}

func TestStorage_ConsumePullSkipsRetentionGap(t *testing.T) {
	ctx := context.Background()
	store := newTestStorage(t)

	topic, err := store.CreateTopic(ctx, &v1.CreateTopicRequest{
		TopicName:              "lagging-worker",
		RetentionPeriodSeconds: 1,
	})
	td.CmpNoError(t, err)

	sub, err := store.CreateSubscription(ctx, &v1.CreateSubscriptionRequest{
		TopicId:           topic.GetTopicId(),
		SubscriptionName:  "analytics",
		Type:              v1.SubscriptionType_SUBSCRIPTION_TYPE_DURABLE,
		DeliveryMode:      v1.DeliveryMode_DELIVERY_MODE_PULL,
		StartPosition:     v1.StartPosition_START_POSITION_EARLIEST,
		AckTimeoutSeconds: 30,
	})
	td.CmpNoError(t, err)

	_, err = store.Publish(ctx, &v1.PublishRequest{
		TopicId: topic.GetTopicId(),
		Messages: []*v1.PublishMessage{
			{Body: []byte("old")},
		},
	})
	td.CmpNoError(t, err)

	time.Sleep(1100 * time.Millisecond)
	td.CmpNoError(t, store.collectExpiredMessages(ctx))

	_, err = store.Publish(ctx, &v1.PublishRequest{
		TopicId: topic.GetTopicId(),
		Messages: []*v1.PublishMessage{
			{Body: []byte("fresh")},
		},
	})
	td.CmpNoError(t, err)

	pull, err := store.ConsumePull(ctx, &v1.ConsumePullRequest{
		SubscriptionId: sub.GetSubscriptionId(),
		BatchSize:      1,
		ConsumerToken:  "worker-1",
	})
	td.CmpNoError(t, err)
	td.CmpLen(t, pull.GetMessages(), 1)
	td.Cmp(t, string(pull.GetMessages()[0].GetBody()), "fresh")

	desc, err := store.DescribeSubscription(ctx, &v1.DescribeSubscriptionRequest{
		SubscriptionId: sub.GetSubscriptionId(),
	})
	td.CmpNoError(t, err)
	td.Cmp(t, desc.GetAckedOffset(), uint64(1))
	td.Cmp(t, desc.GetNextReadOffset(), uint64(3))
}
```

- [ ] **Step 2: Run the durable-delivery tests and verify they fail**

Run: `go test ./internal/server/service/pubsub/litestore -run 'TestStorage_(ConsumePullAndAckAdvancesCursor|LeaseExpiryRedeliversMessage|ConsumePullSkipsRetentionGap)' -count=1`

Expected: FAIL because `ConsumePull` and `Ack` are not implemented yet.

- [ ] **Step 3: Implement durable leasing and ack watermark advancement**

Extend `internal/server/service/pubsub/litestore/storage.go`:

```go
func (s *Storage) ConsumePull(ctx context.Context, in *v1.ConsumePullRequest) (_ *v1.ConsumePullResponse, sErr error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		topicID           string
		nextReadOffset    int64
		ackTimeoutSeconds int64
	)

	if err := tx.QueryRowContext(ctx, `
		SELECT topic_id, next_read_offset, ack_timeout_seconds
		FROM pubsub_subscriptions
		WHERE subscription_id = ?
	`, in.GetSubscriptionId()).Scan(&topicID, &nextReadOffset, &ackTimeoutSeconds); err != nil {
		return nil, fmt.Errorf("load subscription: %w", err)
	}

	var oldestRetainedOffset int64
	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(MIN(topic_offset), 0)
		FROM pubsub_messages
		WHERE topic_id = ?
	`, topicID).Scan(&oldestRetainedOffset); err != nil {
		return nil, fmt.Errorf("load oldest retained offset: %w", err)
	}

	if oldestRetainedOffset > 0 && nextReadOffset < oldestRetainedOffset {
		nextReadOffset = oldestRetainedOffset
		if _, err := tx.ExecContext(ctx, `
			UPDATE pubsub_subscriptions
			SET acked_offset = ?,
			    next_read_offset = ?,
			    retention_skip_count = retention_skip_count + 1
			WHERE subscription_id = ?
		`, oldestRetainedOffset-1, oldestRetainedOffset, in.GetSubscriptionId()); err != nil {
			return nil, fmt.Errorf("record retention skip: %w", err)
		}
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT m.topic_offset, m.message_id, m.body
		FROM pubsub_messages m
		WHERE m.topic_id = ?
		  AND m.topic_offset >= ?
		  AND NOT EXISTS (
		    SELECT 1 FROM pubsub_inflight i
		    WHERE i.subscription_id = ? AND i.topic_offset = m.topic_offset AND i.lease_expires_at > CURRENT_TIMESTAMP
		  )
		ORDER BY m.topic_offset
		LIMIT ?
	`, topicID, nextReadOffset, in.GetSubscriptionId(), in.GetBatchSize())
	if err != nil {
		return nil, fmt.Errorf("select deliverable messages: %w", err)
	}
	defer rows.Close()

	out := &v1.ConsumePullResponse{Messages: make([]*v1.ConsumeMessage, 0, in.GetBatchSize())}
	leaseExpiry := time.Now().Add(time.Duration(ackTimeoutSeconds) * time.Second)

	for rows.Next() {
		var (
			offset    int64
			messageID string
			body      []byte
		)

		if err := rows.Scan(&offset, &messageID, &body); err != nil {
			return nil, fmt.Errorf("scan message: %w", err)
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT OR REPLACE INTO pubsub_inflight (subscription_id, topic_id, topic_offset, consumer_token, lease_expires_at, delivery_attempts)
			VALUES (?, ?, ?, ?, ?, COALESCE((SELECT delivery_attempts + 1 FROM pubsub_inflight WHERE subscription_id = ? AND topic_offset = ?), 1))
		`, in.GetSubscriptionId(), topicID, offset, in.GetConsumerToken(), leaseExpiry, in.GetSubscriptionId(), offset); err != nil {
			return nil, fmt.Errorf("upsert inflight: %w", err)
		}

		out.Messages = append(out.Messages, &v1.ConsumeMessage{
			MessageId:   messageID,
			Offset:      uint64(offset),
			Body:        body,
			LeaseToken:  fmt.Sprintf("%s:%d", in.GetSubscriptionId(), offset),
		})

		nextReadOffset = offset + 1
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE pubsub_subscriptions
		SET next_read_offset = ?
		WHERE subscription_id = ?
	`, nextReadOffset, in.GetSubscriptionId()); err != nil {
		return nil, fmt.Errorf("advance next_read_offset: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit consume: %w", err)
	}

	return out, nil
}

func (s *Storage) Ack(ctx context.Context, in *v1.AckRequest) (_ *v1.AckResponse, sErr error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var acked uint32
	for _, messageID := range in.GetMessageIds() {
		var offset int64
		if err := tx.QueryRowContext(ctx, `
			SELECT topic_offset
			FROM pubsub_messages
			WHERE message_id = ?
		`, messageID).Scan(&offset); err != nil {
			return nil, fmt.Errorf("resolve message offset: %w", err)
		}

		if _, err := tx.ExecContext(ctx, `
			DELETE FROM pubsub_inflight
			WHERE subscription_id = ? AND topic_offset = ?
		`, in.GetSubscriptionId(), offset); err != nil {
			return nil, fmt.Errorf("delete inflight: %w", err)
		}

		acked++
	}

	var watermark int64
	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(MIN(topic_offset), 0)
		FROM pubsub_inflight
		WHERE subscription_id = ?
	`, in.GetSubscriptionId()).Scan(&watermark); err != nil {
		return nil, fmt.Errorf("read inflight watermark: %w", err)
	}

	if watermark == 0 {
		if _, err := tx.ExecContext(ctx, `
			UPDATE pubsub_subscriptions
			SET acked_offset = next_read_offset - 1
			WHERE subscription_id = ?
		`, in.GetSubscriptionId()); err != nil {
			return nil, fmt.Errorf("advance acked_offset: %w", err)
		}
	} else {
		if _, err := tx.ExecContext(ctx, `
			UPDATE pubsub_subscriptions
			SET acked_offset = ?
			WHERE subscription_id = ?
		`, watermark-1, in.GetSubscriptionId()); err != nil {
			return nil, fmt.Errorf("set acked watermark: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit ack: %w", err)
	}

	return &v1.AckResponse{AckedCount: acked}, nil
}
```

- [ ] **Step 4: Add SQLite retention and lease cleanup**

Create `internal/server/service/pubsub/litestore/gc.go`:

```go
package litestore

import (
	"context"
	"time"
)

func (s *Storage) gc(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.collectExpiredLeases(ctx); err != nil {
				continue
			}
			if err := s.collectExpiredMessages(ctx); err != nil {
				continue
			}
		}
	}
}

func (s *Storage) collectExpiredLeases(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM pubsub_inflight
		WHERE lease_expires_at <= CURRENT_TIMESTAMP
	`)
	if err != nil {
		return fmt.Errorf("delete expired inflight leases: %w", err)
	}

	return nil
}

func (s *Storage) collectExpiredMessages(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM pubsub_messages
		WHERE topic_id IN (
		  SELECT topic_id FROM pubsub_topics WHERE retention_period_seconds > 0
		)
		AND published_at <= datetime(
		  'now',
		  '-' || (
		    SELECT retention_period_seconds
		    FROM pubsub_topics t
		    WHERE t.topic_id = pubsub_messages.topic_id
		  ) || ' seconds'
		)
	`)
	if err != nil {
		return fmt.Errorf("delete expired pubsub messages: %w", err)
	}

	return nil
}
```

- [ ] **Step 5: Run the SQLite durable-delivery tests and commit**

Run:

- `go test ./internal/server/service/pubsub/litestore -run 'TestStorage_(ConsumePullAndAckAdvancesCursor|LeaseExpiryRedeliversMessage|ConsumePullSkipsRetentionGap)' -count=1`

Expected: PASS

Commit:

```bash
git add internal/server/service/pubsub/litestore/storage.go internal/server/service/pubsub/litestore/gc.go internal/server/service/pubsub/litestore/storage_test.go
git commit -m "feat: add sqlite pubsub durable delivery"
```

### Task 5: Implement PostgreSQL Topic, Subscription, And Publish Persistence

**Files:**
- Modify: `internal/server/mutations/storage/postgres/1_schema.sql`
- Modify: `sqlc/postgres/schema.sql`
- Create: `internal/server/service/pubsub/pgstore/queries/pubsub.sql`
- Create: `internal/server/service/pubsub/pgstore/query.go`
- Create: `internal/server/service/pubsub/pgstore/storage.go`
- Create: `internal/server/service/pubsub/pgstore/query_test.go`
- Create: `internal/server/service/pubsub/pgstore/storage_test.go`
- Create: `internal/server/service/pubsub/pgstore/sqlcgen/db.go`
- Create: `internal/server/service/pubsub/pgstore/sqlcgen/models.go`
- Create: `internal/server/service/pubsub/pgstore/sqlcgen/pubsub.sql.go`

- [ ] **Step 1: Write the failing PostgreSQL metadata tests with pgxmock**

Create `internal/server/service/pubsub/pgstore/storage_test.go`:

```go
package pgstore

import (
	"context"
	"testing"
	"time"

	"github.com/maxatome/go-testdeep/td"
	"github.com/pashagolub/pgxmock/v4"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
)

func TestStorage_CreateTopic(t *testing.T) {
	pool, mock, err := pgxmock.NewPool()
	td.CmpNoError(t, err)
	defer pool.Close()

	mock.ExpectExec(`INSERT INTO pubsub_topics`).
		WithArgs(pgxmock.AnyArg(), "orders", int64(604800), int64(0)).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	store, err := New(pool)
	td.CmpNoError(t, err)

	out, err := store.CreateTopic(context.Background(), &v1.CreateTopicRequest{
		TopicName: "orders",
	})
	td.CmpNoError(t, err)
	td.Cmp(t, out.GetTopicId() != "", true)
	td.CmpNoError(t, mock.ExpectationsWereMet())
}

func TestStorage_DescribeSubscription(t *testing.T) {
	pool, mock, err := pgxmock.NewPool()
	td.CmpNoError(t, err)
	defer pool.Close()

	mock.ExpectQuery(`SELECT \* FROM pubsub_subscriptions WHERE subscription_id = \$1`).
		WithArgs("sub-1").
		WillReturnRows(pgxmock.NewRows([]string{
			"subscription_id",
			"subscription_name",
			"topic_id",
			"subscription_type",
			"delivery_mode",
			"start_position",
			"start_offset",
			"ack_timeout_seconds",
			"acked_offset",
			"next_read_offset",
			"retention_skip_count",
			"created_at",
		}).AddRow("sub-1", "worker", "topic-1", 1, 1, 1, int64(0), int64(30), int64(0), int64(1), int64(0), time.Now()))

	store, err := New(pool)
	td.CmpNoError(t, err)

	out, err := store.DescribeSubscription(context.Background(), &v1.DescribeSubscriptionRequest{SubscriptionId: "sub-1"})
	td.CmpNoError(t, err)
	td.Cmp(t, out.GetSubscriptionName(), "worker")
	td.CmpNoError(t, mock.ExpectationsWereMet())
}
```

- [ ] **Step 2: Run the PostgreSQL metadata tests and verify they fail**

Run: `go test ./internal/server/service/pubsub/pgstore -run TestStorage_CreateTopic -count=1`

Expected: FAIL because the package and schema do not exist yet.

- [ ] **Step 3: Add PostgreSQL schema, sqlc queries, and generated bindings**

Extend `internal/server/mutations/storage/postgres/1_schema.sql` and `sqlc/postgres/schema.sql` with:

```sql
CREATE TABLE pubsub_topics
(
    topic_id                 varchar(26)               NOT NULL,
    topic_name               text                      NOT NULL,
    created_at               timestamptz DEFAULT now() NOT NULL,
    next_offset              bigint      DEFAULT 0     NOT NULL,
    retention_period_seconds bigint      DEFAULT 604800 NOT NULL,
    retention_bytes          bigint      DEFAULT 0     NOT NULL,
    CONSTRAINT pubsub_topics_pk PRIMARY KEY (topic_id),
    CONSTRAINT pubsub_topics_name_uq UNIQUE (topic_name)
);

CREATE TABLE pubsub_subscriptions
(
    subscription_id      varchar(26)               NOT NULL,
    subscription_name    text                      NOT NULL,
    topic_id             varchar(26)               NOT NULL,
    subscription_type    integer                   NOT NULL,
    delivery_mode        integer                   NOT NULL,
    start_position       integer                   NOT NULL,
    start_offset         bigint      DEFAULT 0     NOT NULL,
    ack_timeout_seconds  bigint      DEFAULT 30    NOT NULL,
    acked_offset         bigint      DEFAULT 0     NOT NULL,
    next_read_offset     bigint      DEFAULT 1     NOT NULL,
    retention_skip_count bigint      DEFAULT 0     NOT NULL,
    created_at           timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT pubsub_subscriptions_pk PRIMARY KEY (subscription_id),
    CONSTRAINT pubsub_subscriptions_name_uq UNIQUE (topic_id, subscription_name)
);

CREATE TABLE pubsub_messages
(
    topic_id      varchar(26)               NOT NULL,
    topic_offset  bigint                    NOT NULL,
    message_id    varchar(26)               NOT NULL,
    body          bytea                     NOT NULL,
    published_at  timestamptz DEFAULT now() NOT NULL,
    size_bytes    bigint                    NOT NULL,
    CONSTRAINT pubsub_messages_pk PRIMARY KEY (topic_id, topic_offset),
    CONSTRAINT pubsub_messages_id_uq UNIQUE (message_id)
);

CREATE TABLE pubsub_inflight
(
    subscription_id   varchar(26)               NOT NULL,
    topic_id          varchar(26)               NOT NULL,
    topic_offset      bigint                    NOT NULL,
    consumer_token    text                      NOT NULL,
    lease_expires_at  timestamptz               NOT NULL,
    delivery_attempts integer     DEFAULT 1     NOT NULL,
    created_at        timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT pubsub_inflight_pk PRIMARY KEY (subscription_id, topic_offset)
);
```

Create `internal/server/service/pubsub/pgstore/queries/pubsub.sql`:

```sql
-- name: InsertTopic :exec
INSERT INTO pubsub_topics (
    topic_id,
    topic_name,
    retention_period_seconds,
    retention_bytes
) VALUES ($1, $2, $3, $4);

-- name: GetTopicByID :one
SELECT * FROM pubsub_topics WHERE topic_id = $1;

-- name: GetTopicByName :one
SELECT * FROM pubsub_topics WHERE topic_name = $1;

-- name: ListTopics :many
SELECT * FROM pubsub_topics ORDER BY created_at DESC LIMIT $1 OFFSET $2;

-- name: DeleteTopic :execrows
DELETE FROM pubsub_topics WHERE topic_id = $1;

-- name: InsertSubscription :exec
INSERT INTO pubsub_subscriptions (
    subscription_id,
    subscription_name,
    topic_id,
    subscription_type,
    delivery_mode,
    start_position,
    start_offset,
    ack_timeout_seconds,
    acked_offset,
    next_read_offset
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: GetSubscriptionByID :one
SELECT * FROM pubsub_subscriptions WHERE subscription_id = $1;

-- name: ListSubscriptionsByTopic :many
SELECT * FROM pubsub_subscriptions WHERE topic_id = $1 ORDER BY created_at DESC;

-- name: DeleteSubscription :execrows
DELETE FROM pubsub_subscriptions WHERE subscription_id = $1;
```

Run:

- `make sqlc-generate`

- [ ] **Step 4: Implement topic creation and publish for the PostgreSQL store**

Create `internal/server/service/pubsub/pgstore/storage.go`:

```go
package pgstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/pubsub/pgstore/sqlcgen"
	"github.com/marsolab/servekit/idkit"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Storage struct {
	pool    *pgxpool.Pool
	queries *sqlcgen.Queries
	stop    func()
}

func New(pool *pgxpool.Pool) (*Storage, error) {
	if pool == nil {
		return nil, errors.New("pool is nil")
	}

	return &Storage{
		pool:    pool,
		queries: sqlcgen.New(pool),
		stop:    func() {},
	}, nil
}

func (s *Storage) Close() error {
	s.stop()
	return nil
}

func (s *Storage) CreateTopic(ctx context.Context, in *v1.CreateTopicRequest) (*v1.CreateTopicResponse, error) {
	retentionSeconds := in.GetRetentionPeriodSeconds()
	if retentionSeconds == 0 {
		retentionSeconds = uint64((7 * 24 * time.Hour).Seconds())
	}

	topicID := idkit.XID()

	if err := s.queries.InsertTopic(ctx, sqlcgen.InsertTopicParams{
		TopicID:                topicID,
		TopicName:              in.GetTopicName(),
		RetentionPeriodSeconds: int64(retentionSeconds),
		RetentionBytes:         int64(in.GetRetentionBytes()),
	}); err != nil {
		return nil, fmt.Errorf("insert topic: %w", err)
	}

	return &v1.CreateTopicResponse{TopicId: topicID}, nil
}

func (s *Storage) DescribeTopic(ctx context.Context, in *v1.DescribeTopicRequest) (*v1.DescribeTopicResponse, error) {
	var (
		row sqlcgen.PubsubTopic
		err error
	)

	switch {
	case in.GetTopicId() != "":
		row, err = s.queries.GetTopicByID(ctx, in.GetTopicId())
	case in.GetTopicName() != "":
		row, err = s.queries.GetTopicByName(ctx, in.GetTopicName())
	default:
		return nil, fmt.Errorf("get topic: missing topic identifier")
	}
	if err != nil {
		return nil, fmt.Errorf("get topic: %w", err)
	}

	return &v1.DescribeTopicResponse{
		TopicId:                row.TopicID,
		TopicName:              row.TopicName,
		CreatedAt:              timestamppb.New(row.CreatedAt.Time),
		RetentionPeriodSeconds: uint64(row.RetentionPeriodSeconds),
		RetentionBytes:         uint64(row.RetentionBytes),
	}, nil
}

func (s *Storage) ListTopics(ctx context.Context, in *v1.ListTopicsRequest) (*v1.ListTopicsResponse, error) {
	rows, err := s.queries.ListTopics(ctx, sqlcgen.ListTopicsParams{
		Limit:  int32(in.GetLimit()),
		Offset: int32(in.GetOffset()),
	})
	if err != nil {
		return nil, fmt.Errorf("list topics: %w", err)
	}

	out := &v1.ListTopicsResponse{Topics: make([]*v1.DescribeTopicResponse, 0, len(rows))}
	for _, row := range rows {
		out.Topics = append(out.Topics, &v1.DescribeTopicResponse{
			TopicId:                row.TopicID,
			TopicName:              row.TopicName,
			CreatedAt:              timestamppb.New(row.CreatedAt.Time),
			RetentionPeriodSeconds: uint64(row.RetentionPeriodSeconds),
			RetentionBytes:         uint64(row.RetentionBytes),
		})
	}

	return out, nil
}

func (s *Storage) DeleteTopic(ctx context.Context, in *v1.DeleteTopicRequest) (*v1.DeleteTopicResponse, error) {
	if _, err := s.queries.DeleteTopic(ctx, in.GetTopicId()); err != nil {
		return nil, fmt.Errorf("delete topic: %w", err)
	}

	return &v1.DeleteTopicResponse{}, nil
}

func (s *Storage) CreateSubscription(ctx context.Context, in *v1.CreateSubscriptionRequest) (*v1.CreateSubscriptionResponse, error) {
	topic, err := s.queries.GetTopicByID(ctx, in.GetTopicId())
	if err != nil {
		return nil, fmt.Errorf("get topic: %w", err)
	}

	subscriptionType := in.GetType()
	if subscriptionType == v1.SubscriptionType_SUBSCRIPTION_TYPE_UNSPECIFIED {
		subscriptionType = v1.SubscriptionType_SUBSCRIPTION_TYPE_DURABLE
	}

	deliveryMode := in.GetDeliveryMode()
	if deliveryMode == v1.DeliveryMode_DELIVERY_MODE_UNSPECIFIED {
		if subscriptionType == v1.SubscriptionType_SUBSCRIPTION_TYPE_EPHEMERAL {
			deliveryMode = v1.DeliveryMode_DELIVERY_MODE_PUSH
		} else {
			deliveryMode = v1.DeliveryMode_DELIVERY_MODE_PULL
		}
	}

	startPosition := in.GetStartPosition()
	if startPosition == v1.StartPosition_START_POSITION_UNSPECIFIED {
		startPosition = v1.StartPosition_START_POSITION_LATEST
	}

	ackTimeoutSeconds := in.GetAckTimeoutSeconds()
	if ackTimeoutSeconds == 0 {
		ackTimeoutSeconds = 30
	}

	startOffset := topic.NextOffset
	if startPosition == v1.StartPosition_START_POSITION_EARLIEST {
		startOffset = 0
	}
	if startPosition == v1.StartPosition_START_POSITION_EXPLICIT_OFFSET {
		startOffset = int64(in.GetStartOffset())
	}

	subscriptionID := idkit.XID()
	if err := s.queries.InsertSubscription(ctx, sqlcgen.InsertSubscriptionParams{
		SubscriptionID:    subscriptionID,
		SubscriptionName:  in.GetSubscriptionName(),
		TopicID:           in.GetTopicId(),
		SubscriptionType:  int32(subscriptionType),
		DeliveryMode:      int32(deliveryMode),
		StartPosition:     int32(startPosition),
		StartOffset:       startOffset,
		AckTimeoutSeconds: int64(ackTimeoutSeconds),
		AckedOffset:       startOffset,
		NextReadOffset:    startOffset + 1,
	}); err != nil {
		return nil, fmt.Errorf("insert subscription: %w", err)
	}

	return &v1.CreateSubscriptionResponse{
		SubscriptionId: subscriptionID,
		StartOffset:    uint64(startOffset),
	}, nil
}

func (s *Storage) DescribeSubscription(ctx context.Context, in *v1.DescribeSubscriptionRequest) (*v1.DescribeSubscriptionResponse, error) {
	row, err := s.queries.GetSubscriptionByID(ctx, in.GetSubscriptionId())
	if err != nil {
		return nil, fmt.Errorf("get subscription: %w", err)
	}

	return &v1.DescribeSubscriptionResponse{
		SubscriptionId:    row.SubscriptionID,
		SubscriptionName:  row.SubscriptionName,
		TopicId:           row.TopicID,
		Type:              v1.SubscriptionType(row.SubscriptionType),
		DeliveryMode:      v1.DeliveryMode(row.DeliveryMode),
		StartPosition:     v1.StartPosition(row.StartPosition),
		StartOffset:       uint64(row.StartOffset),
		AckTimeoutSeconds: uint64(row.AckTimeoutSeconds),
		AckedOffset:       uint64(row.AckedOffset),
		NextReadOffset:    uint64(row.NextReadOffset),
		CreatedAt:         timestamppb.New(row.CreatedAt.Time),
	}, nil
}

func (s *Storage) ListSubscriptions(ctx context.Context, in *v1.ListSubscriptionsRequest) (*v1.ListSubscriptionsResponse, error) {
	rows, err := s.queries.ListSubscriptionsByTopic(ctx, in.GetTopicId())
	if err != nil {
		return nil, fmt.Errorf("list subscriptions: %w", err)
	}

	out := &v1.ListSubscriptionsResponse{
		Subscriptions: make([]*v1.DescribeSubscriptionResponse, 0, len(rows)),
	}
	for _, row := range rows {
		out.Subscriptions = append(out.Subscriptions, &v1.DescribeSubscriptionResponse{
			SubscriptionId:    row.SubscriptionID,
			SubscriptionName:  row.SubscriptionName,
			TopicId:           row.TopicID,
			Type:              v1.SubscriptionType(row.SubscriptionType),
			DeliveryMode:      v1.DeliveryMode(row.DeliveryMode),
			StartPosition:     v1.StartPosition(row.StartPosition),
			StartOffset:       uint64(row.StartOffset),
			AckTimeoutSeconds: uint64(row.AckTimeoutSeconds),
			AckedOffset:       uint64(row.AckedOffset),
			NextReadOffset:    uint64(row.NextReadOffset),
			CreatedAt:         timestamppb.New(row.CreatedAt.Time),
		})
	}

	return out, nil
}

func (s *Storage) DeleteSubscription(ctx context.Context, in *v1.DeleteSubscriptionRequest) (*v1.DeleteSubscriptionResponse, error) {
	if _, err := s.queries.DeleteSubscription(ctx, in.GetSubscriptionId()); err != nil {
		return nil, fmt.Errorf("delete subscription: %w", err)
	}

	return &v1.DeleteSubscriptionResponse{}, nil
}

func (s *Storage) ReadMessages(ctx context.Context, topicID string, fromOffset uint64, limit uint32) ([]*v1.ConsumeMessage, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT topic_offset, message_id, body
		FROM pubsub_messages
		WHERE topic_id = $1
		  AND topic_offset >= $2
		ORDER BY topic_offset
		LIMIT $3
	`, topicID, int64(fromOffset), int32(limit))
	if err != nil {
		return nil, fmt.Errorf("read topic messages: %w", err)
	}
	defer rows.Close()

	out := make([]*v1.ConsumeMessage, 0, limit)
	for rows.Next() {
		var (
			offset    int64
			messageID string
			body      []byte
		)

		if err := rows.Scan(&offset, &messageID, &body); err != nil {
			return nil, fmt.Errorf("scan topic message: %w", err)
		}

		out = append(out, &v1.ConsumeMessage{
			MessageId: messageID,
			Offset:    uint64(offset),
			Body:      body,
		})
	}

	return out, nil
}

func (s *Storage) Publish(ctx context.Context, in *v1.PublishRequest) (_ *v1.PublishResponse, sErr error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var nextOffset int64
	if err := tx.QueryRow(ctx, `
		UPDATE pubsub_topics
		SET next_offset = next_offset + $1
		WHERE topic_id = $2
		RETURNING next_offset
	`, len(in.GetMessages()), in.GetTopicId()).Scan(&nextOffset); err != nil {
		return nil, fmt.Errorf("reserve offsets: %w", err)
	}

	firstOffset := nextOffset - int64(len(in.GetMessages())) + 1
	messageIDs := make([]string, 0, len(in.GetMessages()))

	for idx, msg := range in.GetMessages() {
		messageID := idkit.XID()
		offset := firstOffset + int64(idx)

		if _, err := tx.Exec(ctx, `
			INSERT INTO pubsub_messages (topic_id, topic_offset, message_id, body, size_bytes)
			VALUES ($1, $2, $3, $4, $5)
		`, in.GetTopicId(), offset, messageID, msg.GetBody(), len(msg.GetBody())); err != nil {
			return nil, fmt.Errorf("insert message %d: %w", idx, err)
		}

		messageIDs = append(messageIDs, messageID)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit publish: %w", err)
	}

	return &v1.PublishResponse{
		MessageIds: messageIDs,
		LastOffset: uint64(nextOffset),
	}, nil
}
```

- [ ] **Step 5: Run the PostgreSQL metadata tests and commit**

Run:

- `go test ./internal/server/service/pubsub/pgstore -run 'TestStorage_(CreateTopic|DescribeSubscription)' -count=1`

Expected: PASS

Commit:

```bash
git add internal/server/mutations/storage/postgres/1_schema.sql sqlc/postgres/schema.sql internal/server/service/pubsub/pgstore/queries/pubsub.sql internal/server/service/pubsub/pgstore/query.go internal/server/service/pubsub/pgstore/storage.go internal/server/service/pubsub/pgstore/query_test.go internal/server/service/pubsub/pgstore/storage_test.go internal/server/service/pubsub/pgstore/sqlcgen/db.go internal/server/service/pubsub/pgstore/sqlcgen/models.go internal/server/service/pubsub/pgstore/sqlcgen/pubsub.sql.go
git commit -m "feat: add postgres pubsub topic storage"
```

### Task 6: Implement PostgreSQL Durable Pull, Ack, Redelivery, And Retention Skip

**Files:**
- Modify: `internal/server/service/pubsub/pgstore/storage.go`
- Create: `internal/server/service/pubsub/pgstore/gc.go`
- Modify: `internal/server/service/pubsub/pgstore/storage_test.go`

- [ ] **Step 1: Write the failing PostgreSQL durable-delivery tests**

Append to `internal/server/service/pubsub/pgstore/storage_test.go`:

```go
func TestStorage_ConsumePullCreatesInflightLease(t *testing.T) {
	pool, mock, err := pgxmock.NewPool()
	td.CmpNoError(t, err)
	defer pool.Close()

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT topic_id, next_read_offset, ack_timeout_seconds FROM pubsub_subscriptions`).
		WithArgs("sub-1").
		WillReturnRows(pgxmock.NewRows([]string{"topic_id", "next_read_offset", "ack_timeout_seconds"}).AddRow("topic-1", int64(1), int64(30)))
	mock.ExpectQuery(`SELECT m.topic_offset, m.message_id, m.body FROM pubsub_messages`).
		WithArgs("topic-1", int64(1), "sub-1", uint32(1)).
		WillReturnRows(pgxmock.NewRows([]string{"topic_offset", "message_id", "body"}).AddRow(int64(1), "msg-1", []byte("a")))
	mock.ExpectExec(`INSERT INTO pubsub_inflight`).WillReturnResult(pgxmock.NewResult("INSERT", 1))
	mock.ExpectExec(`UPDATE pubsub_subscriptions SET next_read_offset`).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectCommit()

	store, err := New(pool)
	td.CmpNoError(t, err)

	out, err := store.ConsumePull(context.Background(), &v1.ConsumePullRequest{
		SubscriptionId: "sub-1",
		BatchSize:      1,
		ConsumerToken:  "worker-1",
	})
	td.CmpNoError(t, err)
	td.CmpLen(t, out.GetMessages(), 1)

	td.CmpNoError(t, mock.ExpectationsWereMet())
}

func TestStorage_ConsumePullSkipsRetentionGap(t *testing.T) {
	pool, mock, err := pgxmock.NewPool()
	td.CmpNoError(t, err)
	defer pool.Close()

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT topic_id, next_read_offset, ack_timeout_seconds FROM pubsub_subscriptions`).
		WithArgs("sub-1").
		WillReturnRows(pgxmock.NewRows([]string{"topic_id", "next_read_offset", "ack_timeout_seconds"}).AddRow("topic-1", int64(1), int64(30)))
	mock.ExpectQuery(`SELECT COALESCE\(MIN\(topic_offset\), 0\) FROM pubsub_messages WHERE topic_id = \$1`).
		WithArgs("topic-1").
		WillReturnRows(pgxmock.NewRows([]string{"coalesce"}).AddRow(int64(2)))
	mock.ExpectExec(`UPDATE pubsub_subscriptions SET acked_offset = \$1, next_read_offset = \$2, retention_skip_count = retention_skip_count \+ 1 WHERE subscription_id = \$3`).
		WithArgs(int64(1), int64(2), "sub-1").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectQuery(`SELECT m.topic_offset, m.message_id, m.body FROM pubsub_messages`).
		WithArgs("topic-1", int64(2), "sub-1", uint32(1)).
		WillReturnRows(pgxmock.NewRows([]string{"topic_offset", "message_id", "body"}).AddRow(int64(2), "msg-2", []byte("b")))
	mock.ExpectExec(`INSERT INTO pubsub_inflight`).WillReturnResult(pgxmock.NewResult("INSERT", 1))
	mock.ExpectExec(`UPDATE pubsub_subscriptions SET next_read_offset`).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectCommit()

	store, err := New(pool)
	td.CmpNoError(t, err)

	out, err := store.ConsumePull(context.Background(), &v1.ConsumePullRequest{
		SubscriptionId: "sub-1",
		BatchSize:      1,
		ConsumerToken:  "worker-1",
	})
	td.CmpNoError(t, err)
	td.CmpLen(t, out.GetMessages(), 1)
	td.Cmp(t, out.GetMessages()[0].GetOffset(), uint64(2))

	td.CmpNoError(t, mock.ExpectationsWereMet())
}
```

- [ ] **Step 2: Run the PostgreSQL durable-delivery tests and verify they fail**

Run: `go test ./internal/server/service/pubsub/pgstore -run 'TestStorage_(ConsumePullCreatesInflightLease|ConsumePullSkipsRetentionGap)' -count=1`

Expected: FAIL because `ConsumePull` is not implemented yet.

- [ ] **Step 3: Implement PostgreSQL durable leasing and ack handling**

Extend `internal/server/service/pubsub/pgstore/storage.go`:

```go
func (s *Storage) ConsumePull(ctx context.Context, in *v1.ConsumePullRequest) (_ *v1.ConsumePullResponse, sErr error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		topicID           string
		nextReadOffset    int64
		ackTimeoutSeconds int64
	)

	if err := tx.QueryRow(ctx, `
		SELECT topic_id, next_read_offset, ack_timeout_seconds
		FROM pubsub_subscriptions
		WHERE subscription_id = $1
		FOR UPDATE
	`, in.GetSubscriptionId()).Scan(&topicID, &nextReadOffset, &ackTimeoutSeconds); err != nil {
		return nil, fmt.Errorf("load subscription: %w", err)
	}

	var oldestRetainedOffset int64
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(MIN(topic_offset), 0)
		FROM pubsub_messages
		WHERE topic_id = $1
	`, topicID).Scan(&oldestRetainedOffset); err != nil {
		return nil, fmt.Errorf("load oldest retained offset: %w", err)
	}

	if oldestRetainedOffset > 0 && nextReadOffset < oldestRetainedOffset {
		nextReadOffset = oldestRetainedOffset
		if _, err := tx.Exec(ctx, `
			UPDATE pubsub_subscriptions
			SET acked_offset = $1,
			    next_read_offset = $2,
			    retention_skip_count = retention_skip_count + 1
			WHERE subscription_id = $3
		`, oldestRetainedOffset-1, oldestRetainedOffset, in.GetSubscriptionId()); err != nil {
			return nil, fmt.Errorf("record retention skip: %w", err)
		}
	}

	rows, err := tx.Query(ctx, `
		SELECT m.topic_offset, m.message_id, m.body
		FROM pubsub_messages m
		WHERE m.topic_id = $1
		  AND m.topic_offset >= $2
		  AND NOT EXISTS (
		    SELECT 1 FROM pubsub_inflight i
		    WHERE i.subscription_id = $3 AND i.topic_offset = m.topic_offset AND i.lease_expires_at > now()
		  )
		ORDER BY m.topic_offset
		LIMIT $4
	`, topicID, nextReadOffset, in.GetSubscriptionId(), in.GetBatchSize())
	if err != nil {
		return nil, fmt.Errorf("select deliverable messages: %w", err)
	}
	defer rows.Close()

	out := &v1.ConsumePullResponse{Messages: make([]*v1.ConsumeMessage, 0, in.GetBatchSize())}
	leaseExpiry := time.Now().Add(time.Duration(ackTimeoutSeconds) * time.Second)

	for rows.Next() {
		var (
			offset    int64
			messageID string
			body      []byte
		)

		if err := rows.Scan(&offset, &messageID, &body); err != nil {
			return nil, fmt.Errorf("scan message: %w", err)
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO pubsub_inflight (subscription_id, topic_id, topic_offset, consumer_token, lease_expires_at)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (subscription_id, topic_offset)
			DO UPDATE SET consumer_token = EXCLUDED.consumer_token,
			              lease_expires_at = EXCLUDED.lease_expires_at,
			              delivery_attempts = pubsub_inflight.delivery_attempts + 1
		`, in.GetSubscriptionId(), topicID, offset, in.GetConsumerToken(), leaseExpiry); err != nil {
			return nil, fmt.Errorf("upsert inflight: %w", err)
		}

		out.Messages = append(out.Messages, &v1.ConsumeMessage{
			MessageId:  messageID,
			Offset:     uint64(offset),
			Body:       body,
			LeaseToken: fmt.Sprintf("%s:%d", in.GetSubscriptionId(), offset),
		})

		nextReadOffset = offset + 1
	}

	if _, err := tx.Exec(ctx, `
		UPDATE pubsub_subscriptions
		SET next_read_offset = $1
		WHERE subscription_id = $2
	`, nextReadOffset, in.GetSubscriptionId()); err != nil {
		return nil, fmt.Errorf("advance next_read_offset: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit consume: %w", err)
	}

	return out, nil
}

func (s *Storage) Ack(ctx context.Context, in *v1.AckRequest) (_ *v1.AckResponse, sErr error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var acked uint32
	for _, messageID := range in.GetMessageIds() {
		var offset int64
		if err := tx.QueryRow(ctx, `SELECT topic_offset FROM pubsub_messages WHERE message_id = $1`, messageID).Scan(&offset); err != nil {
			return nil, fmt.Errorf("resolve message offset: %w", err)
		}

		if _, err := tx.Exec(ctx, `
			DELETE FROM pubsub_inflight
			WHERE subscription_id = $1 AND topic_offset = $2
		`, in.GetSubscriptionId(), offset); err != nil {
			return nil, fmt.Errorf("delete inflight: %w", err)
		}

		acked++
	}

	if _, err := tx.Exec(ctx, `
		UPDATE pubsub_subscriptions s
		SET acked_offset = COALESCE((
		  SELECT MIN(i.topic_offset) - 1
		  FROM pubsub_inflight i
		  WHERE i.subscription_id = s.subscription_id
		), s.next_read_offset - 1)
		WHERE s.subscription_id = $1
	`, in.GetSubscriptionId()); err != nil {
		return nil, fmt.Errorf("update ack watermark: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit ack: %w", err)
	}

	return &v1.AckResponse{AckedCount: acked}, nil
}
```

- [ ] **Step 4: Add PostgreSQL cleanup logic**

Create `internal/server/service/pubsub/pgstore/gc.go`:

```go
package pgstore

import (
	"context"
	"fmt"
	"time"
)

func (s *Storage) gc(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.pool.Exec(ctx, `
				DELETE FROM pubsub_inflight
				WHERE lease_expires_at <= now()
			`); err != nil {
				continue
			}

			if _, err := s.pool.Exec(ctx, `
				DELETE FROM pubsub_messages m
				USING pubsub_topics t
				WHERE t.topic_id = m.topic_id
				  AND t.retention_period_seconds > 0
				  AND m.published_at <= now() - make_interval(secs => t.retention_period_seconds::int)
			`); err != nil {
				continue
			}
		}
	}
}
```

- [ ] **Step 5: Run the PostgreSQL durable-delivery tests and commit**

Run:

- `go test ./internal/server/service/pubsub/pgstore -run 'TestStorage_(ConsumePullCreatesInflightLease|ConsumePullSkipsRetentionGap)' -count=1`

Expected: PASS

Commit:

```bash
git add internal/server/service/pubsub/pgstore/storage.go internal/server/service/pubsub/pgstore/gc.go internal/server/service/pubsub/pgstore/storage_test.go
git commit -m "feat: add postgres pubsub durable delivery"
```

### Task 7: Add Push Delivery, Ephemeral Runtime, Server Wiring, And Metrics

**Files:**
- Create: `internal/server/service/pubsub/runtime.go`
- Create: `internal/server/service/pubsub/runtime_test.go`
- Modify: `internal/server/service/pubsub/service.go`
- Modify: `internal/server/service/pubsub/grpc_transport.go`
- Modify: `internal/server/server.go`
- Modify: `cmd/server.go`
- Modify: `internal/server/service/telemetry/observer.go`

- [ ] **Step 1: Write failing runtime and wiring tests**

Create `internal/server/service/pubsub/runtime_test.go`:

```go
package pubsub

import (
	"testing"
	"time"
)

func TestRuntime_NotifyTopicWakesSubscriber(t *testing.T) {
	rt := NewRuntime()
	ch, cancel := rt.SubscribeTopic("topic-1")
	defer cancel()

	rt.NotifyTopic("topic-1", 1)

	select {
	case <-ch:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected topic notification")
	}
}
```

Append to `internal/server/service/pubsub/service_test.go` and add `time` to the existing import list:

```go
func TestService_PublishNotifiesRuntime(t *testing.T) {
	rt := NewRuntime()
	notified, cancel := rt.SubscribeTopic("topic-1")
	defer cancel()

	svc := NewService(nil, &mockStorage{
		publish: func(context.Context, *v1.PublishRequest) (*v1.PublishResponse, error) {
			return &v1.PublishResponse{MessageIds: []string{"m1"}, LastOffset: 1}, nil
		},
	})
	svc.hub = rt

	_, err := svc.Publish(context.Background(), &v1.PublishRequest{
		TopicId: "topic-1",
	})
	td.CmpNoError(t, err)

	select {
	case <-notified:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected runtime notification")
	}
}
```

- [ ] **Step 2: Run the runtime tests and verify they fail**

Run: `go test ./internal/server/service/pubsub -run 'Test(Runtime|Service_PublishNotifiesRuntime)' -count=1`

Expected: FAIL because `Runtime` does not exist yet.

- [ ] **Step 3: Implement the runtime hub and push streaming**

Create `internal/server/service/pubsub/runtime.go`:

```go
package pubsub

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

type ephemeralLease struct {
	msg        *v1.ConsumeMessage
	expiresAt  time.Time
}

type ephemeralState struct {
	topicID        string
	nextReadOffset uint64
	ackTimeout     time.Duration
	attachments    int
	inflight       map[string]ephemeralLease
}

type Runtime struct {
	mu        sync.Mutex
	topics    map[string][]chan struct{}
	ephemeral map[string]*ephemeralState
}

func NewRuntime() *Runtime {
	return &Runtime{
		topics:    make(map[string][]chan struct{}),
		ephemeral: make(map[string]*ephemeralState),
	}
}

func (r *Runtime) RegisterEphemeral(subscriptionID, topicID string, startOffset, ackTimeoutSeconds uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.ephemeral[subscriptionID]; ok {
		return
	}

	if ackTimeoutSeconds == 0 {
		ackTimeoutSeconds = 30
	}

	r.ephemeral[subscriptionID] = &ephemeralState{
		topicID:        topicID,
		nextReadOffset: startOffset + 1,
		ackTimeout:     time.Duration(ackTimeoutSeconds) * time.Second,
		inflight:       make(map[string]ephemeralLease),
	}
}

func (r *Runtime) AttachEphemeral(subscriptionID string) (func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	sub, ok := r.ephemeral[subscriptionID]
	if !ok {
		return nil, fmt.Errorf("%w: ephemeral subscription", pqerr.ErrNotFound)
	}

	sub.attachments++

	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()

		sub, ok := r.ephemeral[subscriptionID]
		if !ok {
			return
		}

		sub.attachments--
		if sub.attachments <= 0 {
			sub.attachments = 0
			sub.inflight = make(map[string]ephemeralLease)
		}
	}, nil
}

func (r *Runtime) DeleteEphemeral(subscriptionID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.ephemeral, subscriptionID)
}

func (r *Runtime) AckEphemeral(subscriptionID string, messageIDs []string) uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()

	sub, ok := r.ephemeral[subscriptionID]
	if !ok {
		return 0
	}

	var acked uint32
	for _, messageID := range messageIDs {
		if _, exists := sub.inflight[messageID]; !exists {
			continue
		}

		delete(sub.inflight, messageID)
		acked++
	}

	return acked
}

func cloneConsumeMessage(in *v1.ConsumeMessage) *v1.ConsumeMessage {
	if in == nil {
		return nil
	}

	body := append([]byte(nil), in.GetBody()...)
	return &v1.ConsumeMessage{
		MessageId:  in.GetMessageId(),
		Offset:     in.GetOffset(),
		Body:       body,
		LeaseToken: in.GetLeaseToken(),
	}
}

func (r *Runtime) ConsumeEphemeral(ctx context.Context, store Storage, subscriptionID string, batchSize uint32) (*v1.ConsumePullResponse, error) {
	r.mu.Lock()
	sub, ok := r.ephemeral[subscriptionID]
	if !ok {
		r.mu.Unlock()
		return nil, fmt.Errorf("%w: ephemeral subscription", pqerr.ErrNotFound)
	}

	now := time.Now()
	out := &v1.ConsumePullResponse{Messages: make([]*v1.ConsumeMessage, 0, batchSize)}
	expired := make([]ephemeralLease, 0, len(sub.inflight))
	for _, lease := range sub.inflight {
		if now.After(lease.expiresAt) {
			expired = append(expired, lease)
		}
	}

	sort.Slice(expired, func(i, j int) bool {
		return expired[i].msg.GetOffset() < expired[j].msg.GetOffset()
	})

	for _, lease := range expired {
		if len(out.Messages) == int(batchSize) {
			break
		}

		lease.expiresAt = now.Add(sub.ackTimeout)
		sub.inflight[lease.msg.GetMessageId()] = lease
		out.Messages = append(out.Messages, cloneConsumeMessage(lease.msg))
	}

	fromOffset := sub.nextReadOffset
	topicID := sub.topicID
	r.mu.Unlock()

	if len(out.Messages) == int(batchSize) {
		return out, nil
	}

	fresh, err := store.ReadMessages(ctx, topicID, fromOffset, batchSize-uint32(len(out.Messages)))
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	sub, ok = r.ephemeral[subscriptionID]
	if !ok {
		return nil, fmt.Errorf("%w: ephemeral subscription", pqerr.ErrNotFound)
	}

	now = time.Now()
	for _, msg := range fresh {
		if msg.GetOffset() < sub.nextReadOffset {
			continue
		}

		copied := cloneConsumeMessage(msg)
		copied.LeaseToken = fmt.Sprintf("%s:%d", subscriptionID, copied.GetOffset())

		sub.inflight[copied.GetMessageId()] = ephemeralLease{
			msg:       copied,
			expiresAt: now.Add(sub.ackTimeout),
		}
		sub.nextReadOffset = copied.GetOffset() + 1
		out.Messages = append(out.Messages, copied)
	}

	return out, nil
}

func (r *Runtime) SubscribeTopic(topicID string) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)

	r.mu.Lock()
	r.topics[topicID] = append(r.topics[topicID], ch)
	r.mu.Unlock()

	cancel := func() {
		r.mu.Lock()
		defer r.mu.Unlock()

		subs := r.topics[topicID]
		kept := subs[:0]
		for _, sub := range subs {
			if sub != ch {
				kept = append(kept, sub)
			}
		}
		if len(kept) == 0 {
			delete(r.topics, topicID)
		} else {
			r.topics[topicID] = kept
		}
	}

	return ch, cancel
}

func (r *Runtime) NotifyTopic(topicID string, lastOffset uint64) {
	r.mu.Lock()
	for _, sub := range r.ephemeral {
		if sub.topicID != topicID || sub.attachments > 0 {
			continue
		}

		if sub.nextReadOffset <= lastOffset {
			sub.nextReadOffset = lastOffset + 1
		}
		sub.inflight = make(map[string]ephemeralLease)
	}

	subs := append([]chan struct{}(nil), r.topics[topicID]...)
	r.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
```

Update `internal/server/service/pubsub/service.go`:

```go
type Service struct {
	v1.UnimplementedPubSubServiceServer

	logger  *slog.Logger
	storage Storage
	hub     *Runtime
}

func NewService(logger *slog.Logger, storage Storage) *Service {
	return &Service{
		logger:  logger,
		storage: storage,
		hub:     NewRuntime(),
	}
}
```

Replace the existing `DeleteSubscription`, `Publish`, and `Ack` implementations in `internal/server/service/pubsub/grpc_transport.go`, then add `ConsumePush`:

```go
func (s *Service) DeleteSubscription(ctx context.Context, in *v1.DeleteSubscriptionRequest) (*v1.DeleteSubscriptionResponse, error) {
	if err := validateSubscriptionID(in.GetSubscriptionId()); err != nil {
		return grpckit.ErrorGRPC[*v1.DeleteSubscriptionResponse](ctx, err)
	}

	s.hub.DeleteEphemeral(in.GetSubscriptionId())

	out, err := s.storage.DeleteSubscription(ctx, in)
	if err != nil {
		return grpckit.ErrorGRPC[*v1.DeleteSubscriptionResponse](ctx, err)
	}

	return out, nil
}

func (s *Service) Publish(ctx context.Context, in *v1.PublishRequest) (*v1.PublishResponse, error) {
	if err := validateTopicID(in.GetTopicId()); err != nil {
		return grpckit.ErrorGRPC[*v1.PublishResponse](ctx, err)
	}

	out, err := s.storage.Publish(ctx, in)
	if err != nil {
		return grpckit.ErrorGRPC[*v1.PublishResponse](ctx, err)
	}

	s.hub.NotifyTopic(in.GetTopicId(), out.GetLastOffset())

	return out, nil
}

func (s *Service) Ack(ctx context.Context, in *v1.AckRequest) (*v1.AckResponse, error) {
	if err := validateSubscriptionIDFromRequest(in); err != nil {
		return grpckit.ErrorGRPC[*v1.AckResponse](ctx, err)
	}

	sub, err := s.storage.DescribeSubscription(ctx, &v1.DescribeSubscriptionRequest{
		SubscriptionId: in.GetSubscriptionId(),
	})
	if err != nil {
		return grpckit.ErrorGRPC[*v1.AckResponse](ctx, err)
	}

	if sub.GetType() == v1.SubscriptionType_SUBSCRIPTION_TYPE_EPHEMERAL {
		return &v1.AckResponse{
			AckedCount: s.hub.AckEphemeral(in.GetSubscriptionId(), in.GetMessageIds()),
		}, nil
	}

	out, err := s.storage.Ack(ctx, in)
	if err != nil {
		return grpckit.ErrorGRPC[*v1.AckResponse](ctx, err)
	}

	return out, nil
}

func (s *Service) ConsumePush(in *v1.ConsumePushRequest, stream v1.PubSubService_ConsumePushServer) error {
	sub, err := s.storage.DescribeSubscription(stream.Context(), &v1.DescribeSubscriptionRequest{
		SubscriptionId: in.GetSubscriptionId(),
	})
	if err != nil {
		return err
	}

	if sub.GetType() == v1.SubscriptionType_SUBSCRIPTION_TYPE_EPHEMERAL {
		s.hub.RegisterEphemeral(
			sub.GetSubscriptionId(),
			sub.GetTopicId(),
			sub.GetStartOffset(),
			sub.GetAckTimeoutSeconds(),
		)
		detach, err := s.hub.AttachEphemeral(sub.GetSubscriptionId())
		if err != nil {
			return err
		}
		defer detach()
	}

	topicCh, cancel := s.hub.SubscribeTopic(sub.GetTopicId())
	defer cancel()

	sendBatch := func() error {
		var out *v1.ConsumePullResponse
		if sub.GetType() == v1.SubscriptionType_SUBSCRIPTION_TYPE_EPHEMERAL {
			out, err = s.hub.ConsumeEphemeral(stream.Context(), s.storage, in.GetSubscriptionId(), in.GetBatchSize())
		} else {
			out, err = s.storage.ConsumePull(stream.Context(), &v1.ConsumePullRequest{
				SubscriptionId: in.GetSubscriptionId(),
				BatchSize:      in.GetBatchSize(),
				ConsumerToken:  in.GetConsumerToken(),
			})
		}
		if err != nil {
			return err
		}

		for _, msg := range out.GetMessages() {
			if err := stream.Send(&v1.ConsumePushResponse{Message: msg}); err != nil {
				return err
			}
		}

		return nil
	}

	if err := sendBatch(); err != nil {
		return err
	}

	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-topicCh:
			if err := sendBatch(); err != nil {
				return err
			}
		}
	}
}
```

- [ ] **Step 4: Wire the new service into server startup and add metrics**

Update `internal/server/service/telemetry/observer.go` observed metrics:

```go
var observedMetrics = map[string]struct{}{
	"queues_exist":                    {},
	"topics_exist":                    {},
	"subscriptions_exist":             {},
	"messages_sent_total":             {},
	"pubsub_messages_published_total": {},
	"pubsub_messages_delivered_total": {},
	"pubsub_messages_acked_total":     {},
	"pubsub_retention_skips_total":    {},
	"gc_schedules_total":              {},
	"gc_duration":                     {},
}
```

Update `internal/server/server.go` to accept and mount the new service:

```go
type PlainQ struct {
	cfg        *config.Config
	logger     *slog.Logger
	queue      *queue.Service
	pubsub     *pubsub.Service
	account    *account.Service
	onboarding *onboarding.Service
	rbac       *rbac.Service
	oauth      *oauth.Service
	observer   telemetry.Observer
}

func NewServer(
	cfg *config.Config,
	logger *slog.Logger,
	checker hc.HealthChecker,
	queue *queue.Service,
	pubsub *pubsub.Service,
	account *account.Service,
	onboarding *onboarding.Service,
	rbac *rbac.Service,
	oauth *oauth.Service,
) (*servekit.Server, error) {
	pq := PlainQ{
		cfg:        cfg,
		logger:     logger,
		queue:      queue,
		pubsub:     pubsub,
		account:    account,
		onboarding: onboarding,
		rbac:       rbac,
		oauth:      oauth,
		observer:   telemetry.NewObserver(),
	}

	grpcListener, grpcListenerErr := grpckit.NewListenerGRPC(cfg.GRPCAddr)
	if grpcListenerErr != nil {
		return nil, fmt.Errorf("create gRPC listener: %w", grpcListenerErr)
	}

	grpcListener.Mount(pq.queue)
	grpcListener.Mount(pq.pubsub)
```

Update `cmd/server.go` with `initPubSubStorage` and service construction:

```go
func initPubSubStorage(cfg *config.Config, logger *slog.Logger, backend *storageBackend) (pubsub.Storage, func() error, error) {
	switch backend.driver {
	case storageDriverPostgres:
		store, err := pubsubpg.New(backend.pgpool)
		if err != nil {
			return nil, nil, fmt.Errorf("create postgres pubsub storage: %w", err)
		}
		return store, store.Close, nil
	default:
		store, err := pubsubsqlite.New(backend.sqlite)
		if err != nil {
			return nil, nil, fmt.Errorf("create sqlite pubsub storage: %w", err)
		}
		return store, store.Close, nil
	}
}

pubsubStorage, pubsubStorageClose, pubsubStorageErr := initPubSubStorage(&cfg, logger, backend)
if pubsubStorageErr != nil {
	return pubsubStorageErr
}
defer func() {
	if pubsubStorageClose == nil {
		return
	}
	if err := pubsubStorageClose(); err != nil {
		logger.Error("close pubsub storage", slog.String("error", err.Error()))
	}
}()

pubsubService := pubsub.NewService(logger, pubsubStorage)

plainqServer, serverErr := server.NewServer(
	&cfg,
	logger,
	checker,
	queueService,
	pubsubService,
	accountService,
	onboardingService,
	rbacService,
	oauthService,
)
```

- [ ] **Step 5: Run the pubsub service tests and commit**

Run:

- `go test ./internal/server/service/pubsub -count=1`
- `go test ./internal/server/... -count=1`

Expected: PASS

Commit:

```bash
git add internal/server/service/pubsub/runtime.go internal/server/service/pubsub/runtime_test.go internal/server/service/pubsub/service.go internal/server/service/pubsub/grpc_transport.go internal/server/server.go cmd/server.go internal/server/service/telemetry/observer.go
git commit -m "feat: wire pubsub service and push runtime"
```

### Task 8: Document The New Surface And Run End-To-End Verification

**Files:**
- Create: `docs/pubsub.md`
- Modify: `README.md`
- Modify: `schema/README.md`

- [ ] **Step 1: Write the failing documentation smoke check**

Add a quick doc-link smoke step by checking for the new file before creating it:

Run: `test -f docs/pubsub.md`

Expected: FAIL with a non-zero exit status because the file does not exist yet.

- [ ] **Step 2: Write the user-facing pub/sub guide**

Create `docs/pubsub.md`:

```md
# Pub/Sub

PlainQ pub/sub is built around five concepts:

- topic
- subscription
- publish
- consume
- ack

## Default Behavior

- topics are single ordered streams
- subscriptions are durable by default
- durable subscriptions default to pull delivery
- delivery is at-least-once
- clients must ack messages they finish processing

## Example Flow

1. Create a topic called `orders`
2. Create a durable subscription called `billing-worker`
3. Publish messages to `orders`
4. Consume from `billing-worker`
5. Ack the message IDs you completed

## Delivery Modes

- durable + pull: lowest operational complexity
- durable + push: lower latency, same ack semantics
- ephemeral + push: live-only delivery with no replay
```

Update `README.md`:

```md
## Getting started

PlainQ currently supports two messaging models:

- Queues for point-to-point delivery
- Pub/Sub for topic and subscription based delivery

For pub/sub concepts and examples, see [docs/pubsub.md](docs/pubsub.md).
```

Update `schema/README.md`:

```md
## Services

The schema currently exposes:

- `PlainQService` for queue operations
- `PubSubService` for topic, subscription, publish, consume, and ack operations
```

- [ ] **Step 3: Run generation and full verification**

Run:

- `make schema`
- `make sqlc-generate`
- `go test ./internal/client -count=1`
- `go test ./internal/server/service/pubsub/... -count=1`
- `go test ./internal/server/... -count=1`
- `go test ./cmd/... -count=1`

Expected: PASS for all commands.

- [ ] **Step 4: Build the server binary and verify it still compiles**

Run: `make build`

Expected: PASS and a `plainq` binary at the repo root.

- [ ] **Step 5: Commit the docs and final verification state**

```bash
git add docs/pubsub.md README.md schema/README.md
git commit -m "docs: add pubsub usage guide"
```

## Final Verification Checklist

- `make schema`
- `make sqlc-generate`
- `go test ./internal/client -count=1`
- `go test ./internal/server/service/pubsub/... -count=1`
- `go test ./internal/server/... -count=1`
- `go test ./cmd/... -count=1`
- `make build`

## Notes For The Implementer

- Do not add HTTP handlers or Houston UI in this plan. That is a follow-up once the gRPC semantics are proven.
- Keep topic writes single-copy; never materialize per-subscription message tables.
- Treat `next_read_offset` as the dispatch cursor and `acked_offset` as the durable watermark.
- Use the same durable `ConsumePull` engine underneath `ConsumePush`.
- Keep ephemeral cursor and inflight state runtime-only; persisting subscription metadata is acceptable, but never persist ephemeral delivery progress.
