package queue

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/config"
	_ "github.com/marsolab/plainq/internal/server/grpccodec" // Register PlainQ's process-wide protobuf codec at init time.
	"github.com/marsolab/plainq/internal/server/middleware"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/telemetry"
	"google.golang.org/grpc"
)

// Storage encapsulates interaction with queue storage.
//
//nolint:interfacebloat // Queue and pub/sub transports share one backend contract.
type Storage interface {
	// CreateQueue creates new queue.
	CreateQueue(ctx context.Context, input *v1.CreateQueueRequest) (*v1.CreateQueueResponse, error)

	// DescribeQueue returns information about specified queue.
	DescribeQueue(
		ctx context.Context,
		input *v1.DescribeQueueRequest,
	) (*v1.DescribeQueueResponse, error)

	// ListQueues returns a list of existing queues.
	ListQueues(ctx context.Context, input *v1.ListQueuesRequest) (*v1.ListQueuesResponse, error)

	// PurgeQueue purges all messages from the queue.
	PurgeQueue(ctx context.Context, input *v1.PurgeQueueRequest) (*v1.PurgeQueueResponse, error)

	// DeleteQueue deletes a queue if it's not empty. Also supports DeleteQueueInput.Force
	// to delete queue with messages.
	DeleteQueue(ctx context.Context, input *v1.DeleteQueueRequest) (*DeleteQueueResult, error)

	// Send sends message to the queue.
	Send(ctx context.Context, input *v1.SendRequest) (*v1.SendResponse, error)

	// Receive receives message form the queue.
	Receive(ctx context.Context, input *v1.ReceiveRequest) (*v1.ReceiveResponse, error)

	// Delete delete messages from the queue.
	Delete(ctx context.Context, input *v1.DeleteRequest) (*v1.DeleteResponse, error)

	// Peek browses messages without consuming them — visibility deadlines and
	// retry counts are left untouched. It backs the Houston message browser.
	Peek(ctx context.Context, input *PeekRequest) (*PeekResponse, error)

	ListTopics(ctx context.Context) (*ListTopicsResponse, error)
	CreateTopic(ctx context.Context, input *CreateTopicRequest) (*CreateTopicResponse, error)
	DeleteTopic(ctx context.Context, topicID string) (*DeleteTopicResult, error)
	Subscribe(ctx context.Context, topicID string, input *SubscribeRequest) (*SubscribeResponse, error)
	Unsubscribe(ctx context.Context, topicID, subscriptionID string) error
	Publish(ctx context.Context, topicID string, input *PublishRequest) (*PublishResponse, error)
	TopicInventory(ctx context.Context) (TopicInventory, error)
}

func storageSupportsPolicyTransactions(storage Storage) bool {
	if observed, ok := storage.(*ObservedStorage); ok {
		storage = observed.Unwrap()
	}

	_, ok := storage.(PolicyStorage)

	return ok
}

func storageSupportsSharedPolicy(storage Storage) bool {
	if observed, ok := storage.(*ObservedStorage); ok {
		storage = observed.Unwrap()
	}

	_, ok := storage.(authz.PolicyStore)

	return ok
}

// Service holds logic of interacting with a queue.
type Service struct {
	v1.UnimplementedPlainQServiceServer

	cfg          *config.Config
	logger       *slog.Logger
	router       chi.Router
	storage      Storage
	pubsub       *pubSubApplication
	operations   *Operations
	operationsMu sync.Mutex
	permissions  middleware.PermissionChecker
}

// policyPubSubStorage keeps pubSubApplication as the single validation and
// business-event boundary while routing its storage mutations through the
// current policy layer. Holding Service rather than an Operations pointer is
// deliberate: SetPermissionChecker can invalidate the lazy policy instance.
type policyPubSubStorage struct {
	Storage
	service *Service
}

func (s *policyPubSubStorage) ListTopics(ctx context.Context) (*ListTopicsResponse, error) {
	return s.service.policyOperations().ListTopics(ctx)
}

func (s *policyPubSubStorage) CreateTopic(
	ctx context.Context,
	input *CreateTopicRequest,
) (*CreateTopicResponse, error) {
	return s.service.policyOperations().CreateTopic(ctx, input)
}

func (s *policyPubSubStorage) DeleteTopic(ctx context.Context, topicID string) (*DeleteTopicResult, error) {
	return s.service.policyOperations().DeleteTopic(ctx, topicID)
}

func (s *policyPubSubStorage) Subscribe(
	ctx context.Context,
	topicID string,
	input *SubscribeRequest,
) (*SubscribeResponse, error) {
	return s.service.policyOperations().Subscribe(ctx, topicID, input)
}

func (s *policyPubSubStorage) Unsubscribe(ctx context.Context, topicID, subscriptionID string) error {
	return s.service.policyOperations().Unsubscribe(ctx, topicID, subscriptionID)
}

func (s *policyPubSubStorage) Publish(
	ctx context.Context,
	topicID string,
	input *PublishRequest,
) (*PublishResponse, error) {
	return s.service.policyOperations().Publish(ctx, topicID, input)
}

func (s *policyPubSubStorage) DeleteQueue(
	ctx context.Context,
	input *v1.DeleteQueueRequest,
) (*DeleteQueueResult, error) {
	return s.service.policyOperations().DeleteQueue(ctx, input)
}

var _ Storage = (*policyPubSubStorage)(nil)

func (s *Service) policyOperations() *Operations {
	s.operationsMu.Lock()
	defer s.operationsMu.Unlock()

	if s.operations == nil {
		var authorizer authz.Authorizer
		if !storageSupportsSharedPolicy(s.storage) && s.policyProtectionEnabled() {
			authorizer = legacyServicePolicyAuthorizer{service: s}
		}

		operations, err := NewOperations(s.storage, authorizer)
		if err != nil {
			panic(fmt.Sprintf("create queue operations: %v", err))
		}

		s.operations = operations
	}

	return s.operations
}

func (s *Service) policyProtectionEnabled() bool {
	if s.cfg == nil {
		return s.permissions != nil
	}

	return s.cfg.AuthEnable || s.cfg.GRPCProtectLegacy
}

// SetPermissionChecker wires the tenant-aware RBAC resolver used by queue
// mutation routes. It is set after both services are constructed to avoid a
// package cycle between queue and RBAC.
func (s *Service) SetPermissionChecker(checker middleware.PermissionChecker) {
	s.operationsMu.Lock()
	defer s.operationsMu.Unlock()

	s.permissions = checker
	if !storageSupportsSharedPolicy(s.storage) {
		s.operations = nil
	}
}

// HasQueuePermission delegates through the currently configured checker. The
// service itself is installed in route middleware so construction order does
// not create a window where handlers capture a nil checker.
func (s *Service) HasQueuePermission(
	ctx context.Context, userID, queueID string, permission middleware.PermissionType,
) (bool, error) {
	if s.permissions == nil {
		return false, errors.New("queue permission checker is not configured")
	}

	allowed, err := s.permissions.HasQueuePermission(ctx, userID, queueID, permission)
	if err != nil {
		return false, fmt.Errorf("resolve queue permission: %w", err)
	}

	return allowed, nil
}

// NewService creates a new queue service.
func NewService(
	cfg *config.Config,
	logger *slog.Logger,
	storage Storage,
	observer *telemetry.Observer,
) *Service {
	if observer == nil {
		panic("queue: observer is required")
	}

	s := Service{
		cfg: cfg, logger: logger, router: chi.NewRouter(), storage: storage,
	}
	s.pubsub = newPubSubApplication(&policyPubSubStorage{Storage: storage, service: &s}, observer, logger)

	s.router.Route("/", func(r chi.Router) {
		r.Post("/", s.createQueueHandler)
		r.Get("/", s.listQueuesHandler)
		r.Get("/{id}", s.describeQueueHandler)
		r.Post("/{id}/purge", s.purgeQueueHandler)
		r.Delete("/{id}", s.deleteQueueHandler)

		// Message-level operations for the Houston admin UI. Browse is
		// non-consuming (peek); receive claims with a visibility timeout; ack
		// deletes by id; send enqueues.
		r.Get("/{id}/messages", s.peekMessagesHandler)
		r.Post("/{id}/messages", s.sendMessagesHandler)
		r.Post("/{id}/messages/receive", s.receiveMessagesHandler)
		r.Post("/{id}/messages/ack", s.ackMessagesHandler)
	})

	s.router.Route("/topics", func(r chi.Router) {
		r.Get("/", s.listTopicsHandler)
		r.Post("/", s.createTopicHandler)
		r.Delete("/{topicID}", s.deleteTopicHandler)
		r.Post("/{topicID}/publish", s.publishTopicHandler)
		r.Post("/{topicID}/subscriptions", s.subscribeTopicHandler)
		r.Delete("/{topicID}/subscriptions/{subscriptionID}", s.unsubscribeTopicHandler)
	})

	return &s
}

func (s *Service) Mount(server *grpc.Server)                        { v1.RegisterPlainQServiceServer(server, s) }
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.router.ServeHTTP(w, r) }
