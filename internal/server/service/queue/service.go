package queue

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/server/config"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	vtgrpc "github.com/planetscale/vtprotobuf/codec/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
)

// Storage encapsulates interaction with queue storage.
type Storage interface {
	// CreateQueue creates new queue.
	CreateQueue(ctx context.Context, input *v1.CreateQueueRequest) (*v1.CreateQueueResponse, error)

	// DescribeQueue returns information about specified queue.
	DescribeQueue(ctx context.Context, input *v1.DescribeQueueRequest) (*v1.DescribeQueueResponse, error)

	// ListQueues returns a list of existing queues.
	ListQueues(ctx context.Context, input *v1.ListQueuesRequest) (*v1.ListQueuesResponse, error)

	// PurgeQueue purges all messages from the queue.
	PurgeQueue(ctx context.Context, input *v1.PurgeQueueRequest) (*v1.PurgeQueueResponse, error)

	// DeleteQueue deletes a queue if it's not empty. Also supports DeleteQueueInput.Force
	// to delete queue with messages.
	DeleteQueue(ctx context.Context, input *v1.DeleteQueueRequest) (*v1.DeleteQueueResponse, error)

	// Send sends message to the queue.
	Send(ctx context.Context, input *v1.SendRequest) (*v1.SendResponse, error)

	// Receive receives message form the queue.
	Receive(ctx context.Context, input *v1.ReceiveRequest) (*v1.ReceiveResponse, error)

	// Delete delete messages from the queue.
	Delete(ctx context.Context, input *v1.DeleteRequest) (*v1.DeleteResponse, error)
}

// Service holds logic of interacting with a queue.
type Service struct {
	v1.UnimplementedPlainQServiceServer

	cfg     *config.Config
	logger  *slog.Logger
	router  chi.Router
	storage Storage
}

// NewService creates a new queue service.
func NewService(cfg *config.Config, logger *slog.Logger, storage Storage) *Service {
	encoding.RegisterCodec(vtgrpc.Codec{})

	s := Service{
		cfg:     cfg,
		logger:  logger,
		router:  chi.NewRouter(),
		storage: storage,
	}

	s.router.Route("/", func(r chi.Router) {
		r.Post("/", s.createQueueHandler)
		r.Get("/", s.listQueuesHandler)
		r.Get("/{id}", s.describeQueueHandler)
		r.Post("/{id}/purge", s.purgeQueueHandler)
		r.Delete("/{id}", s.deleteQueueHandler)
	})

	return &s
}

func (s *Service) Mount(server *grpc.Server)                        { v1.RegisterPlainQServiceServer(server, s) }
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.router.ServeHTTP(w, r) }
