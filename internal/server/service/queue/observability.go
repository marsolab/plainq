//nolint:wrapcheck // A decorator must hand back the inner error unchanged; wrapping would rewrite every storage error with a layer that adds nothing.
package queue

import (
	"context"
	"time"

	"github.com/marsolab/plainq/internal/metrics"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/telemetry"
)

// Compile-time check that the decorator still satisfies the contract it wraps.
var _ Storage = (*ObservedStorage)(nil)

// ObservedStorage wraps a Storage and records what passes through it.
//
// It sits at the API boundary rather than inside a backend deliberately.
// Every request reaches storage through this one interface — SQLite,
// Postgres, and the replicated cluster store alike — so instrumenting here
// measures all three identically, and a fourth backend is instrumented the
// day it is written. It also means the numbers describe what callers asked
// for, which is what an operator is actually looking at when they open a
// dashboard.
//
// Events the API cannot see — a message dropped by retention, a dead-letter
// move, how long a delivered message had been waiting — stay instrumented
// inside the backend that observes them.
type ObservedStorage struct {
	inner    Storage
	observer *telemetry.Observer
}

// NewObservedStorage wraps storage so its operations are recorded.
func NewObservedStorage(storage Storage, observer *telemetry.Observer) *ObservedStorage {
	return &ObservedStorage{inner: storage, observer: observer}
}

// Unwrap returns the wrapped storage, for the callers that need to reach
// through to a backend-specific capability.
func (s *ObservedStorage) Unwrap() Storage { return s.inner }

// CreateQueue implements Storage.
func (s *ObservedStorage) CreateQueue(
	ctx context.Context,
	input *v1.CreateQueueRequest,
) (*v1.CreateQueueResponse, error) {
	start := time.Now()

	out, err := s.inner.CreateQueue(ctx, input)

	s.observer.Operation(metrics.OpCreateQueue, start, err)

	return out, err
}

// DescribeQueue implements Storage.
func (s *ObservedStorage) DescribeQueue(
	ctx context.Context,
	input *v1.DescribeQueueRequest,
) (*v1.DescribeQueueResponse, error) {
	start := time.Now()

	out, err := s.inner.DescribeQueue(ctx, input)

	s.observer.Operation(metrics.OpDescribeQueue, start, err)

	return out, err
}

// ListQueues implements Storage.
func (s *ObservedStorage) ListQueues(ctx context.Context, input *v1.ListQueuesRequest) (*v1.ListQueuesResponse, error) {
	start := time.Now()

	out, err := s.inner.ListQueues(ctx, input)

	s.observer.Operation(metrics.OpListQueues, start, err)

	return out, err
}

// PurgeQueue implements Storage.
func (s *ObservedStorage) PurgeQueue(ctx context.Context, input *v1.PurgeQueueRequest) (*v1.PurgeQueueResponse, error) {
	start := time.Now()

	out, err := s.inner.PurgeQueue(ctx, input)

	s.observer.Operation(metrics.OpPurgeQueue, start, err)

	if err == nil {
		s.observer.QueuePurged(input.GetQueueId())
	}

	return out, err
}

// DeleteQueue implements Storage.
func (s *ObservedStorage) DeleteQueue(
	ctx context.Context,
	input *v1.DeleteQueueRequest,
) (*v1.DeleteQueueResponse, error) {
	start := time.Now()

	out, err := s.inner.DeleteQueue(ctx, input)

	s.observer.Operation(metrics.OpDeleteQueue, start, err)

	if err == nil {
		s.observer.QueuePurged(input.GetQueueId())
	}

	return out, err
}

// Send implements Storage.
func (s *ObservedStorage) Send(ctx context.Context, input *v1.SendRequest) (*v1.SendResponse, error) {
	start := time.Now()

	out, err := s.inner.Send(ctx, input)

	s.observer.Operation(metrics.OpSend, start, err)

	if err != nil {
		return out, err
	}

	queueID := input.GetQueueId()

	// Sizes are recorded per message and the total once, because the two
	// answer different questions: the histogram says what a typical message
	// looks like, the counter says how much traffic the queue is carrying.
	//
	// The histogram is resolved once for the batch. A Send may carry two
	// thousand messages, and looking the same handle up by label on each of
	// them is work the hot path should not be doing.
	var bytes uint64

	sizes := s.observer.MessageSizes(queueID)

	for _, message := range input.GetMessages() {
		size := len(message.GetBody())
		bytes += uint64(size)

		sizes.Update(float64(size))
	}

	s.observer.Sent(queueID, uint64(len(out.GetMessageIds())), bytes)

	return out, err
}

// Receive implements Storage.
func (s *ObservedStorage) Receive(ctx context.Context, input *v1.ReceiveRequest) (*v1.ReceiveResponse, error) {
	start := time.Now()

	out, err := s.inner.Receive(ctx, input)

	s.observer.Operation(metrics.OpReceive, start, err)

	if err != nil {
		return out, err
	}

	var bytes uint64

	for _, message := range out.GetMessages() {
		bytes += uint64(len(message.GetBody()))
	}

	s.observer.Received(input.GetQueueId(), uint64(len(out.GetMessages())), bytes)

	return out, err
}

// Delete implements Storage.
func (s *ObservedStorage) Delete(ctx context.Context, input *v1.DeleteRequest) (*v1.DeleteResponse, error) {
	start := time.Now()

	out, err := s.inner.Delete(ctx, input)

	s.observer.Operation(metrics.OpDelete, start, err)

	if err == nil {
		// Only the acknowledged ids count. A delete for a message that was
		// never there is reported back to the caller as a failure and must not
		// move the queue's depth.
		s.observer.Deleted(input.GetQueueId(), uint64(len(out.GetSuccessful())))
	}

	return out, err
}

// Peek implements Storage.
func (s *ObservedStorage) Peek(ctx context.Context, input *PeekRequest) (*PeekResponse, error) {
	start := time.Now()

	out, err := s.inner.Peek(ctx, input)

	s.observer.Operation(metrics.OpPeek, start, err)

	return out, err
}

// ListTopics implements Storage.
func (s *ObservedStorage) ListTopics(ctx context.Context) (*ListTopicsResponse, error) {
	start := time.Now()

	out, err := s.inner.ListTopics(ctx)

	s.observer.TopicOperation(metrics.OpListTopics, start, err)

	if err == nil {
		metrics.SetTopicsExist(int64(len(out.Topics)))
	}

	return out, err
}

// CreateTopic implements Storage.
func (s *ObservedStorage) CreateTopic(ctx context.Context, input *CreateTopicRequest) (*CreateTopicResponse, error) {
	start := time.Now()

	out, err := s.inner.CreateTopic(ctx, input)

	s.observer.TopicOperation(metrics.OpCreateTopic, start, err)

	return out, err
}

// DeleteTopic implements Storage.
func (s *ObservedStorage) DeleteTopic(ctx context.Context, topicID string) error {
	start := time.Now()

	err := s.inner.DeleteTopic(ctx, topicID)

	s.observer.TopicOperation(metrics.OpDeleteTopic, start, err)

	if err == nil {
		metrics.ResetTopic(topicID)
	}

	return err
}

// Subscribe implements Storage.
func (s *ObservedStorage) Subscribe(ctx context.Context, topicID string, input *SubscribeRequest) (*SubscribeResponse, error) {
	start := time.Now()

	out, err := s.inner.Subscribe(ctx, topicID, input)

	s.observer.TopicOperation(metrics.OpSubscribe, start, err)

	return out, err
}

// Unsubscribe implements Storage.
func (s *ObservedStorage) Unsubscribe(ctx context.Context, topicID, subscriptionID string) error {
	start := time.Now()

	err := s.inner.Unsubscribe(ctx, topicID, subscriptionID)

	s.observer.TopicOperation(metrics.OpUnsubscribe, start, err)

	return err
}

// Publish implements Storage.
func (s *ObservedStorage) Publish(ctx context.Context, topicID string, input *PublishRequest) (*PublishResponse, error) {
	start := time.Now()

	out, err := s.inner.Publish(ctx, topicID, input)

	s.observer.TopicOperation(metrics.OpPublish, start, err)

	if err != nil {
		return out, err
	}

	var bytes uint64

	for _, message := range input.Messages {
		bytes += uint64(len(message.Body))
	}

	// A publish reports success once it is accepted, so a subscriber that
	// could not be written to leaves no other trace. The difference between
	// the subscribers a topic has and the deliveries it managed is that trace.
	delivered := uint64(max(out.DeliveredCount, 0))

	var failed uint64

	if expected := uint64(len(out.QueueIDs)) * uint64(len(input.Messages)); expected > delivered {
		failed = expected - delivered
	}

	s.observer.Published(topicID, uint64(len(input.Messages)), bytes, delivered, failed)

	return out, err
}
