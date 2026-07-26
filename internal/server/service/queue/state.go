package queue

import (
	"context"
	"time"
)

// The types and interfaces below describe the *whole* contents of a queue
// store, so a replica can be reconstructed from nothing.
//
// A consensus log cannot grow forever, so it is periodically replaced by a
// snapshot of the state it produced; a node that falls too far behind — or one
// joining an established cluster — is caught up by shipping it that snapshot
// rather than replaying history from the beginning. Both directions need a
// storage backend that can say everything it holds, and be told everything it
// should hold.
//
// The serialization format deliberately lives in the cluster layer, not here.
// Storage knows records; the cluster knows bytes.

// QueueState is a queue's full definition.
type QueueState struct {
	ID                       string
	Name                     string
	CreatedAt                time.Time
	RetentionPeriodSeconds   uint64
	VisibilityTimeoutSeconds uint64
	MaxReceiveAttempts       uint32
	EvictionPolicy           uint32
	DeadLetterQueueID        string
}

// MessageState is one message, with the fields that make it recoverable:
// not just its body, but where it sits in its own lifecycle.
type MessageState struct {
	// QueueID is the queue the message belongs to.
	QueueID string

	// ID is the message identifier.
	ID string

	// Body is the payload.
	Body []byte

	// CreatedAt is when the message was enqueued. It drives retention.
	CreatedAt time.Time

	// VisibleAt is when the message next becomes visible. A message that was
	// in flight when the snapshot was taken stays in flight after a restore.
	VisibleAt time.Time

	// Retries is how many times the message has been delivered. Losing it
	// would give a poison message a fresh set of attempts on every restore.
	Retries uint32
}

// TopicState is a pub/sub topic.
type TopicState struct {
	ID   string
	Name string
}

// SubscriptionState attaches a queue to a topic.
type SubscriptionState struct {
	ID      string
	TopicID string
	QueueID string
}

// StateSink receives every record a store holds during a snapshot. Returning
// an error from any method aborts the snapshot.
type StateSink interface {
	// Queue writes a queue definition. Every message that follows for that
	// queue is written after its definition.
	Queue(state QueueState) error

	// Message writes one message.
	Message(state MessageState) error

	// Topic writes a topic definition.
	Topic(state TopicState) error

	// Subscription writes a subscription.
	Subscription(state SubscriptionState) error
}

// StateSnapshotter is a storage backend that can describe everything it holds.
type StateSnapshotter interface {
	// BeginSnapshot pins the store's current contents and returns a handle to
	// read them.
	//
	// The split matters. A snapshot has to correspond to one position in the
	// consensus log, but writing it out takes time, and writes do not stop
	// while it happens. BeginSnapshot is called at the instant the snapshot is
	// meant to capture; the streaming happens afterwards, against the view
	// pinned here.
	BeginSnapshot(ctx context.Context) (StateSnapshot, error)
}

// StateSnapshot is a pinned, consistent view of a store.
type StateSnapshot interface {
	// Stream writes every record in the pinned view to sink.
	Stream(ctx context.Context, sink StateSink) error

	// Release drops the pinned view. It is safe to call more than once, and
	// must be called even when Stream failed.
	Release() error
}

// StateRestorer is a storage backend that can be replaced wholesale by a
// snapshot.
//
// A restore is all-or-nothing: it discards the current contents and installs
// the snapshot's. Interrupting it halfway would leave the node holding a state
// that never existed anywhere, which is worse than holding stale state, so
// implementations stage the work and swap at the end.
type StateRestorer interface {
	// BeginRestore starts a restore, discarding what the store currently
	// holds.
	BeginRestore(ctx context.Context) error

	// RestoreQueue installs a queue definition.
	RestoreQueue(ctx context.Context, state QueueState) error

	// RestoreMessages installs a batch of messages. All of them belong to a
	// queue that a preceding RestoreQueue installed.
	RestoreMessages(ctx context.Context, states []MessageState) error

	// RestoreTopic installs a topic definition.
	RestoreTopic(ctx context.Context, state TopicState) error

	// RestoreSubscription installs a subscription.
	RestoreSubscription(ctx context.Context, state SubscriptionState) error

	// CommitRestore makes the restored state live.
	CommitRestore(ctx context.Context) error

	// AbortRestore discards a partial restore and leaves the previous state
	// in place. It is safe to call after CommitRestore, where it does
	// nothing.
	AbortRestore(ctx context.Context) error
}

// ReplicatedStorage is the contract a storage backend must meet to sit under a
// consensus cluster: it holds queues, and it can be snapshotted and restored.
type ReplicatedStorage interface {
	Storage
	StateSnapshotter
	StateRestorer
}
