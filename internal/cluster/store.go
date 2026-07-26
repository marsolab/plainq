package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/marsolab/plainq/internal/cluster/command"
	"github.com/marsolab/plainq/internal/cluster/consensus"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/servekit/idkit"
	"github.com/marsolab/servekit/logkit"
)

// Compilation time check that Store can stand in for a plain queue backend.
var _ queue.Storage = (*Store)(nil)

// Forwarder hands a command to the cluster leader. A follower has no way to
// commit a write itself, so it asks whoever can.
type Forwarder interface {
	// Forward sends an encoded command to the node at addr and returns the
	// leader's encoded response.
	Forward(ctx context.Context, addr string, payload []byte) ([]byte, error)
}

// Backoff bounds for a write that arrives during an election. An election
// resolves in well under a second on a healthy cluster, so the first retry is
// quick and the ceiling is there for the pathological case.
const (
	electionBackoff    = 50 * time.Millisecond
	maxElectionBackoff = 500 * time.Millisecond
)

// ConsistencyMode decides where reads are answered from.
type ConsistencyMode string

// The available consistency modes.
const (
	// ConsistencyLocal answers reads from the local replica. It is the
	// default: it costs nothing, it scales with the cluster, and for a queue
	// dashboard or a queue listing a few milliseconds of staleness is not a
	// property anyone is relying on.
	ConsistencyLocal ConsistencyMode = "local"

	// ConsistencyStrong answers reads on the leader, behind a consensus
	// barrier, so a read never returns state older than a write that already
	// completed.
	ConsistencyStrong ConsistencyMode = "strong"
)

// Store is the queue.Storage a clustered node hands to the queue service.
//
// Reads go to the local replica. Writes are turned into commands with every
// ambiguity resolved, then committed through consensus — on this node if it
// leads, through the leader if it does not. Nothing above this layer knows
// which of those happened.
type Store struct {
	local     queue.ReplicatedStorage
	consensus consensus.Consensus
	forwarder Forwarder
	logger    *slog.Logger

	// consistency decides where reads are answered.
	consistency ConsistencyMode

	// applyTimeout bounds a single replicated write.
	applyTimeout time.Duration

	// now is the clock the leader stamps commands with, injectable for tests.
	now func() time.Time

	// newULID overrides message identifier generation for tests. Left nil, a
	// Send mints a fresh monotonic batch — which is what keeps a batch in
	// order — so nothing but a test should set it.
	newULID func() string

	// newXID generates the identifiers for queues, topics and subscriptions,
	// injectable for tests.
	newXID func() string
}

// StoreOption configures a Store.
type StoreOption func(*Store)

// WithConsistency sets how reads are answered.
func WithConsistency(mode ConsistencyMode) StoreOption {
	return func(s *Store) { s.consistency = mode }
}

// WithApplyTimeout bounds a single replicated write.
func WithApplyTimeout(timeout time.Duration) StoreOption {
	return func(s *Store) { s.applyTimeout = timeout }
}

// WithStoreLogger sets the store's logger.
func WithStoreLogger(logger *slog.Logger) StoreOption {
	return func(s *Store) { s.logger = logger }
}

// WithStoreClock overrides the clock, for tests.
func WithStoreClock(now func() time.Time) StoreOption {
	return func(s *Store) { s.now = now }
}

// WithStoreIDs overrides identifier generation, for tests.
func WithStoreIDs(newULID, newXID func() string) StoreOption {
	return func(s *Store) {
		s.newULID = newULID
		s.newXID = newXID
	}
}

// NewStore wraps a local store in the cluster's write path.
func NewStore(
	local queue.ReplicatedStorage,
	engine consensus.Consensus,
	forwarder Forwarder,
	opts ...StoreOption,
) *Store {
	s := Store{
		local:        local,
		consensus:    engine,
		forwarder:    forwarder,
		logger:       logkit.NewNop(),
		consistency:  ConsistencyLocal,
		applyTimeout: 15 * time.Second,
		now:          func() time.Time { return time.Now().UTC() },
		newXID:       idkit.XID,
	}

	for _, opt := range opts {
		opt(&s)
	}

	return &s
}

// CreateQueue implements queue.Storage.
func (s *Store) CreateQueue(ctx context.Context, input *v1.CreateQueueRequest) (*v1.CreateQueueResponse, error) {
	return protoResponse[v1.CreateQueueResponse](
		s.applyProto(ctx, command.OpCreateQueue, input, []string{s.newXID()}),
	)
}

// DeleteQueue implements queue.Storage.
func (s *Store) DeleteQueue(ctx context.Context, input *v1.DeleteQueueRequest) (*v1.DeleteQueueResponse, error) {
	return protoResponse[v1.DeleteQueueResponse](s.applyProto(ctx, command.OpDeleteQueue, input, nil))
}

// PurgeQueue implements queue.Storage.
func (s *Store) PurgeQueue(ctx context.Context, input *v1.PurgeQueueRequest) (*v1.PurgeQueueResponse, error) {
	return protoResponse[v1.PurgeQueueResponse](s.applyProto(ctx, command.OpPurgeQueue, input, nil))
}

// Send implements queue.Storage.
//
// The message ids are minted here, on whichever node received the request, and
// travel with the command. Letting each replica mint its own would give the
// same message a different id on every node.
func (s *Store) Send(ctx context.Context, input *v1.SendRequest) (*v1.SendResponse, error) {
	ids := s.batchIDs(len(input.GetMessages()))

	return protoResponse[v1.SendResponse](s.applyProto(ctx, command.OpSend, input, ids))
}

// batchIDs mints n message identifiers that sort in the order they were
// produced, so a batch is delivered in the order it was sent.
func (s *Store) batchIDs(n int) []string {
	if n == 0 {
		return nil
	}

	// The override exists for tests; production always takes the monotonic
	// generator, because a batch's delivery order depends on it.
	next := s.newULID
	if next == nil {
		next = queue.NewBatchIDs(s.now())
	}

	ids := make([]string, 0, n)
	for range n {
		ids = append(ids, next())
	}

	return ids
}

// Receive implements queue.Storage.
//
// A receive is a write: it hides the messages it hands out. Serving it from a
// local replica would let two consumers on two nodes claim the same message,
// which is the one thing a queue may not do.
func (s *Store) Receive(ctx context.Context, input *v1.ReceiveRequest) (*v1.ReceiveResponse, error) {
	return protoResponse[v1.ReceiveResponse](s.applyProto(ctx, command.OpReceive, input, nil))
}

// Delete implements queue.Storage.
func (s *Store) Delete(ctx context.Context, input *v1.DeleteRequest) (*v1.DeleteResponse, error) {
	return protoResponse[v1.DeleteResponse](s.applyProto(ctx, command.OpDelete, input, nil))
}

// DescribeQueue implements queue.Storage.
func (s *Store) DescribeQueue(ctx context.Context, input *v1.DescribeQueueRequest) (*v1.DescribeQueueResponse, error) {
	if err := s.readBarrier(ctx); err != nil {
		return nil, err
	}

	response, err := s.local.DescribeQueue(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("describe queue on the local replica: %w", err)
	}

	return response, nil
}

// ListQueues implements queue.Storage.
func (s *Store) ListQueues(ctx context.Context, input *v1.ListQueuesRequest) (*v1.ListQueuesResponse, error) {
	if err := s.readBarrier(ctx); err != nil {
		return nil, err
	}

	response, err := s.local.ListQueues(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("list queues on the local replica: %w", err)
	}

	return response, nil
}

// Peek implements queue.Storage.
func (s *Store) Peek(ctx context.Context, input *queue.PeekRequest) (*queue.PeekResponse, error) {
	if err := s.readBarrier(ctx); err != nil {
		return nil, err
	}

	response, err := s.local.Peek(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("browse queue on the local replica: %w", err)
	}

	return response, nil
}

// ListTopics implements queue.Storage.
func (s *Store) ListTopics(ctx context.Context) (*queue.ListTopicsResponse, error) {
	if err := s.readBarrier(ctx); err != nil {
		return nil, err
	}

	response, err := s.local.ListTopics(ctx)
	if err != nil {
		return nil, fmt.Errorf("list topics on the local replica: %w", err)
	}

	return response, nil
}

// CreateTopic implements queue.Storage.
func (s *Store) CreateTopic(ctx context.Context, input *queue.CreateTopicRequest) (*queue.CreateTopicResponse, error) {
	return jsonResponse[queue.CreateTopicResponse](
		s.applyJSON(ctx, command.OpCreateTopic, input, "", []string{s.newXID()}),
	)
}

// DeleteTopic implements queue.Storage.
func (s *Store) DeleteTopic(ctx context.Context, topicID string) error {
	_, err := s.applyJSON(ctx, command.OpDeleteTopic, struct{}{}, topicID, nil)

	return err
}

// Subscribe implements queue.Storage.
func (s *Store) Subscribe(
	ctx context.Context,
	topicID string,
	input *queue.SubscribeRequest,
) (*queue.SubscribeResponse, error) {
	return jsonResponse[queue.SubscribeResponse](
		s.applyJSON(ctx, command.OpSubscribe, input, topicID, []string{s.newXID()}),
	)
}

// Unsubscribe implements queue.Storage.
func (s *Store) Unsubscribe(ctx context.Context, topicID, subscriptionID string) error {
	_, err := s.applyJSON(ctx, command.OpUnsubscribe, struct{}{}, topicID, []string{subscriptionID})

	return err
}

// Publish implements queue.Storage.
//
// Fan-out needs one message id per subscriber per message, and the number of
// subscribers is state. The local replica is read to size the batch; if it is
// stale the FSM mints the shortfall itself and logs the mismatch, so a publish
// during a subscription change still delivers.
func (s *Store) Publish(
	ctx context.Context,
	topicID string,
	input *queue.PublishRequest,
) (*queue.PublishResponse, error) {
	subscribers, err := s.countSubscribers(ctx, topicID)
	if err != nil {
		return nil, err
	}

	ids := s.batchIDs(subscribers * len(input.Messages))

	return jsonResponse[queue.PublishResponse](s.applyJSON(ctx, command.OpPublish, input, topicID, ids))
}

// Sweep proposes eviction for one queue. Only the leader calls it — see the
// sweeper in node.go — because eviction is replicated state, not local
// housekeeping.
func (s *Store) Sweep(ctx context.Context, queueID string) (uint64, error) {
	response, err := s.apply(ctx, &command.Command{
		Op:        command.OpSweep,
		Timestamp: s.now().UnixNano(),
		Target:    queueID,
	})
	if err != nil {
		return 0, err
	}

	dropped, _ := response.(uint64) //nolint:errcheck // a backend that reports no count is fine.

	return dropped, nil
}

func (s *Store) countSubscribers(ctx context.Context, topicID string) (int, error) {
	topics, err := s.local.ListTopics(ctx)
	if err != nil {
		return 0, fmt.Errorf("count subscribers of topic %q: %w", topicID, err)
	}

	for _, topic := range topics.Topics {
		if topic.TopicID == topicID {
			return len(topic.Subscriptions), nil
		}
	}

	return 0, nil
}

// readBarrier makes a read as strong as the configured mode requires. In local
// mode it does nothing, which is the point.
func (s *Store) readBarrier(ctx context.Context) error {
	if s.consistency != ConsistencyStrong {
		return nil
	}

	// A strong read on a follower would still be answered from local state, so
	// there is nothing honest to do but say the read cannot be served here.
	if !s.consensus.IsLeader() {
		return fmt.Errorf("%w: strong reads are served by the leader", consensus.ErrNotLeader)
	}

	if err := s.consensus.Barrier(ctx); err != nil {
		return fmt.Errorf("strong read barrier: %w", err)
	}

	return nil
}

// apply commits a command: locally when this node leads, through the leader
// when it does not.
//
// An election in progress is not a failure to report to a client — it is a
// few hundred milliseconds during which nobody can commit anything. The write
// waits it out, up to the apply timeout, and only then gives up.
//
// The retry is deliberately narrow. It fires only when this node is certain
// the command was *not* committed: either no leader was known, so nothing was
// ever proposed, or the local engine rejected the proposal outright. A
// forwarded command whose reply was lost may well have been committed, and
// re-sending that would enqueue the same message twice.
func (s *Store) apply(ctx context.Context, cmd *command.Command) (any, error) {
	encoded, encodeErr := cmd.Encode()
	if encodeErr != nil {
		return nil, fmt.Errorf("encode %s command: %w", cmd.Op, encodeErr)
	}

	ctx, cancel := context.WithTimeout(ctx, s.applyTimeout)
	defer cancel()

	backoff := electionBackoff

	for attempt := 0; ; attempt++ {
		response, err := s.applyOnce(ctx, cmd, encoded)
		if err == nil {
			return response, nil
		}

		// Both retryable cases are ones where nothing was proposed: no leader
		// was known, or the peer we asked answered that it is not the leader.
		// A transport failure carries neither class — the leader may well have
		// committed before the reply was lost — and re-sending that would
		// enqueue the same message twice.
		if !errors.Is(err, consensus.ErrNoLeader) && !errors.Is(err, consensus.ErrNotLeader) {
			return nil, err
		}

		s.logger.Debug("Waiting for a leader before retrying a write",
			slog.String("op", cmd.Op.String()),
			slog.Int("attempt", attempt+1),
		)

		select {
		case <-ctx.Done():
			// Report the reason the write could not be made, not the fact that
			// waiting for it timed out.
			return nil, err

		case <-time.After(backoff):
		}

		if backoff < maxElectionBackoff {
			backoff *= 2
		}
	}
}

// applyOnce makes one attempt to commit a command.
func (s *Store) applyOnce(ctx context.Context, cmd *command.Command, encoded []byte) (any, error) {
	if s.consensus.IsLeader() {
		response, err := s.consensus.Apply(ctx, encoded)
		if err == nil {
			return response, nil
		}

		if !errors.Is(err, consensus.ErrNotLeader) {
			return nil, fmt.Errorf("commit %s: %w", cmd.Op, err)
		}

		// Leadership moved between the check and the proposal. The command was
		// not committed, so forwarding it is safe rather than a duplicate.
		s.logger.Debug("Lost leadership mid-write, forwarding to the new leader",
			slog.String("op", cmd.Op.String()),
		)
	}

	return s.forward(ctx, cmd, encoded)
}

func (s *Store) forward(ctx context.Context, cmd *command.Command, encoded []byte) (any, error) {
	if s.forwarder == nil {
		return nil, fmt.Errorf("%w: this node cannot forward writes", consensus.ErrNotLeader)
	}

	_, addr, leaderErr := s.consensus.Leader()
	if leaderErr != nil {
		return nil, fmt.Errorf("locate the leader for %s: %w", cmd.Op, leaderErr)
	}

	raw, err := s.forwarder.Forward(ctx, addr, encoded)
	if err != nil {
		return nil, fmt.Errorf("forward %s to leader %s: %w", cmd.Op, addr, err)
	}

	return raw, nil
}

// applyProto replicates a command whose request is a schema message.
func (s *Store) applyProto(
	ctx context.Context,
	op command.Op,
	input vtMarshaler,
	ids []string,
) (any, error) {
	payload, marshalErr := input.MarshalVT()
	if marshalErr != nil {
		return nil, fmt.Errorf("encode %s request: %w", op, marshalErr)
	}

	// Queue operations carry their target inside the request, so the envelope's
	// Target is only used by the pub/sub and sweep commands.
	return s.apply(ctx, &command.Command{
		Op:        op,
		Timestamp: s.now().UnixNano(),
		IDs:       ids,
		Payload:   payload,
	})
}

// applyJSON replicates a command whose request is a plain Go struct.
func (s *Store) applyJSON(
	ctx context.Context,
	op command.Op,
	input any,
	target string,
	ids []string,
) (any, error) {
	payload, marshalErr := json.Marshal(input)
	if marshalErr != nil {
		return nil, fmt.Errorf("encode %s request: %w", op, marshalErr)
	}

	return s.apply(ctx, &command.Command{
		Op:        op,
		Timestamp: s.now().UnixNano(),
		Target:    target,
		IDs:       ids,
		Payload:   payload,
	})
}

// protoResponse turns what came back from a replicated command into a schema
// response.
//
// There are two shapes to handle, because there are two paths. A command
// applied on this node returns the state machine's own value; one forwarded to
// the leader returns the bytes the leader encoded for the wire. Both end up
// as the same type here.
func protoResponse[U any, R interface {
	*U
	vtUnmarshaler
}](response any, err error) (R, error) {
	if err != nil {
		return nil, err
	}

	if response == nil {
		return nil, nil
	}

	if typed, ok := response.(R); ok {
		return typed, nil
	}

	raw, ok := response.([]byte)
	if !ok {
		return nil, fmt.Errorf("state machine returned %T, want %T or an encoded response", response, R(nil))
	}

	out := R(new(U))

	if unmarshalErr := out.UnmarshalVT(raw); unmarshalErr != nil {
		return nil, fmt.Errorf("decode forwarded response: %w", unmarshalErr)
	}

	return out, nil
}

// jsonResponse is protoResponse for the pub/sub types, which are plain Go
// structs and travel as JSON.
func jsonResponse[U any](response any, err error) (*U, error) {
	if err != nil {
		return nil, err
	}

	if response == nil {
		return nil, nil
	}

	if typed, ok := response.(*U); ok {
		return typed, nil
	}

	raw, ok := response.([]byte)
	if !ok {
		return nil, fmt.Errorf("state machine returned %T, want *%T or an encoded response", response, *new(U))
	}

	if len(raw) == 0 {
		return nil, nil
	}

	out := new(U)

	if unmarshalErr := json.Unmarshal(raw, out); unmarshalErr != nil {
		return nil, fmt.Errorf("decode forwarded response: %w", unmarshalErr)
	}

	return out, nil
}

// vtMarshaler is what the generated schema request types satisfy.
type vtMarshaler interface {
	MarshalVT() ([]byte, error)
}

// vtUnmarshaler is what the generated schema response types satisfy.
type vtUnmarshaler interface {
	UnmarshalVT(data []byte) error
}
