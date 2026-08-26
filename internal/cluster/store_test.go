package cluster

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"

	hraft "github.com/hashicorp/raft"
	"github.com/marsolab/plainq/internal/cluster/consensus"
	"github.com/marsolab/plainq/internal/cluster/deletewire"
	"github.com/marsolab/plainq/internal/cluster/peer"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/maxatome/go-testdeep/td"
)

type commitUnknownConsensus struct {
	consensus.Consensus

	mu         sync.Mutex
	applyCalls int
}

type outcomeConsensus struct {
	consensus.Consensus
	leader   bool
	address  string
	response any
	err      error
}

func (c *outcomeConsensus) IsLeader() bool { return c.leader }
func (c *outcomeConsensus) Apply(context.Context, []byte) (any, error) {
	return c.response, c.err
}
func (c *outcomeConsensus) Leader() (string, string, error) {
	address := c.address
	if address == "" {
		address = "leader-address"
	}
	return "leader", address, nil
}

type topicListStorage struct {
	queue.ReplicatedStorage
	topics *queue.ListTopicsResponse
}

func (s *topicListStorage) ListTopics(context.Context) (*queue.ListTopicsResponse, error) {
	return s.topics, nil
}

func newHealthyReplicaForStoreTest(t *testing.T) *replicaHealth {
	t.Helper()
	health, err := newReplicaHealth(t.TempDir(), hraft.NewInmemStore())
	if err != nil {
		t.Fatalf("newReplicaHealth() = %v", err)
	}
	return health
}

func TestStoreLeaderReturnsPartialPublishOutcomeAndError(t *testing.T) {
	health := newHealthyReplicaForStoreTest(t)
	response := &queue.PublishResponse{TopicID: "topicone", QueueIDs: []string{"queueone"}}
	engine := &outcomeConsensus{leader: true, response: &queue.PublishOutcome{
		Response: response,
		Partial:  true,
		// A typed partial may conservatively carry no count. The discriminator,
		// not FailedDeliveries, is the contract.
		FailedDeliveries: 0,
	}}
	local := &topicListStorage{topics: &queue.ListTopicsResponse{Topics: []queue.Topic{{
		TopicID: "topicone", Subscriptions: []queue.Subscription{{QueueID: "queueone"}},
	}}}}
	store := NewStore(local, engine, nil, WithReplicaHealth(health))

	got, err := store.Publish(context.Background(), "topicone", &queue.PublishRequest{})
	if got != response {
		t.Fatalf("Publish response = %#v, want %#v", got, response)
	}
	var partial *queue.PartialPublishError
	if !errors.As(err, &partial) || !errors.Is(err, pqerr.ErrPartialFanout) {
		t.Fatalf("Publish error = %v, want typed partial fanout", err)
	}
	if !partial.Outcome.Partial || partial.Outcome.FailedDeliveries != 0 {
		t.Fatalf("partial outcome = %#v, want explicit zero-count partial", partial.Outcome)
	}
}

type httpPeerForwarder struct{}

func (httpPeerForwarder) Forward(ctx context.Context, addr string, payload []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/v1/forward", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer returned %s: %s", resp.Status, body)
	}
	return body, nil
}

func TestStoreFollowerPreservesPartialPublishOutcomeAndError(t *testing.T) {
	response := &queue.PublishResponse{TopicID: "topicone", QueueIDs: []string{"queueone"}}
	server := peer.NewServer(peer.ServerConfig{Applier: &outcomeConsensus{response: &queue.PublishOutcome{
		Response: response,
		Partial:  true,
	}}})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		_ = server.Shutdown(context.Background())
	})
	go func() { _ = server.Serve(listener) }()

	health := newHealthyReplicaForStoreTest(t)
	engine := &outcomeConsensus{leader: false, address: listener.Addr().String()}
	local := &topicListStorage{topics: &queue.ListTopicsResponse{Topics: []queue.Topic{{TopicID: "topicone"}}}}
	store := NewStore(local, engine, httpPeerForwarder{}, WithReplicaHealth(health))

	got, err := store.Publish(context.Background(), "topicone", &queue.PublishRequest{})
	if got == nil || got.TopicID != response.TopicID {
		t.Fatalf("follower Publish response = %#v, want %#v", got, response)
	}
	var partial *queue.PartialPublishError
	if !errors.As(err, &partial) || !partial.Outcome.Partial || partial.Outcome.FailedDeliveries != 0 {
		t.Fatalf("follower Publish error = %v, want explicit zero-count partial", err)
	}
}

type blockingDescribeStorage struct {
	queue.ReplicatedStorage
	started chan struct{}
	release chan struct{}
}

func (s *blockingDescribeStorage) DescribeQueue(context.Context, *v1.DescribeQueueRequest) (*v1.DescribeQueueResponse, error) {
	close(s.started)
	<-s.release
	return &v1.DescribeQueueResponse{}, nil
}

func TestQuarantineRaceCannotReturnACompletedLocalRead(t *testing.T) {
	health := newHealthyReplicaForStoreTest(t)
	local := &blockingDescribeStorage{started: make(chan struct{}), release: make(chan struct{})}
	store := NewStore(local, &outcomeConsensus{}, nil, WithReplicaHealth(health))

	done := make(chan error, 1)
	go func() {
		_, err := store.DescribeQueue(context.Background(), &v1.DescribeQueueRequest{QueueId: "queueone"})
		done <- err
	}()
	<-local.started
	if err := health.Fail(errors.New("replica partial")); err != nil {
		t.Fatalf("Fail() = %v", err)
	}
	if err := health.Recover(); err != nil {
		t.Fatalf("Recover() = %v", err)
	}
	close(local.release)

	if err := <-done; !errors.Is(err, pqerr.ErrUnavailable) {
		t.Fatalf("DescribeQueue spanning Fail/Recover = %v, want unavailable", err)
	}
}

func TestQuarantinedStoreRejectsEveryPublicOperation(t *testing.T) {
	health := newHealthyReplicaForStoreTest(t)
	if err := health.Fail(errors.New("replica partial")); err != nil {
		t.Fatalf("Fail() = %v", err)
	}
	store := NewStore(&topicListStorage{}, &outcomeConsensus{leader: true}, nil, WithReplicaHealth(health))
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{name: "create queue", call: func() error { _, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{}); return err }},
		{name: "delete queue", call: func() error { _, err := store.DeleteQueue(ctx, &v1.DeleteQueueRequest{}); return err }},
		{name: "purge queue", call: func() error { _, err := store.PurgeQueue(ctx, &v1.PurgeQueueRequest{}); return err }},
		{name: "send", call: func() error { _, err := store.Send(ctx, &v1.SendRequest{}); return err }},
		{name: "receive", call: func() error { _, err := store.Receive(ctx, &v1.ReceiveRequest{}); return err }},
		{name: "delete messages", call: func() error { _, err := store.Delete(ctx, &v1.DeleteRequest{}); return err }},
		{name: "describe queue", call: func() error { _, err := store.DescribeQueue(ctx, &v1.DescribeQueueRequest{}); return err }},
		{name: "list queues", call: func() error { _, err := store.ListQueues(ctx, &v1.ListQueuesRequest{}); return err }},
		{name: "peek", call: func() error { _, err := store.Peek(ctx, &queue.PeekRequest{}); return err }},
		{name: "list topics", call: func() error { _, err := store.ListTopics(ctx); return err }},
		{name: "create topic", call: func() error { _, err := store.CreateTopic(ctx, &queue.CreateTopicRequest{}); return err }},
		{name: "delete topic", call: func() error { _, err := store.DeleteTopic(ctx, "topicone"); return err }},
		{name: "topic inventory", call: func() error { _, err := store.TopicInventory(ctx); return err }},
		{name: "subscribe", call: func() error { _, err := store.Subscribe(ctx, "topicone", &queue.SubscribeRequest{}); return err }},
		{name: "unsubscribe", call: func() error { return store.Unsubscribe(ctx, "topicone", "subone") }},
		{name: "publish", call: func() error { _, err := store.Publish(ctx, "topicone", &queue.PublishRequest{}); return err }},
		{name: "sweep", call: func() error { _, err := store.Sweep(ctx, "queueone"); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); !errors.Is(err, pqerr.ErrUnavailable) {
				t.Fatalf("operation error = %v, want unavailable", err)
			}
		})
	}
}

func (c *commitUnknownConsensus) IsLeader() bool { return true }

func (c *commitUnknownConsensus) Apply(context.Context, []byte) (any, error) {
	c.mu.Lock()
	c.applyCalls++
	c.mu.Unlock()

	return nil, consensus.ErrCommitUnknown
}

type countingForwarder struct {
	mu       sync.Mutex
	calls    int
	err      error
	raw      []byte
	payloads [][]byte
}

type delegatingCountingForwarder struct {
	delegate Forwarder
	mu       sync.Mutex
	calls    int
}

func (f *delegatingCountingForwarder) Forward(ctx context.Context, addr string, payload []byte) ([]byte, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return f.delegate.Forward(ctx, addr, payload)
}

func (f *countingForwarder) Forward(_ context.Context, _ string, payload []byte) ([]byte, error) {
	f.mu.Lock()
	f.calls++
	f.payloads = append(f.payloads, append([]byte(nil), payload...))
	f.mu.Unlock()

	if f.err != nil {
		return nil, f.err
	}

	return f.raw, nil
}

func TestStoreDoesNotRetryOrForwardCommitUnknown(t *testing.T) {
	engine := new(commitUnknownConsensus)
	forwarder := new(countingForwarder)
	store := NewStore(nil, engine, forwarder, WithApplyTimeout(250*time.Millisecond))

	result, err := store.CreateTopic(context.Background(), &queue.CreateTopicRequest{TopicName: "events"})
	if result != nil || !errors.Is(err, consensus.ErrCommitUnknown) {
		t.Fatalf("CreateTopic() = %#v, %v; want nil %v", result, err, consensus.ErrCommitUnknown)
	}

	engine.mu.Lock()
	applyCalls := engine.applyCalls
	engine.mu.Unlock()
	if applyCalls != 1 {
		t.Fatalf("consensus Apply calls = %d, want 1", applyCalls)
	}

	forwarder.mu.Lock()
	forwardCalls := forwarder.calls
	forwarder.mu.Unlock()
	if forwardCalls != 0 {
		t.Fatalf("peer Forward calls = %d, want 0 for indeterminate commit", forwardCalls)
	}
}

type scriptedConsensus struct {
	consensus.Consensus

	mu         sync.Mutex
	leader     bool
	applyErr   error
	applyCalls int
}

func (c *scriptedConsensus) IsLeader() bool { return c.leader }

func (c *scriptedConsensus) Leader() (string, string, error) {
	return "leader", "leader-address", nil
}

func (c *scriptedConsensus) Apply(context.Context, []byte) (any, error) {
	c.mu.Lock()
	c.applyCalls++
	c.mu.Unlock()
	return nil, c.applyErr
}

func TestStoreNeverReroutesAmbiguousJoinedErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "commit unknown plus not leader", err: errors.Join(consensus.ErrCommitUnknown, consensus.ErrNotLeader)},
		{name: "partial fanout plus not leader", err: &queue.PartialPublishError{Causes: []error{consensus.ErrNotLeader}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine := &scriptedConsensus{leader: true, applyErr: test.err}
			forwarder := new(countingForwarder)
			store := NewStore(nil, engine, forwarder, WithApplyTimeout(100*time.Millisecond))

			result, err := store.CreateTopic(context.Background(), &queue.CreateTopicRequest{TopicName: "events"})
			if result != nil || !errors.Is(err, test.err) {
				t.Fatalf("CreateTopic() = %#v, %v; want original ambiguous error", result, err)
			}
			engine.mu.Lock()
			applyCalls := engine.applyCalls
			engine.mu.Unlock()
			forwarder.mu.Lock()
			forwardCalls := forwarder.calls
			forwarder.mu.Unlock()
			if applyCalls != 1 || forwardCalls != 0 {
				t.Fatalf("Apply/Forward calls = %d/%d, want 1/0", applyCalls, forwardCalls)
			}
		})
	}
}

func TestFollowerStoreDoesNotRetryForwardedTerminalErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "commit unknown", err: consensus.ErrCommitUnknown},
		{name: "failed precondition", err: pqerr.ErrFailedPrecondition},
		{name: "partial fanout plus not leader", err: &queue.PartialPublishError{Causes: []error{consensus.ErrNotLeader}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine := &scriptedConsensus{leader: false}
			forwarder := &countingForwarder{err: test.err}
			store := NewStore(nil, engine, forwarder, WithApplyTimeout(100*time.Millisecond))

			result, err := store.CreateTopic(context.Background(), &queue.CreateTopicRequest{TopicName: "events"})
			if result != nil || !errors.Is(err, test.err) {
				t.Fatalf("CreateTopic() = %#v, %v; want terminal forwarded error", result, err)
			}
			forwarder.mu.Lock()
			forwardCalls := forwarder.calls
			forwarder.mu.Unlock()
			if forwardCalls != 1 {
				t.Fatalf("Forward calls = %d, want one with no retry", forwardCalls)
			}
		})
	}
}

func TestDeleteResultResponseDecodesForwardedEffects(t *testing.T) {
	want := &queue.DeleteQueueResult{RemovedSubscriptions: []queue.Subscription{{SubscriptionID: "subscription-1"}}}
	encoded, err := deletewire.Encode(want)
	td.Require(t).CmpNoError(err)
	got, err := deleteResultResponse[queue.DeleteQueueResult](encoded, nil)
	td.Require(t).CmpNoError(err)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("forwarded delete result = %#v, want %#v", got, want)
	}
}

func TestDeleteResultResponseAcceptsLegacyEmptyResponse(t *testing.T) {
	got, err := deleteResultResponse[queue.DeleteQueueResult]([]byte{}, nil)
	td.Require(t).CmpNoError(err)
	if got == nil || len(got.RemovedSubscriptions) != 0 {
		t.Fatalf("legacy delete result = %#v, want non-nil empty result", got)
	}
}

func TestStoreDeleteResultsRoundTripThroughFSM(t *testing.T) {
	ctx := context.Background()
	cluster := newTestCluster(t, 1)
	store := cluster.leader(5 * time.Second).node.Store()

	firstQueue, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "first"})
	td.Require(t).CmpNoError(err)
	secondQueue, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "second"})
	td.Require(t).CmpNoError(err)
	firstTopic, err := store.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "first"})
	td.Require(t).CmpNoError(err)
	secondTopic, err := store.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "second"})
	td.Require(t).CmpNoError(err)

	firstSubscription, err := store.Subscribe(ctx, firstTopic.TopicID, &queue.SubscribeRequest{QueueID: firstQueue.QueueId})
	td.Require(t).CmpNoError(err)
	_, err = store.Subscribe(ctx, firstTopic.TopicID, &queue.SubscribeRequest{QueueID: secondQueue.QueueId})
	td.Require(t).CmpNoError(err)
	secondSubscription, err := store.Subscribe(ctx, secondTopic.TopicID, &queue.SubscribeRequest{QueueID: firstQueue.QueueId})
	td.Require(t).CmpNoError(err)

	deletedTopic, err := store.DeleteTopic(ctx, firstTopic.TopicID)
	td.Require(t).CmpNoError(err)
	td.Cmp(t, deletedTopic.RemovedSubscriptions, td.Len(2))
	td.Cmp(t, deletedTopic.RemovedSubscriptions[0].SubscriptionID, firstSubscription.SubscriptionID)

	deletedQueue, err := store.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: firstQueue.QueueId, Force: true})
	td.Require(t).CmpNoError(err)
	td.Cmp(t, deletedQueue.RemovedSubscriptions, td.Len(1))
	td.Cmp(t, deletedQueue.RemovedSubscriptions[0].SubscriptionID, secondSubscription.SubscriptionID)

	store.consistency = ConsistencyStrong
	inventory, err := store.TopicInventory(ctx)
	td.Require(t).CmpNoError(err)
	td.Cmp(t, inventory.TopicsExist, int64(1))
	td.Cmp(t, inventory.SubscriptionCounts, map[string]int64{secondTopic.TopicID: 0})
}

func TestFollowerStoreDeleteResultsRoundTripThroughPeer(t *testing.T) {
	ctx := context.Background()
	cluster := newTestCluster(t, 3)
	cluster.leader(10 * time.Second)
	store := cluster.follower().node.Store()

	firstQueue, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "follower-first"})
	td.Require(t).CmpNoError(err)
	secondQueue, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "follower-second"})
	td.Require(t).CmpNoError(err)
	firstTopic, err := store.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "follower-first"})
	td.Require(t).CmpNoError(err)
	secondTopic, err := store.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "follower-second"})
	td.Require(t).CmpNoError(err)

	firstSubscription, err := store.Subscribe(ctx, firstTopic.TopicID, &queue.SubscribeRequest{QueueID: firstQueue.QueueId})
	td.Require(t).CmpNoError(err)
	secondSubscription, err := store.Subscribe(ctx, firstTopic.TopicID, &queue.SubscribeRequest{QueueID: secondQueue.QueueId})
	td.Require(t).CmpNoError(err)
	queueSubscription, err := store.Subscribe(ctx, secondTopic.TopicID, &queue.SubscribeRequest{QueueID: firstQueue.QueueId})
	td.Require(t).CmpNoError(err)

	deletedTopic, err := store.DeleteTopic(ctx, firstTopic.TopicID)
	td.Require(t).CmpNoError(err)
	td.Cmp(t, subscriptionResultIDs(deletedTopic.RemovedSubscriptions), []string{
		firstSubscription.SubscriptionID,
		secondSubscription.SubscriptionID,
	})

	deletedQueue, err := store.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: firstQueue.QueueId, Force: true})
	td.Require(t).CmpNoError(err)
	td.Cmp(t, subscriptionResultIDs(deletedQueue.RemovedSubscriptions), []string{queueSubscription.SubscriptionID})
}

func TestFollowerStorePreservesLeaderDeleteFailedPreconditionWithoutRetry(t *testing.T) {
	ctx := context.Background()
	cluster := newTestCluster(t, 3)
	cluster.leader(10 * time.Second)
	store := cluster.follower().node.Store()
	counter := &delegatingCountingForwarder{delegate: store.forwarder}
	store.forwarder = counter

	created, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "follower-force-safe"})
	td.Require(t).CmpNoError(err)
	_, err = store.Send(ctx, &v1.SendRequest{
		QueueId:  created.QueueId,
		Messages: []*v1.SendMessage{{Body: []byte("message")}},
	})
	td.Require(t).CmpNoError(err)
	counter.mu.Lock()
	counter.calls = 0
	counter.mu.Unlock()

	result, err := store.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: created.QueueId})
	if result != nil || !errors.Is(err, pqerr.ErrFailedPrecondition) {
		t.Fatalf("follower unforced delete = %#v, %v; want nil %v", result, err, pqerr.ErrFailedPrecondition)
	}
	counter.mu.Lock()
	forwardCalls := counter.calls
	counter.mu.Unlock()
	if forwardCalls != 1 {
		t.Fatalf("follower Forward calls = %d, want one with no retry", forwardCalls)
	}
}

func subscriptionResultIDs(subscriptions []queue.Subscription) []string {
	ids := make([]string, 0, len(subscriptions))
	for _, subscription := range subscriptions {
		ids = append(ids, subscription.SubscriptionID)
	}
	return ids
}
