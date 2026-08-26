package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/cluster/command"
	"github.com/marsolab/plainq/internal/cluster/consensus"
	"github.com/marsolab/plainq/internal/cluster/peer"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/server/service/queue/litestore"
	"github.com/marsolab/plainq/internal/shared/deleteresult"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

func TestNewLeaderRejectsOversizedLocalDeleteBeforeLegacyFollowerApply(t *testing.T) {
	ctx := context.Background()
	storage, topicID, _ := newProposalDeleteFixture(t, "local")
	underlying := &proposalConsensusRecorder{leader: true}
	guard := newProposalGuard(underlying, storage)
	guard.deleteResultLimit = 128
	store := NewStore(storage, guard, nil, WithApplyTimeout(time.Second))

	result, err := store.DeleteTopic(ctx, topicID)
	var capacityErr *deleteresult.CapacityError
	if result != nil || !errors.As(err, &capacityErr) || errors.Is(err, pqerr.ErrInvalidInput) {
		t.Fatalf("oversized local delete = %#v, %v; want nil unclassified capacity result", result, err)
	}
	if got := underlying.applyCount(); got != 0 {
		t.Fatalf("legacy follower Apply calls = %d, want zero before proposal", got)
	}

	inventory, err := storage.TopicInventory(ctx)
	if err != nil {
		t.Fatalf("inventory after rejected local delete: %v", err)
	}
	if inventory.SubscriptionCounts[topicID] != 1 {
		t.Fatalf("subscription count after rejected local delete = %d, want 1", inventory.SubscriptionCounts[topicID])
	}
}

func TestNewLeaderRejectsOversizedForwardedDeleteBeforeLegacyFollowerApply(t *testing.T) {
	ctx := context.Background()
	storage, topicID, queueID := newProposalDeleteFixture(t, "forwarded")
	underlying := &proposalConsensusRecorder{leader: true}
	guard := newProposalGuard(underlying, storage)
	guard.deleteResultLimit = 128
	serverURL := startProposalPeerServer(t, guard)

	payload, err := (&v1.DeleteQueueRequest{QueueId: queueID, Force: true}).MarshalVT()
	if err != nil {
		t.Fatalf("marshal forwarded queue delete: %v", err)
	}
	encoded := encodeProposalCommand(t, &command.Command{
		Op:        command.OpDeleteQueue,
		Timestamp: time.Now().UnixNano(),
		Payload:   payload,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/v1/forward", bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("create forwarded delete request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("forward oversized delete: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read forwarded delete response: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError || resp.Header.Get("X-Plainq-Cluster-Error") != "internal" {
		t.Fatalf("forwarded delete status = %d class %q body %q, want 500 internal",
			resp.StatusCode, resp.Header.Get("X-Plainq-Cluster-Error"), body)
	}
	if !strings.Contains(string(body), "transport capacity") {
		t.Fatalf("forwarded delete body = %q, want capacity error", body)
	}
	if got := underlying.applyCount(); got != 0 {
		t.Fatalf("legacy follower Apply calls = %d, want zero before proposal", got)
	}
	if _, err := storage.DescribeQueue(ctx, &v1.DescribeQueueRequest{QueueId: queueID}); err != nil {
		t.Fatalf("queue after rejected forwarded delete: %v", err)
	}
	inventory, err := storage.TopicInventory(ctx)
	if err != nil || inventory.SubscriptionCounts[topicID] != 1 {
		t.Fatalf("inventory after rejected forwarded delete = %#v, %v; want binding intact", inventory, err)
	}
}

func TestProposalGuardRejectsNonLeaderDeleteBeforePreview(t *testing.T) {
	underlying := &proposalConsensusRecorder{leader: false}
	preview := &proposalPreviewRecorder{}
	guard := newProposalGuard(underlying, preview)
	encoded := encodeProposalCommand(t, &command.Command{Op: command.OpDeleteTopic, Target: "topic-1"})

	result, err := guard.Apply(context.Background(), encoded)
	if result != nil || !errors.Is(err, consensus.ErrNotLeader) {
		t.Fatalf("non-leader delete = %#v, %v; want nil ErrNotLeader", result, err)
	}
	if got := preview.callCount(); got != 0 {
		t.Fatalf("non-leader preview calls = %d, want zero", got)
	}
	if got := underlying.barrierCount(); got != 0 {
		t.Fatalf("non-leader barrier calls = %d, want zero", got)
	}
	if got := underlying.applyCount(); got != 0 {
		t.Fatalf("non-leader Apply calls = %d, want zero", got)
	}
}

func TestProposalGuardBarrierFailureStopsBeforePreviewAndApply(t *testing.T) {
	barrierErr := errors.New("barrier failed")
	underlying := &proposalConsensusRecorder{leader: true, barrierErr: barrierErr}
	preview := &proposalPreviewRecorder{}
	guard := newProposalGuard(underlying, preview)
	encoded := encodeProposalCommand(t, &command.Command{Op: command.OpDeleteTopic, Target: "topic-1"})

	result, err := guard.Apply(context.Background(), encoded)
	if result != nil || !errors.Is(err, barrierErr) {
		t.Fatalf("delete with failed barrier = %#v, %v; want nil barrier error", result, err)
	}
	if got := preview.callCount(); got != 0 {
		t.Fatalf("preview calls after barrier failure = %d, want zero", got)
	}
	if got := underlying.applyCount(); got != 0 {
		t.Fatalf("Apply calls after barrier failure = %d, want zero", got)
	}
}

func TestStoreForwardsDeleteOnceWhenGuardBarrierLosesLeadership(t *testing.T) {
	underlying := &proposalConsensusRecorder{
		leader:     true,
		barrierErr: fmt.Errorf("leadership changed before preview: %w", consensus.ErrNotLeader),
	}
	preflight := &proposalPreviewRecorder{}
	guard := newProposalGuard(underlying, preflight)
	forwarder := new(countingForwarder)
	store := NewStore(nil, guard, forwarder, WithApplyTimeout(time.Second))

	result, err := store.DeleteTopic(context.Background(), "topic-1")
	if err != nil || result == nil || len(result.RemovedSubscriptions) != 0 {
		t.Fatalf("DeleteTopic() = %#v, %v; want forwarded legacy-empty success", result, err)
	}
	if got := preflight.callCount(); got != 0 {
		t.Fatalf("preflight calls after barrier leadership loss = %d, want zero", got)
	}
	if got := underlying.applyCount(); got != 0 {
		t.Fatalf("local underlying Apply calls = %d, want zero", got)
	}
	forwarder.mu.Lock()
	forwardCalls := forwarder.calls
	forwarded := append([][]byte(nil), forwarder.payloads...)
	forwarder.mu.Unlock()
	if forwardCalls != 1 || len(forwarded) != 1 {
		t.Fatalf("Forward calls/payloads = %d/%d, want 1/1", forwardCalls, len(forwarded))
	}
	cmd, err := command.Decode(forwarded[0])
	if err != nil || cmd.Op != command.OpDeleteTopic || cmd.Target != "topic-1" {
		t.Fatalf("forwarded command = %#v, %v; want original topic delete", cmd, err)
	}
}

func TestProposalGuardOrdersBarrierPreflightAndApply(t *testing.T) {
	events := new(proposalEventLog)
	underlying := &proposalConsensusRecorder{leader: true, events: events}
	preview := &proposalPreviewRecorder{events: events}
	guard := newProposalGuard(underlying, preview)
	if guard.deleteResultLimit != deleteresult.MaxEnvelopeBytes {
		t.Fatalf("default delete result limit = %d, want %d", guard.deleteResultLimit, deleteresult.MaxEnvelopeBytes)
	}
	encoded := encodeProposalCommand(t, &command.Command{Op: command.OpDeleteTopic, Target: "topic-1"})

	if _, err := guard.Apply(context.Background(), encoded); err != nil {
		t.Fatalf("apply ordered delete proposal: %v", err)
	}
	want := []string{"barrier", "preflight-topic", "apply-delete_topic"}
	if got := events.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("delete proposal order = %v, want %v", got, want)
	}
	if got := preview.recordedLimits(); !reflect.DeepEqual(got, []int{deleteresult.MaxEnvelopeBytes}) {
		t.Fatalf("preflight limits = %v, want default peer ceiling", got)
	}
}

func TestProposalGuardPassesFullQueueRequestToPreflight(t *testing.T) {
	preflight := &proposalPreviewRecorder{}
	guard := newProposalGuard(&proposalConsensusRecorder{leader: true}, preflight)
	input := &v1.DeleteQueueRequest{QueueId: "queue-1", Force: true}
	payload, err := input.MarshalVT()
	if err != nil {
		t.Fatalf("marshal delete queue request: %v", err)
	}
	encoded := encodeProposalCommand(t, &command.Command{Op: command.OpDeleteQueue, Payload: payload})

	if _, err := guard.Apply(context.Background(), encoded); err != nil {
		t.Fatalf("apply queue proposal: %v", err)
	}
	preflight.mu.Lock()
	defer preflight.mu.Unlock()
	if len(preflight.queueReqs) != 1 || preflight.queueReqs[0].GetQueueId() != "queue-1" || !preflight.queueReqs[0].GetForce() {
		t.Fatalf("queue preflight requests = %#v, want full Force=true request", preflight.queueReqs)
	}
}

func TestProposalGuardAllowsOrdinaryAppliesToOverlap(t *testing.T) {
	applyStarted := make(chan command.Op, 2)
	release := make(chan struct{})
	underlying := &proposalConsensusRecorder{
		leader:               true,
		applyStarted:         applyStarted,
		releaseOrdinaryApply: release,
	}
	guard := newProposalGuard(underlying, &proposalPreviewRecorder{})
	encoded := encodeProposalCommand(t, &command.Command{Op: command.OpSubscribe})

	done := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := guard.Apply(context.Background(), encoded)
			done <- err
		}()
	}
	for range 2 {
		select {
		case <-applyStarted:
		case <-time.After(time.Second):
			t.Fatal("ordinary Applies did not overlap in the underlying consensus call")
		}
	}
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatalf("ordinary Apply error = %v", err)
		}
	}
}

func TestProposalGuardFairlyOrdersWaitingDeleteBeforeLaterOrdinaryApply(t *testing.T) {
	applyStarted := make(chan command.Op, 2)
	releaseDeleteApply := make(chan struct{})
	underlying := &proposalConsensusRecorder{
		leader:             true,
		applyStarted:       applyStarted,
		releaseDeleteApply: releaseDeleteApply,
	}
	guard := newProposalGuard(underlying, &proposalPreviewRecorder{})
	if err := guard.gate.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("hold initial reader slot: %v", err)
	}
	heldInitialReader := true
	defer func() {
		if heldInitialReader {
			guard.gate.Release(1)
		}
	}()

	deleteCommand := encodeProposalCommand(t, &command.Command{Op: command.OpDeleteTopic, Target: "topic-1"})
	deleteDone := make(chan error, 1)
	go func() {
		_, err := guard.Apply(context.Background(), deleteCommand)
		deleteDone <- err
	}()

	deadline := time.Now().Add(time.Second)
	for guard.gate.TryAcquire(1) {
		guard.gate.Release(1)
		if time.Now().After(deadline) {
			t.Fatal("delete did not queue for exclusive admission")
		}
		runtime.Gosched()
	}

	ordinaryCommand := encodeProposalCommand(t, &command.Command{Op: command.OpSubscribe})
	ordinaryDone := make(chan error, 1)
	go func() {
		_, err := guard.Apply(context.Background(), ordinaryCommand)
		ordinaryDone <- err
	}()
	guard.gate.Release(1)
	heldInitialReader = false

	if op := <-applyStarted; op != command.OpDeleteTopic {
		t.Fatalf("first Apply after held reader = %s, want waiting delete", op)
	}
	select {
	case op := <-applyStarted:
		t.Fatalf("later %s bypassed delete's exclusive Apply", op)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseDeleteApply)
	if err := <-deleteDone; err != nil {
		t.Fatalf("delete Apply error = %v", err)
	}
	if op := <-applyStarted; op != command.OpSubscribe {
		t.Fatalf("Apply after delete = %s, want subscribe", op)
	}
	if err := <-ordinaryDone; err != nil {
		t.Fatalf("ordinary Apply error = %v", err)
	}
}

func TestProposalGuardSerializesDeletePreviewAndConcurrentWrite(t *testing.T) {
	applyStarted := make(chan command.Op, 2)
	releaseDeleteApply := make(chan struct{})
	preview := &proposalPreviewRecorder{}
	underlying := &proposalConsensusRecorder{
		leader:             true,
		applyStarted:       applyStarted,
		releaseDeleteApply: releaseDeleteApply,
	}
	guard := newProposalGuard(underlying, preview)

	deleteCommand := encodeProposalCommand(t, &command.Command{Op: command.OpDeleteTopic, Target: "topic-1"})
	subscribePayload, err := json.Marshal(&queue.SubscribeRequest{QueueID: "queue-1"})
	if err != nil {
		t.Fatalf("marshal subscribe command: %v", err)
	}
	subscribeCommand := encodeProposalCommand(t, &command.Command{
		Op:      command.OpSubscribe,
		Target:  "topic-1",
		IDs:     []string{"subscription-1"},
		Payload: subscribePayload,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	deleteDone := make(chan error, 1)
	go func() {
		_, applyErr := guard.Apply(ctx, deleteCommand)
		deleteDone <- applyErr
	}()

	select {
	case op := <-applyStarted:
		if op != command.OpDeleteTopic {
			t.Fatalf("first underlying Apply = %s, want delete_topic", op)
		}
	case <-ctx.Done():
		t.Fatal("delete underlying Apply did not start")
	}

	subscribeCalling := make(chan struct{})
	subscribeDone := make(chan error, 1)
	go func() {
		close(subscribeCalling)
		_, applyErr := guard.Apply(ctx, subscribeCommand)
		subscribeDone <- applyErr
	}()
	<-subscribeCalling

	select {
	case op := <-applyStarted:
		t.Fatalf("concurrent %s reached underlying Apply before delete Apply completed", op)
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseDeleteApply)
	if err := <-deleteDone; err != nil {
		t.Fatalf("apply guarded delete: %v", err)
	}
	select {
	case op := <-applyStarted:
		if op != command.OpSubscribe {
			t.Fatalf("second underlying Apply = %s, want subscribe", op)
		}
	case <-ctx.Done():
		t.Fatal("serialized subscribe did not reach underlying Apply")
	}
	if err := <-subscribeDone; err != nil {
		t.Fatalf("apply serialized subscribe: %v", err)
	}
	if got := underlying.appliedOperations(); len(got) != 2 || got[0] != command.OpDeleteTopic || got[1] != command.OpSubscribe {
		t.Fatalf("underlying Apply order = %v, want [delete_topic subscribe]", got)
	}
}

func TestProposalGuardCanceledWaiterNeverCallsUnderlyingApply(t *testing.T) {
	applyStarted := make(chan command.Op, 1)
	releaseDeleteApply := make(chan struct{})
	underlying := &proposalConsensusRecorder{
		leader:             true,
		applyStarted:       applyStarted,
		releaseDeleteApply: releaseDeleteApply,
	}
	guard := newProposalGuard(underlying, &proposalPreviewRecorder{})
	deleteCommand := encodeProposalCommand(t, &command.Command{Op: command.OpDeleteTopic, Target: "topic-1"})
	ordinaryCommand := encodeProposalCommand(t, &command.Command{Op: command.OpSubscribe})

	deleteDone := make(chan error, 1)
	go func() {
		_, err := guard.Apply(context.Background(), deleteCommand)
		deleteDone <- err
	}()
	<-applyStarted
	if guard.gate.TryAcquire(1) {
		guard.gate.Release(1)
		t.Fatal("ordinary proposal acquired gate while delete held exclusive admission")
	}

	waitCtx, cancel := context.WithCancel(context.Background())
	waiterCalling := make(chan struct{})
	waiterDone := make(chan error, 1)
	go func() {
		close(waiterCalling)
		_, err := guard.Apply(waitCtx, ordinaryCommand)
		waiterDone <- err
	}()
	<-waiterCalling
	runtime.Gosched()
	cancel()
	if err := <-waiterDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter error = %v, want %v", err, context.Canceled)
	}
	if got := underlying.applyCount(); got != 1 {
		t.Fatalf("underlying Apply calls with canceled waiter = %d, want one delete only", got)
	}
	close(releaseDeleteApply)
	if err := <-deleteDone; err != nil {
		t.Fatalf("delete Apply error = %v", err)
	}
}

func TestProposalGuardCancellationAfterPreflightStopsBeforeApply(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	preflight := &proposalPreviewRecorder{afterCall: cancel}
	underlying := &proposalConsensusRecorder{leader: true}
	guard := newProposalGuard(underlying, preflight)
	encoded := encodeProposalCommand(t, &command.Command{Op: command.OpDeleteTopic, Target: "topic-1"})

	result, err := guard.Apply(ctx, encoded)
	if result != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("post-preflight cancellation = %#v, %v; want nil %v", result, err, context.Canceled)
	}
	if got := underlying.applyCount(); got != 0 {
		t.Fatalf("underlying Apply calls after preflight cancellation = %d, want zero", got)
	}
}

func TestProposalGuardFailedPreconditionPrecedesCapacity(t *testing.T) {
	ctx := context.Background()
	storage, _, queueID := newProposalDeleteFixture(t, "force-precedence")
	if _, err := storage.Send(ctx, &v1.SendRequest{
		QueueId:  queueID,
		Messages: []*v1.SendMessage{{Body: []byte("message")}},
	}); err != nil {
		t.Fatalf("send precondition fixture message: %v", err)
	}
	underlying := &proposalConsensusRecorder{leader: true}
	guard := newProposalGuard(underlying, storage)
	guard.deleteResultLimit = 1
	store := NewStore(storage, guard, nil, WithApplyTimeout(time.Second))

	result, err := store.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID})
	var capacityErr *deleteresult.CapacityError
	if result != nil || !errors.Is(err, pqerr.ErrFailedPrecondition) || errors.As(err, &capacityErr) {
		t.Fatalf("guarded unforced delete = %#v, %v; want failed precondition before capacity", result, err)
	}
	if got := underlying.applyCount(); got != 0 {
		t.Fatalf("underlying Apply calls after precondition failure = %d, want zero", got)
	}
}

func TestNewNodeSharesProposalGuardAcrossStoreAndPeer(t *testing.T) {
	ctx := context.Background()
	testCluster := newTestCluster(t, 1)
	leader := testCluster.leader(5 * time.Second)
	guard, ok := leader.node.consensus.(*proposalGuard)
	if !ok {
		t.Fatalf("node consensus = %T, want *proposalGuard", leader.node.consensus)
	}
	if leader.node.store.consensus != guard {
		t.Fatal("Store and Node do not share the proposal guard instance")
	}
	guard.deleteResultLimit = 128

	createdQueue, err := leader.node.store.CreateQueue(ctx, &v1.CreateQueueRequest{
		QueueName: strings.Repeat(`<legacy & "uncapped">`, 8),
	})
	if err != nil {
		t.Fatalf("create guarded queue: %v", err)
	}
	createdTopic, err := leader.node.store.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "guard-wiring"})
	if err != nil {
		t.Fatalf("create guarded topic: %v", err)
	}
	if _, err := leader.node.store.Subscribe(ctx, createdTopic.TopicID, &queue.SubscribeRequest{QueueID: createdQueue.QueueId}); err != nil {
		t.Fatalf("create guarded subscription: %v", err)
	}

	if result, err := leader.node.store.DeleteTopic(ctx, createdTopic.TopicID); result != nil || err == nil {
		t.Fatalf("local guarded delete = %#v, %v; want capacity rejection", result, err)
	}
	payload, err := (&v1.DeleteQueueRequest{QueueId: createdQueue.QueueId, Force: true}).MarshalVT()
	if err != nil {
		t.Fatalf("marshal peer queue delete: %v", err)
	}
	encoded := encodeProposalCommand(t, &command.Command{Op: command.OpDeleteQueue, Payload: payload})
	response, err := leader.node.peerClient.Forward(ctx, leader.node.mux.Addr().String(), encoded)
	if err == nil || !strings.Contains(err.Error(), "transport capacity") || errors.Is(err, pqerr.ErrInvalidInput) {
		t.Fatalf("peer guarded delete = %d response bytes, %v; want unclassified capacity rejection", len(response), err)
	}

	inventory, err := leader.storage.TopicInventory(ctx)
	if err != nil || inventory.SubscriptionCounts[createdTopic.TopicID] != 1 {
		t.Fatalf("state after Store/peer rejections = %#v, %v; want binding intact", inventory, err)
	}
}

func newProposalDeleteFixture(t *testing.T, suffix string) (*litestore.Storage, string, string) {
	t.Helper()
	ctx := context.Background()
	storage := newTestStorage(t, t.TempDir())
	createdQueue, err := storage.CreateQueue(ctx, &v1.CreateQueueRequest{
		QueueName: strings.Repeat(`<legacy & "uncapped">`, 8) + suffix,
	})
	if err != nil {
		t.Fatalf("create proposal queue: %v", err)
	}
	createdTopic, err := storage.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "proposal-" + suffix})
	if err != nil {
		t.Fatalf("create proposal topic: %v", err)
	}
	if _, err := storage.Subscribe(ctx, createdTopic.TopicID, &queue.SubscribeRequest{QueueID: createdQueue.QueueId}); err != nil {
		t.Fatalf("create proposal subscription: %v", err)
	}

	return storage, createdTopic.TopicID, createdQueue.QueueId
}

func encodeProposalCommand(t *testing.T, cmd *command.Command) []byte {
	t.Helper()
	encoded, err := cmd.Encode()
	if err != nil {
		t.Fatalf("encode proposal command: %v", err)
	}
	return encoded
}

type proposalConsensusRecorder struct {
	consensus.Consensus

	mu                   sync.Mutex
	leader               bool
	applyCalls           int
	barrierCalls         int
	applied              []command.Op
	barrierErr           error
	events               *proposalEventLog
	applyStarted         chan<- command.Op
	releaseDeleteApply   <-chan struct{}
	releaseOrdinaryApply <-chan struct{}
}

func (c *proposalConsensusRecorder) Apply(_ context.Context, data []byte) (any, error) {
	cmd, err := command.Decode(data)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.applyCalls++
	c.applied = append(c.applied, cmd.Op)
	events := c.events
	applyStarted := c.applyStarted
	releaseDeleteApply := c.releaseDeleteApply
	releaseOrdinaryApply := c.releaseOrdinaryApply
	c.mu.Unlock()
	if events != nil {
		events.add("apply-" + cmd.Op.String())
	}
	if applyStarted != nil {
		applyStarted <- cmd.Op
	}
	if cmd.Op == command.OpDeleteTopic && releaseDeleteApply != nil {
		<-releaseDeleteApply
	}
	if cmd.Op != command.OpDeleteTopic && cmd.Op != command.OpDeleteQueue && releaseOrdinaryApply != nil {
		<-releaseOrdinaryApply
	}

	switch cmd.Op {
	case command.OpDeleteTopic:
		return &queue.DeleteTopicResult{}, nil
	case command.OpDeleteQueue:
		return &queue.DeleteQueueResult{}, nil
	case command.OpSubscribe:
		return &queue.SubscribeResponse{}, nil
	default:
		return nil, nil
	}
}

func (c *proposalConsensusRecorder) IsLeader() bool { return c.leader }

func (*proposalConsensusRecorder) Leader() (string, string, error) {
	return "leader", "leader-address", nil
}

func (c *proposalConsensusRecorder) Barrier(context.Context) error {
	c.mu.Lock()
	c.barrierCalls++
	barrierErr := c.barrierErr
	events := c.events
	c.mu.Unlock()
	if events != nil {
		events.add("barrier")
	}
	return barrierErr
}

func (c *proposalConsensusRecorder) applyCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.applyCalls
}

func (c *proposalConsensusRecorder) barrierCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.barrierCalls
}

func (c *proposalConsensusRecorder) appliedOperations() []command.Op {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]command.Op(nil), c.applied...)
}

type proposalPreviewRecorder struct {
	mu        sync.Mutex
	calls     int
	limits    []int
	queueReqs []*v1.DeleteQueueRequest
	topicErr  error
	queueErr  error
	events    *proposalEventLog
	afterCall func()
}

func (p *proposalPreviewRecorder) PreflightDeleteTopic(_ context.Context, _ string, limit int) error {
	p.mu.Lock()
	p.calls++
	p.limits = append(p.limits, limit)
	events := p.events
	err := p.topicErr
	afterCall := p.afterCall
	p.mu.Unlock()
	if events != nil {
		events.add("preflight-topic")
	}
	if afterCall != nil {
		afterCall()
	}
	return err
}

func (p *proposalPreviewRecorder) PreflightDeleteQueue(_ context.Context, input *v1.DeleteQueueRequest, limit int) error {
	p.mu.Lock()
	p.calls++
	p.limits = append(p.limits, limit)
	p.queueReqs = append(p.queueReqs, input)
	err := p.queueErr
	p.mu.Unlock()
	return err
}

func (p *proposalPreviewRecorder) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func (p *proposalPreviewRecorder) recordedLimits() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]int(nil), p.limits...)
}

type proposalEventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *proposalEventLog) add(event string) {
	l.mu.Lock()
	l.events = append(l.events, event)
	l.mu.Unlock()
}

func (l *proposalEventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

type proposalPeerMembership struct{}

func (*proposalPeerMembership) AddVoter(context.Context, string, string) error    { return nil }
func (*proposalPeerMembership) AddNonVoter(context.Context, string, string) error { return nil }
func (*proposalPeerMembership) RemoveServer(context.Context, string) error        { return nil }
func (*proposalPeerMembership) Status() consensus.Status                          { return consensus.Status{} }

func startProposalPeerServer(t *testing.T, applier peer.Applier) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for proposal peer server: %v", err)
	}
	server := peer.NewServer(peer.ServerConfig{
		Applier:    applier,
		Membership: &proposalPeerMembership{},
	})
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			t.Errorf("shut down proposal peer server: %v", err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve proposal peer RPC: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("proposal peer RPC did not stop")
		}
	})

	return "http://" + listener.Addr().String()
}
