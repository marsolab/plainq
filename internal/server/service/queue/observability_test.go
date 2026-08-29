package queue

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	vm "github.com/VictoriaMetrics/metrics"
	"github.com/marsolab/plainq/internal/metrics"
	"github.com/marsolab/plainq/internal/server/policytx"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/telemetry"
	"github.com/maxatome/go-testdeep/td"
)

// scrapeMetrics renders the registry the way the /metrics endpoint does.
func scrapeMetrics() string {
	var buf bytes.Buffer

	vm.WritePrometheus(&buf, false)

	return buf.String()
}

// recorderSpy stands in for the telemetry collector.
type recorderSpy struct {
	mu sync.Mutex

	sent        uint64
	sentBytes   uint64
	received    uint64
	emptyRecv   int
	deleted     uint64
	queuesDelta int
	queuesExact int64
}

func (r *recorderSpy) RecordSend(_ string, count, totalBytes uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.sent += count
	r.sentBytes += totalBytes
}

func (r *recorderSpy) RecordReceive(_ string, count uint64, isEmpty bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.received += count

	if isEmpty {
		r.emptyRecv++
	}
}

func (r *recorderSpy) RecordDelete(_ string, count uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.deleted += count
}

func (r *recorderSpy) IncrementQueues() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.queuesDelta++
}

func (r *recorderSpy) DecrementQueues() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.queuesDelta--
}

func (r *recorderSpy) SetQueuesExist(count int64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.queuesExact = count
}

func (*recorderSpy) RecordRedelivery(string, uint64) {}
func (*recorderSpy) RecordDrop(string, uint64)       {}
func (*recorderSpy) RecordDLQ(string, uint64)        {}

// fakeStorage is a Storage that answers from whatever the test set on it.
type fakeStorage struct {
	Storage

	listTopicsResp  *ListTopicsResponse
	createTopicResp *CreateTopicResponse
	subscribeResp   *SubscribeResponse
	sendResp        *v1.SendResponse
	receiveResp     *v1.ReceiveResponse
	deleteResp      *v1.DeleteResponse
	publishResp     *PublishResponse
	deleteQueueResp *DeleteQueueResult
	deleteTopicResp *DeleteTopicResult
	inventory       TopicInventory
	err             error
}

// replayPolicyStorage returns previously committed policy results and marks
// the call as a replay. Embedding the rest of PolicyStorage keeps this fake
// focused on the observation boundary exercised below.
type replayPolicyStorage struct {
	*fakeStorage
	PolicyStorage
	replay bool
}

func (s *replayPolicyStorage) markReplay(ctx context.Context) {
	if s.replay {
		MarkPolicyReplay(ctx)
	}
}

func (s *replayPolicyStorage) PurgeQueuePolicy(
	ctx context.Context,
	_ *v1.PurgeQueueRequest,
	_ policytx.Mutation,
) (*v1.PurgeQueueResponse, error) {
	s.markReplay(ctx)

	return &v1.PurgeQueueResponse{}, nil
}

func (s *replayPolicyStorage) DeleteQueuePolicy(
	ctx context.Context,
	_ *v1.DeleteQueueRequest,
	_ policytx.Mutation,
) (*DeleteQueueResult, error) {
	s.markReplay(ctx)

	return s.deleteQueueResp, nil
}

func (s *replayPolicyStorage) SendPolicy(
	ctx context.Context,
	_ *v1.SendRequest,
	_ policytx.Mutation,
) (*v1.SendResponse, error) {
	s.markReplay(ctx)

	return s.sendResp, nil
}

func (s *replayPolicyStorage) ReceivePolicy(
	ctx context.Context,
	_ *v1.ReceiveRequest,
	_ policytx.Mutation,
) (*v1.ReceiveResponse, error) {
	s.markReplay(ctx)

	return s.receiveResp, nil
}

func (s *replayPolicyStorage) DeletePolicy(
	ctx context.Context,
	_ *v1.DeleteRequest,
	_ policytx.Mutation,
) (*v1.DeleteResponse, error) {
	s.markReplay(ctx)

	return s.deleteResp, nil
}

func (f *fakeStorage) ListTopics(context.Context) (*ListTopicsResponse, error) {
	return f.listTopicsResp, f.err
}

func (f *fakeStorage) CreateTopic(context.Context, *CreateTopicRequest) (*CreateTopicResponse, error) {
	return f.createTopicResp, f.err
}

func (f *fakeStorage) Subscribe(context.Context, string, *SubscribeRequest) (*SubscribeResponse, error) {
	return f.subscribeResp, f.err
}

func (f *fakeStorage) Unsubscribe(context.Context, string, string) error { return f.err }

func (f *fakeStorage) Send(context.Context, *v1.SendRequest) (*v1.SendResponse, error) {
	return f.sendResp, f.err
}

func (f *fakeStorage) Receive(context.Context, *v1.ReceiveRequest) (*v1.ReceiveResponse, error) {
	return f.receiveResp, f.err
}

func (f *fakeStorage) Delete(context.Context, *v1.DeleteRequest) (*v1.DeleteResponse, error) {
	return f.deleteResp, f.err
}

func (f *fakeStorage) Publish(context.Context, string, *PublishRequest) (*PublishResponse, error) {
	return f.publishResp, f.err
}

func (f *fakeStorage) DeleteQueue(context.Context, *v1.DeleteQueueRequest) (*DeleteQueueResult, error) {
	return f.deleteQueueResp, f.err
}

func (f *fakeStorage) DeleteTopic(context.Context, string) (*DeleteTopicResult, error) {
	return f.deleteTopicResp, f.err
}

func (f *fakeStorage) TopicInventory(context.Context) (TopicInventory, error) {
	return f.inventory, f.err
}

func TestObservedStoragePreservesDeleteResultsAndUnmeasuredInventory(t *testing.T) {
	removed := []Subscription{{SubscriptionID: "sub-1", TopicID: "topic-1", QueueID: "queue-1"}}
	inner := &fakeStorage{
		deleteQueueResp: &DeleteQueueResult{RemovedSubscriptions: removed},
		deleteTopicResp: &DeleteTopicResult{RemovedSubscriptions: removed},
		inventory:       TopicInventory{TopicsExist: 1, SubscriptionCounts: map[string]int64{"topic-1": 1}},
	}
	store := NewObservedStorage(inner, telemetry.NewObserver(metrics.BackendSQLite))

	queueResult, err := store.DeleteQueue(context.Background(), &v1.DeleteQueueRequest{QueueId: "queue-1"})
	td.Require(t).CmpNoError(err)
	td.Cmp(t, queueResult, inner.deleteQueueResp)
	topicResult, err := store.DeleteTopic(context.Background(), "topic-1")
	td.Require(t).CmpNoError(err)
	td.Cmp(t, topicResult, inner.deleteTopicResp)
	inventory, err := store.TopicInventory(context.Background())
	td.Require(t).CmpNoError(err)
	td.Cmp(t, inventory, inner.inventory)
	td.Cmp(t, strings.Contains(scrapeMetrics(), `operation="topic_inventory"`), false,
		"maintenance inventory reads are not public storage operations")
}

// Test_ObservedStorage_recordsTheWholeQueueLifecycle proves the decorator
// derives its numbers from what actually crossed the API boundary — the ids
// the store handed back, not the ids the caller asked for.
func Test_ObservedStorage_recordsTheWholeQueueLifecycle(t *testing.T) {
	const queueID = "QOBSERVEDLIFECYCLE"

	spy := &recorderSpy{}
	observer := telemetry.NewObserver(metrics.BackendSQLite)
	observer.SetRecorder(spy)

	inner := &fakeStorage{
		sendResp: &v1.SendResponse{MessageIds: []string{"a", "b"}},
		receiveResp: &v1.ReceiveResponse{Messages: []*v1.ReceiveMessage{
			{Id: "a", Body: []byte("hello")},
		}},
		deleteResp: &v1.DeleteResponse{
			Successful: []string{"a"},
			Failed:     []*v1.DeleteFailure{{MessageId: "gone"}},
		},
	}

	store := NewObservedStorage(inner, observer)
	ctx := context.Background()

	_, err := store.Send(ctx, &v1.SendRequest{
		QueueId: queueID,
		Messages: []*v1.SendMessage{
			{Body: []byte("one")},
			{Body: []byte("two!!")},
		},
	})
	td.Require(t).CmpNoError(err)

	_, err = store.Receive(ctx, &v1.ReceiveRequest{QueueId: queueID})
	td.Require(t).CmpNoError(err)

	_, err = store.Delete(ctx, &v1.DeleteRequest{QueueId: queueID, MessageIds: []string{"a", "gone"}})
	td.Require(t).CmpNoError(err)

	spy.mu.Lock()
	defer spy.mu.Unlock()

	td.Cmp(t, spy.sent, uint64(2))
	td.Cmp(t, spy.sentBytes, uint64(8), "three bytes plus five")
	td.Cmp(t, spy.received, uint64(1))

	// Per-message sizes are a distribution, so they go to Prometheus only.
	td.Cmp(t, strings.Contains(scrapeMetrics(), `plainq_message_size_bytes_count{queue="`+queueID+`"} 2`), true,
		"each body is measured, not just the batch",
	)

	td.Cmp(t, spy.deleted, uint64(1),
		"only acknowledged ids count — a delete for a message that was never there is reported as a failure",
	)
}

// Test_ObservedStorage_countsEmptyReceives pins the distinction between a
// consumer that is busy and one that is polling an idle queue.
func Test_ObservedStorage_countsEmptyReceives(t *testing.T) {
	spy := &recorderSpy{}
	observer := telemetry.NewObserver(metrics.BackendSQLite)
	observer.SetRecorder(spy)

	store := NewObservedStorage(&fakeStorage{receiveResp: &v1.ReceiveResponse{}}, observer)

	_, err := store.Receive(context.Background(), &v1.ReceiveRequest{QueueId: "QEMPTY"})
	td.Require(t).CmpNoError(err)

	spy.mu.Lock()
	defer spy.mu.Unlock()

	td.Cmp(t, spy.emptyRecv, 1)
	td.Cmp(t, spy.received, uint64(0))
}

// Test_ObservedStorage_doesNotCountFailedOperations checks that a failed
// write leaves the message counters alone — an error is recorded as an error,
// not as traffic.
func Test_ObservedStorage_doesNotCountFailedOperations(t *testing.T) {
	spy := &recorderSpy{}
	observer := telemetry.NewObserver(metrics.BackendSQLite)
	observer.SetRecorder(spy)

	store := NewObservedStorage(&fakeStorage{err: errors.New("storage is down")}, observer)

	_, err := store.Send(context.Background(), &v1.SendRequest{
		QueueId:  "QFAILED",
		Messages: []*v1.SendMessage{{Body: []byte("x")}},
	})
	td.CmpError(t, err)

	spy.mu.Lock()
	defer spy.mu.Unlock()

	td.Cmp(t, spy.sent, uint64(0))

	td.Cmp(t, strings.Contains(scrapeMetrics(), `plainq_message_size_bytes_count{queue="QFAILED"}`), false,
		"a failed write records no message sizes either",
	)
}

func TestObservedStoragePolicyReplayDoesNotRepeatCommittedQueueEffects(t *testing.T) {
	const (
		purgedQueueID  = "QPOLICYREPLAYPURGE"
		deletedQueueID = "QPOLICYREPLAYDELETE"
		messageQueueID = "QPOLICYREPLAYMESSAGES"
	)

	spy := &recorderSpy{}
	observer := telemetry.NewObserver(metrics.BackendSQLite)
	observer.SetRecorder(spy)
	policyStore := &replayPolicyStorage{fakeStorage: &fakeStorage{
		deleteQueueResp: &DeleteQueueResult{},
		sendResp:        &v1.SendResponse{MessageIds: []string{"message-1"}},
		receiveResp: &v1.ReceiveResponse{Messages: []*v1.ReceiveMessage{{
			Id: "message-1", Body: []byte("body"),
		}}},
		deleteResp: &v1.DeleteResponse{Successful: []string{"message-1"}},
	}}
	store := NewObservedStorage(policyStore, observer)

	ctx := context.Background()
	mutation := policytx.Mutation{}
	_, err := store.PurgeQueuePolicy(ctx, &v1.PurgeQueueRequest{QueueId: purgedQueueID}, mutation)
	td.Require(t).CmpNoError(err)
	_, err = store.DeleteQueuePolicy(ctx, &v1.DeleteQueueRequest{QueueId: deletedQueueID}, mutation)
	td.Require(t).CmpNoError(err)
	_, err = store.SendPolicy(ctx, &v1.SendRequest{
		QueueId: messageQueueID, Messages: []*v1.SendMessage{{Body: []byte("body")}},
	}, mutation)
	td.Require(t).CmpNoError(err)
	_, err = store.ReceivePolicy(ctx, &v1.ReceiveRequest{QueueId: messageQueueID}, mutation)
	td.Require(t).CmpNoError(err)
	_, err = store.DeletePolicy(ctx, &v1.DeleteRequest{
		QueueId: messageQueueID, MessageIds: []string{"message-1"},
	}, mutation)
	td.Require(t).CmpNoError(err)

	spy.mu.Lock()
	td.Cmp(t, spy.sent, uint64(1))
	td.Cmp(t, spy.sentBytes, uint64(4))
	td.Cmp(t, spy.received, uint64(1))
	td.Cmp(t, spy.emptyRecv, 0)
	td.Cmp(t, spy.deleted, uint64(1))
	spy.mu.Unlock()

	// Model activity committed after the original purge/delete. Replaying an
	// old key must not erase these newer gauge values.
	metrics.SetQueueStats(purgedQueueID, 7, 3)
	metrics.SetQueueStats(deletedQueueID, 5, 2)
	metrics.SetQueueStats(messageQueueID, 9, 4)
	policyStore.replay = true

	_, err = store.PurgeQueuePolicy(ctx, &v1.PurgeQueueRequest{QueueId: purgedQueueID}, mutation)
	td.Require(t).CmpNoError(err)
	_, err = store.DeleteQueuePolicy(ctx, &v1.DeleteQueueRequest{QueueId: deletedQueueID}, mutation)
	td.Require(t).CmpNoError(err)
	_, err = store.SendPolicy(ctx, &v1.SendRequest{
		QueueId: messageQueueID, Messages: []*v1.SendMessage{{Body: []byte("body")}},
	}, mutation)
	td.Require(t).CmpNoError(err)
	assertQueueGaugeSample(t, messageQueueID, 9, 4)
	_, err = store.ReceivePolicy(ctx, &v1.ReceiveRequest{QueueId: messageQueueID}, mutation)
	td.Require(t).CmpNoError(err)
	assertQueueGaugeSample(t, messageQueueID, 9, 4)
	_, err = store.DeletePolicy(ctx, &v1.DeleteRequest{
		QueueId: messageQueueID, MessageIds: []string{"message-1"},
	}, mutation)
	td.Require(t).CmpNoError(err)
	assertQueueGaugeSample(t, messageQueueID, 9, 4)

	spy.mu.Lock()
	td.Cmp(t, spy.sent, uint64(1))
	td.Cmp(t, spy.sentBytes, uint64(4))
	td.Cmp(t, spy.received, uint64(1))
	td.Cmp(t, spy.emptyRecv, 0)
	td.Cmp(t, spy.deleted, uint64(1))
	spy.mu.Unlock()

	exposition := scrapeMetrics()
	for _, sample := range []string{
		`plainq_queue_depth{queue="` + purgedQueueID + `"} 7`,
		`plainq_messages_in_flight{queue="` + purgedQueueID + `"} 3`,
		`plainq_queue_depth{queue="` + deletedQueueID + `"} 5`,
		`plainq_messages_in_flight{queue="` + deletedQueueID + `"} 2`,
	} {
		td.Cmp(t, strings.Contains(exposition, sample), true, "replay preserves committed gauge sample")
	}
	for _, sample := range []string{
		`plainq_messages_sent_total{queue="` + messageQueueID + `"} 1`,
		`plainq_messages_sent_bytes_total{queue="` + messageQueueID + `"} 4`,
		`plainq_messages_received_total{queue="` + messageQueueID + `"} 1`,
		`plainq_messages_deleted_total{queue="` + messageQueueID + `"} 1`,
		`plainq_message_size_bytes_count{queue="` + messageQueueID + `"} 1`,
	} {
		td.Cmp(t, strings.Contains(exposition, sample), true, "replay preserves one committed metric effect")
	}
}

func assertQueueGaugeSample(t *testing.T, queueID string, depth, inFlight int64) {
	t.Helper()

	exposition := scrapeMetrics()
	td.Cmp(t, strings.Contains(exposition,
		`plainq_queue_depth{queue="`+queueID+`"} `+fmt.Sprint(depth)), true,
		"queue depth must not move on replay",
	)
	td.Cmp(t, strings.Contains(exposition,
		`plainq_messages_in_flight{queue="`+queueID+`"} `+fmt.Sprint(inFlight)), true,
		"in-flight count must not move on replay",
	)
}

func TestObservedStorageDoesNotEmitPublishBusinessEvent(t *testing.T) {
	observer := telemetry.NewObserver(metrics.BackendSQLite)
	recorder := newTopicRecorderSpy()
	observer.SetRecorder(recorder)

	store := NewObservedStorage(&fakeStorage{
		publishResp: &PublishResponse{
			TopicID:        "T1",
			QueueIDs:       []string{"Q1", "Q2", "Q3"},
			DeliveredCount: 2,
		},
	}, observer)

	_, err := store.Publish(context.Background(), "T1", &PublishRequest{
		Messages: []PublishMessage{{Body: []byte("payload")}},
	})
	td.Require(t).CmpNoError(err)

	recorder.mu.Lock()
	defer recorder.mu.Unlock()

	td.Cmp(t, recorder.publishes, []telemetry.TopicPublishEvent(nil),
		"the application boundary, not storage, owns publish business outcomes",
	)
}

func TestObservedStorageAttributesTopicOperations(t *testing.T) {
	recorder := newTopicRecorderSpy()
	observer := telemetry.NewObserver(metrics.BackendSQLite)
	observer.SetRecorder(recorder)
	store := NewObservedStorage(&fakeStorage{
		listTopicsResp:  &ListTopicsResponse{},
		createTopicResp: &CreateTopicResponse{TopicID: "TCREATED"},
		subscribeResp:   &SubscribeResponse{SubscriptionID: "SCREATED"},
		publishResp:     &PublishResponse{TopicID: "TPUBLISH"},
	}, observer)
	ctx := context.Background()

	_, err := store.ListTopics(ctx)
	td.Require(t).CmpNoError(err)
	_, err = store.CreateTopic(ctx, &CreateTopicRequest{TopicName: "created"})
	td.Require(t).CmpNoError(err)
	_, err = store.DeleteTopic(ctx, "TDELETE")
	td.Require(t).CmpNoError(err)
	_, err = store.Subscribe(ctx, "TSUBSCRIBE", &SubscribeRequest{QueueID: "Q1"})
	td.Require(t).CmpNoError(err)
	td.Require(t).CmpNoError(store.Unsubscribe(ctx, "TUNSUBSCRIBE", "S1"))
	_, err = store.Publish(ctx, "TPUBLISH", &PublishRequest{Messages: []PublishMessage{{Body: []byte("body")}}})
	td.Require(t).CmpNoError(err)

	recorder.mu.Lock()
	defer recorder.mu.Unlock()

	type operationAttribution struct {
		Backend   string
		Operation string
		Result    string
		TopicID   string
	}

	got := make([]operationAttribution, 0, len(recorder.operations))
	for _, event := range recorder.operations {
		td.Cmp(t, event.Duration >= 0, true)
		got = append(got, operationAttribution{
			Backend: event.Backend, Operation: event.Operation, Result: event.Result, TopicID: event.TopicID,
		})
	}

	td.Cmp(t, got, []operationAttribution{
		{Backend: metrics.BackendSQLite, Operation: metrics.OpListTopics, Result: metrics.ResultOK, TopicID: ""},
		{Backend: metrics.BackendSQLite, Operation: metrics.OpCreateTopic, Result: metrics.ResultOK, TopicID: "TCREATED"},
		{Backend: metrics.BackendSQLite, Operation: metrics.OpDeleteTopic, Result: metrics.ResultOK, TopicID: "TDELETE"},
		{Backend: metrics.BackendSQLite, Operation: metrics.OpSubscribe, Result: metrics.ResultOK, TopicID: "TSUBSCRIBE"},
		{Backend: metrics.BackendSQLite, Operation: metrics.OpUnsubscribe, Result: metrics.ResultOK, TopicID: "TUNSUBSCRIBE"},
		{Backend: metrics.BackendSQLite, Operation: metrics.OpPublish, Result: metrics.ResultOK, TopicID: "TPUBLISH"},
	})
}

func TestObservedStorageFailedAndNilCreateHaveNoTopicAttribution(t *testing.T) {
	recorder := newTopicRecorderSpy()
	observer := telemetry.NewObserver(metrics.BackendSQLite)
	observer.SetRecorder(recorder)
	ctx := context.Background()

	failed := NewObservedStorage(&fakeStorage{err: errors.New("storage failed")}, observer)
	_, err := failed.ListTopics(ctx)
	td.CmpError(t, err)
	_, err = failed.CreateTopic(ctx, &CreateTopicRequest{TopicName: "failed"})
	td.CmpError(t, err)

	nilSuccess := NewObservedStorage(&fakeStorage{}, observer)
	_, err = nilSuccess.CreateTopic(ctx, &CreateTopicRequest{TopicName: "nil"})
	td.CmpNoError(t, err)

	recorder.mu.Lock()
	defer recorder.mu.Unlock()

	td.Require(t).Cmp(recorder.operations, td.Len(3))
	for _, event := range recorder.operations {
		td.Cmp(t, event.TopicID, "")
	}
}

type topicRecorderSpy struct {
	*recorderSpy

	mu         sync.Mutex
	operations []telemetry.TopicOperationEvent
	publishes  []telemetry.TopicPublishEvent
}

func newTopicRecorderSpy() *topicRecorderSpy {
	return &topicRecorderSpy{recorderSpy: &recorderSpy{}}
}

func (*topicRecorderSpy) RecordTopicRequest(telemetry.TopicOperationEvent) {}

func (r *topicRecorderSpy) RecordTopicOperation(event telemetry.TopicOperationEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.operations = append(r.operations, event)
}

func (r *topicRecorderSpy) RecordTopicPublish(event telemetry.TopicPublishEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.publishes = append(r.publishes, event)
}

func (*topicRecorderSpy) RecordTopicSubscriptionCreated(string)      {}
func (*topicRecorderSpy) RecordTopicSubscriptionDeleted(string)      {}
func (*topicRecorderSpy) RecordTopicState(telemetry.TopicStateEvent) {}
func (*topicRecorderSpy) RecordTopicStateUnavailable()               {}

// Test_Observer_worksWithoutACollector checks the single-node path: with
// telemetry disabled there is no collector, and nothing may depend on one.
func Test_Observer_worksWithoutACollector(t *testing.T) {
	observer := telemetry.NewObserver(metrics.BackendSQLite)

	store := NewObservedStorage(&fakeStorage{
		sendResp: &v1.SendResponse{MessageIds: []string{"a"}},
	}, observer)

	_, err := store.Send(context.Background(), &v1.SendRequest{
		QueueId:  "QNOSINK",
		Messages: []*v1.SendMessage{{Body: []byte("x")}},
	})

	td.CmpNoError(t, err, "recording must not depend on a collector being attached")
}
