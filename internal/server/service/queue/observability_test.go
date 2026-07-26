package queue

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	vm "github.com/VictoriaMetrics/metrics"
	"github.com/marsolab/plainq/internal/metrics"
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

	sendResp    *v1.SendResponse
	receiveResp *v1.ReceiveResponse
	deleteResp  *v1.DeleteResponse
	publishResp *PublishResponse
	err         error
}

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

// Test_ObservedStorage_recordsUndeliveredFanout proves the one thing a
// publish response cannot say for itself: a publish reports success once it is
// accepted, so a subscriber that could not be written to leaves no other trace.
func Test_ObservedStorage_recordsUndeliveredFanout(t *testing.T) {
	observer := telemetry.NewObserver(metrics.BackendSQLite)

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

	// Three subscribers, one message, two deliveries: one delivery is missing
	// and only the metric says so.
	out := scrapeMetrics()

	td.Cmp(t, strings.Contains(out, `plainq_topic_deliveries_total{topic="T1"} 2`), true)
	td.Cmp(t, strings.Contains(out, `plainq_topic_delivery_failures_total{topic="T1"} 1`), true)
}

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
