package telemetry

import (
	"bytes"
	"errors"
	"math"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	vm "github.com/VictoriaMetrics/metrics"
	"github.com/marsolab/plainq/internal/metrics"
	"github.com/maxatome/go-testdeep/td"
)

type queueRecorderSpy struct {
	mu sync.Mutex

	sent          uint64
	queuesDelta   int
	queuesExact   int64
	queueSetCalls int
}

func (r *queueRecorderSpy) RecordSend(_ string, count, _ uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.sent += count
}

func (*queueRecorderSpy) RecordReceive(string, uint64, bool) {}
func (*queueRecorderSpy) RecordDelete(string, uint64)        {}
func (*queueRecorderSpy) RecordRedelivery(string, uint64)    {}
func (*queueRecorderSpy) RecordDrop(string, uint64)          {}
func (*queueRecorderSpy) RecordDLQ(string, uint64)           {}

func (r *queueRecorderSpy) IncrementQueues() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.queuesDelta++
}

func (r *queueRecorderSpy) DecrementQueues() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.queuesDelta--
}

func (r *queueRecorderSpy) SetQueuesExist(count int64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.queuesExact = count
	r.queueSetCalls++
}

type topicRecorderSpy struct {
	*queueRecorderSpy

	mu sync.Mutex

	requests             []TopicOperationEvent
	operations           []TopicOperationEvent
	publishes            []TopicPublishEvent
	subscriptionsCreated []string
	subscriptionsDeleted []string
	states               []TopicStateEvent
	unavailable          int
	mutateState          func(TopicStateEvent)
}

func newTopicRecorderSpy() *topicRecorderSpy {
	return &topicRecorderSpy{queueRecorderSpy: &queueRecorderSpy{}}
}

func (r *topicRecorderSpy) RecordTopicRequest(event TopicOperationEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.requests = append(r.requests, event)
}

func (r *topicRecorderSpy) RecordTopicOperation(event TopicOperationEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.operations = append(r.operations, event)
}

func (r *topicRecorderSpy) RecordTopicPublish(event TopicPublishEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.publishes = append(r.publishes, event)
}

func (r *topicRecorderSpy) RecordTopicSubscriptionCreated(topicID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.subscriptionsCreated = append(r.subscriptionsCreated, topicID)
}

func (r *topicRecorderSpy) RecordTopicSubscriptionDeleted(topicID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.subscriptionsDeleted = append(r.subscriptionsDeleted, topicID)
}

func (r *topicRecorderSpy) RecordTopicState(event TopicStateEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.states = append(r.states, TopicStateEvent{
		TopicsExist:   event.TopicsExist,
		Subscriptions: copySubscriptions(event.Subscriptions),
	})

	if r.mutateState != nil {
		r.mutateState(event)
	}
}

func (r *topicRecorderSpy) RecordTopicStateUnavailable() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.unavailable++
}

func TestObserverFansTopicEventsToBothSinks(t *testing.T) {
	const topicID = "TOBSERVERFANOUT"

	observer := NewObserver(metrics.BackendTurso)
	recorder := newTopicRecorderSpy()
	observer.SetRecorder(recorder)

	requestCounter := `plainq_topic_requests_total{backend="turso",operation="publish",result="ok"}`
	requestDuration := `plainq_topic_request_duration_seconds_sum{backend="turso",operation="publish"}`
	operationCounter := `plainq_topic_operations_total{backend="turso",operation="publish",result="error"}`
	operationDuration := `plainq_topic_operation_duration_seconds_sum{backend="turso",operation="publish"}`
	beforeRequest := prometheusValue(requestCounter)
	beforeRequestDuration := prometheusValue(requestDuration)
	beforeOperation := prometheusValue(operationCounter)
	beforeOperationDuration := prometheusValue(operationDuration)

	observer.TopicRequest(metrics.OpPublish, topicID, time.Now().Add(-5*time.Millisecond), nil)
	observer.TopicOperation(metrics.OpPublish, topicID, time.Now().Add(-7*time.Millisecond), errors.New("write failed"))
	observer.Published(TopicPublishEvent{
		TopicID:      topicID,
		Messages:     2,
		Bytes:        10,
		Destinations: 3,
		Delivered:    4,
		Failed:       2,
	})
	observer.TopicSubscriptionCreated(topicID)
	observer.TopicSubscriptionDeleted(topicID)

	recorder.mu.Lock()
	td.Require(t).Cmp(recorder.requests, td.Len(1))
	td.Require(t).Cmp(recorder.operations, td.Len(1))
	td.Require(t).Cmp(recorder.publishes, td.Len(1))
	requestEvent := recorder.requests[0]
	operationEvent := recorder.operations[0]
	td.Cmp(t, requestEvent.Backend, metrics.BackendTurso)
	td.Cmp(t, requestEvent.Operation, metrics.OpPublish)
	td.Cmp(t, requestEvent.Result, metrics.ResultOK)
	td.Cmp(t, requestEvent.TopicID, topicID)
	td.Cmp(t, operationEvent.Result, metrics.ResultError)
	td.Cmp(t, recorder.publishes[0].Destinations, uint64(3))
	td.Cmp(t, recorder.subscriptionsCreated, []string{topicID})
	td.Cmp(t, recorder.subscriptionsDeleted, []string{topicID})
	recorder.mu.Unlock()

	td.Cmp(t, prometheusValue(requestCounter), beforeRequest+1)
	td.Cmp(t, prometheusValue(operationCounter), beforeOperation+1)
	td.Cmp(t, durationDelta(beforeRequestDuration, prometheusValue(requestDuration)), requestEvent.Duration,
		"Prometheus and the recorder must receive the same elapsed request duration",
	)
	td.Cmp(t, durationDelta(beforeOperationDuration, prometheusValue(operationDuration)), operationEvent.Duration,
		"Prometheus and the recorder must receive the same elapsed storage duration",
	)
}

func TestObserverReplaysKnownTopicStateWhenRecorderAttaches(t *testing.T) {
	observer := NewObserver(metrics.BackendSQLite)
	observer.ReconcileTopicState(TopicStateEvent{
		TopicsExist:   2,
		Subscriptions: map[string]int64{"T1": 1, "T2": 0},
	})

	recorder := newTopicRecorderSpy()
	observer.SetRecorder(recorder)

	recorder.mu.Lock()
	defer recorder.mu.Unlock()

	td.Cmp(t, recorder.states, []TopicStateEvent{{
		TopicsExist:   2,
		Subscriptions: map[string]int64{"T1": 1, "T2": 0},
	}})
}

func TestObserverDoesNotReplayUnknownTopicState(t *testing.T) {
	observer := NewObserver(metrics.BackendSQLite)
	recorder := newTopicRecorderSpy()

	observer.SetRecorder(recorder)

	recorder.mu.Lock()
	defer recorder.mu.Unlock()

	td.Cmp(t, recorder.states, []TopicStateEvent(nil))
	td.Cmp(t, recorder.unavailable, 0)
}

func TestObserverAcceptsQueueOnlyRecorder(t *testing.T) {
	observer := NewObserver(metrics.BackendSQLite)
	recorder := &queueRecorderSpy{}
	observer.SetRecorder(recorder)

	observer.TopicRequest(metrics.OpListTopics, "", time.Now(), nil)
	observer.TopicOperation(metrics.OpListTopics, "", time.Now(), nil)
	observer.Published(TopicPublishEvent{TopicID: "TQUEUEONLY", Messages: 1})
	observer.TopicSubscriptionCreated("TQUEUEONLY")
	observer.TopicSubscriptionDeleted("TQUEUEONLY")
	observer.ReconcileTopicState(TopicStateEvent{TopicsExist: 1, Subscriptions: map[string]int64{"TQUEUEONLY": 0}})
	observer.TopicStateUnavailable()
	observer.Sent("QQUEUEONLY", 1, 1)

	recorder.mu.Lock()
	defer recorder.mu.Unlock()

	td.Cmp(t, recorder.sent, uint64(1))
}

func TestObserverDoesNotReplayUnknownQueueState(t *testing.T) {
	observer := NewObserver(metrics.BackendSQLite)

	// An incremental change does not make the count authoritative.
	observer.QueueCreated()
	recorder := &queueRecorderSpy{}
	observer.SetRecorder(recorder)

	recorder.mu.Lock()
	td.Cmp(t, recorder.queueSetCalls, 0)
	recorder.mu.Unlock()

	observer.SetQueues(7)
	replay := &queueRecorderSpy{}
	observer.SetRecorder(replay)

	replay.mu.Lock()
	defer replay.mu.Unlock()

	td.Cmp(t, replay.queueSetCalls, 1)
	td.Cmp(t, replay.queuesExact, int64(7))
}

func TestObserverInvalidatesTopicStateWithoutChangingLifecycle(t *testing.T) {
	const topicID = "TOBSERVERINVALIDATE"

	observer := NewObserver(metrics.BackendSQLite)
	recorder := newTopicRecorderSpy()
	observer.SetRecorder(recorder)
	observer.ReconcileTopicState(TopicStateEvent{
		TopicsExist:   1,
		Subscriptions: map[string]int64{topicID: 4},
	})
	beforeGauge := prometheusValue(`plainq_topic_subscriptions{topic="` + topicID + `"}`)

	observer.TopicStateUnavailable()

	recorder.mu.Lock()
	defer recorder.mu.Unlock()

	td.Cmp(t, recorder.unavailable, 1)
	td.Cmp(t, recorder.subscriptionsCreated, []string(nil))
	td.Cmp(t, recorder.subscriptionsDeleted, []string(nil))
	td.Cmp(t, prometheusValue(`plainq_topic_subscriptions{topic="`+topicID+`"}`), beforeGauge,
		"unavailability must not turn the last exact value into zero",
	)
}

func TestObserverCopiesReconciledAndReplayedTopicMaps(t *testing.T) {
	observer := NewObserver(metrics.BackendSQLite)
	input := map[string]int64{"TCOPY": 2}
	observer.ReconcileTopicState(TopicStateEvent{TopicsExist: 1, Subscriptions: input})

	input["TCOPY"] = 99
	input["TADDED"] = 1

	mutating := newTopicRecorderSpy()
	mutating.mutateState = func(event TopicStateEvent) {
		event.Subscriptions["TCOPY"] = 77
		event.Subscriptions["TRECORDER"] = 1
	}
	observer.SetRecorder(mutating)

	replay := newTopicRecorderSpy()
	observer.SetRecorder(replay)

	replay.mu.Lock()
	defer replay.mu.Unlock()

	td.Cmp(t, replay.states, []TopicStateEvent{{
		TopicsExist:   1,
		Subscriptions: map[string]int64{"TCOPY": 2},
	}})
}

func TestObserverRecorderAttachAndReplayIsLinearizedWithEvents(t *testing.T) {
	observer := NewObserver(metrics.BackendSQLite)
	observer.ReconcileTopicState(TopicStateEvent{
		TopicsExist:   1,
		Subscriptions: map[string]int64{"TLINEAR": 1},
	})

	old := newTopicRecorderSpy()
	observer.SetRecorder(old)

	attached := make(chan struct{})
	releaseReplay := make(chan struct{})
	published := make(chan struct{})
	next := &orderedTopicRecorder{
		queueRecorderSpy: &queueRecorderSpy{},
		attached:         attached,
		releaseReplay:    releaseReplay,
		published:        published,
	}

	setDone := make(chan struct{})
	go func() {
		observer.SetRecorder(next)
		close(setDone)
	}()

	select {
	case <-attached:
	case <-time.After(time.Second):
		t.Fatal("new recorder did not begin state replay")
	}

	publishDone := make(chan struct{})
	go func() {
		observer.Published(TopicPublishEvent{TopicID: "TLINEAR", Messages: 1})
		close(publishDone)
	}()

	select {
	case <-published:
		t.Fatal("publish overtook the new recorder's state replay")
	case <-time.After(25 * time.Millisecond):
	}

	close(releaseReplay)

	for name, done := range map[string]<-chan struct{}{"attach": setDone, "publish": publishDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("%s did not finish", name)
		}
	}

	next.mu.Lock()
	td.Cmp(t, next.order, []string{"state", "publish"})
	next.mu.Unlock()

	old.mu.Lock()
	td.Cmp(t, old.publishes, []TopicPublishEvent(nil),
		"no post-swap event may reach the old recorder",
	)
	old.mu.Unlock()
}

func TestObserverUnavailableRetainsPriorMapForLaterRemoval(t *testing.T) {
	const (
		kept    = "TOBSERVERKEPT"
		removed = "TOBSERVERREMOVED"
	)

	observer := NewObserver(metrics.BackendSQLite)
	observer.ReconcileTopicState(TopicStateEvent{
		TopicsExist:   2,
		Subscriptions: map[string]int64{kept: 1, removed: 3},
	})
	observer.TopicStateUnavailable()

	// The retained map is unknown and therefore must not be replayed.
	recorder := newTopicRecorderSpy()
	observer.SetRecorder(recorder)

	recorder.mu.Lock()
	td.Cmp(t, recorder.states, []TopicStateEvent(nil))
	recorder.mu.Unlock()

	observer.ReconcileTopicState(TopicStateEvent{
		TopicsExist:   1,
		Subscriptions: map[string]int64{kept: 2},
	})

	recorder.mu.Lock()
	td.Cmp(t, recorder.states, []TopicStateEvent{{
		TopicsExist:   1,
		Subscriptions: map[string]int64{kept: 2},
	}})
	recorder.mu.Unlock()

	td.Cmp(t, prometheusValue(`plainq_topic_subscriptions{topic="`+removed+`"}`), float64(0),
		"the retained prior map identifies topics that need a terminal zero",
	)
}

type orderedTopicRecorder struct {
	*queueRecorderSpy

	mu sync.Mutex

	order         []string
	attached      chan<- struct{}
	releaseReplay <-chan struct{}
	published     chan<- struct{}
}

func (*orderedTopicRecorder) RecordTopicRequest(TopicOperationEvent)   {}
func (*orderedTopicRecorder) RecordTopicOperation(TopicOperationEvent) {}

func (r *orderedTopicRecorder) RecordTopicPublish(TopicPublishEvent) {
	r.mu.Lock()
	r.order = append(r.order, "publish")
	r.mu.Unlock()

	close(r.published)
}

func (*orderedTopicRecorder) RecordTopicSubscriptionCreated(string) {}
func (*orderedTopicRecorder) RecordTopicSubscriptionDeleted(string) {}

func (r *orderedTopicRecorder) RecordTopicState(TopicStateEvent) {
	r.mu.Lock()
	r.order = append(r.order, "state")
	r.mu.Unlock()

	close(r.attached)
	<-r.releaseReplay
}

func (*orderedTopicRecorder) RecordTopicStateUnavailable() {}

func prometheusValue(series string) float64 {
	var buf bytes.Buffer

	vm.WritePrometheus(&buf, false)

	for line := range strings.SplitSeq(buf.String(), "\n") {
		if !strings.HasPrefix(line, series+" ") {
			continue
		}

		value, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(line, series)), 64)
		if err != nil {
			panic("parse Prometheus value for " + series + ": " + err.Error())
		}

		return value
	}

	return 0
}

func copySubscriptions(input map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(input))
	for topicID, count := range input {
		out[topicID] = count
	}

	return out
}

func durationDelta(before, after float64) time.Duration {
	return time.Duration(math.Round((after - before) * float64(time.Second)))
}
