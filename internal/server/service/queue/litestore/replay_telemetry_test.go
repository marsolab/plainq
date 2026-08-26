package litestore

import (
	"bytes"
	"context"
	"strings"
	"testing"

	vm "github.com/VictoriaMetrics/metrics"
	"github.com/marsolab/plainq/internal/metrics"
	"github.com/marsolab/plainq/internal/server/principal"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	queueservice "github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/server/service/telemetry"
	"github.com/marsolab/servekit/logkit"
	"google.golang.org/grpc/metadata"
)

func TestQueuePolicyReplayDoesNotRepeatCommittedPubSubTelemetry(t *testing.T) {
	baseCtx := principal.With(context.Background(), principal.Principal{
		Kind: principal.KindSystem, ID: principal.LegacyPrincipalID, TenantID: principal.LegacyTenantID,
	})
	conn := newMigratedConn(t)
	store := newTestStorage(t, conn)
	recorder := &replayTelemetryRecorder{}
	observer := telemetry.NewObserver(metrics.BackendSQLite)
	observer.SetRecorder(recorder)
	service := queueservice.NewService(
		nil,
		logkit.NewNop(),
		queueservice.NewObservedStorage(store, observer),
		observer,
	)

	createdQueue, err := store.CreateQueue(baseCtx, &v1.CreateQueueRequest{QueueName: "replay-telemetry"})
	if err != nil {
		t.Fatalf("create replay telemetry queue: %v", err)
	}

	createCtx := replayTelemetryContext(baseCtx, "create-topic")
	createdTopic, err := service.CreateTopic(createCtx, &v1.CreateTopicRequest{TopicName: "replay-telemetry"})
	if err != nil {
		t.Fatalf("create replay telemetry topic: %v", err)
	}
	replayedTopic, err := service.CreateTopic(createCtx, &v1.CreateTopicRequest{TopicName: "replay-telemetry"})
	if err != nil {
		t.Fatalf("replay topic creation: %v", err)
	}
	if replayedTopic.GetTopicId() != createdTopic.GetTopicId() {
		t.Fatalf("replayed topic ID = %q, want %q", replayedTopic.GetTopicId(), createdTopic.GetTopicId())
	}

	subscribeCtx := replayTelemetryContext(baseCtx, "subscribe")
	subscribeRequest := &v1.SubscribeRequest{
		TopicId: createdTopic.GetTopicId(), QueueId: createdQueue.GetQueueId(),
	}
	createdSubscription, err := service.Subscribe(subscribeCtx, subscribeRequest)
	if err != nil {
		t.Fatalf("subscribe replay telemetry queue: %v", err)
	}
	replayedSubscription, err := service.Subscribe(subscribeCtx, subscribeRequest)
	if err != nil {
		t.Fatalf("replay subscription: %v", err)
	}
	if replayedSubscription.GetSubscriptionId() != createdSubscription.GetSubscriptionId() {
		t.Fatalf(
			"replayed subscription ID = %q, want %q",
			replayedSubscription.GetSubscriptionId(),
			createdSubscription.GetSubscriptionId(),
		)
	}

	publishCtx := replayTelemetryContext(baseCtx, "publish")
	publishRequest := &v1.PublishRequest{
		TopicId: createdTopic.GetTopicId(), Messages: []*v1.PublishMessage{{Body: []byte("once")}},
	}
	firstPublish, err := service.Publish(publishCtx, publishRequest)
	if err != nil {
		t.Fatalf("publish replay telemetry message: %v", err)
	}
	replayedPublish, err := service.Publish(publishCtx, publishRequest)
	if err != nil {
		t.Fatalf("replay publish: %v", err)
	}
	if strings.Join(replayedPublish.GetMessageIds(), ",") != strings.Join(firstPublish.GetMessageIds(), ",") {
		t.Fatalf("replayed message IDs = %v, want %v", replayedPublish.GetMessageIds(), firstPublish.GetMessageIds())
	}

	conflictingPublish := &v1.PublishRequest{
		TopicId: createdTopic.GetTopicId(), Messages: []*v1.PublishMessage{{Body: []byte("different")}},
	}
	if _, err := service.Publish(publishCtx, conflictingPublish); err == nil {
		t.Fatal("conflicting replay publish error = nil")
	}

	if got := len(recorder.publishes); got != 1 {
		t.Fatalf("committed publish events = %d, want 1", got)
	}
	published := recorder.publishes[0]
	if published.Messages != 1 || published.Bytes != 4 || published.Destinations != 1 ||
		published.Delivered != 1 || published.Failed != 0 {
		t.Fatalf("committed publish event = %#v, want one four-byte delivery", published)
	}
	if got := len(recorder.subscriptionsCreated); got != 1 {
		t.Fatalf("committed subscription-created events = %d, want 1", got)
	}
	if got := len(recorder.states); got != 2 {
		t.Fatalf("post-commit topic reconciliations = %d, want 2", got)
	}

	assertReplayTelemetryOperations(t, recorder.requests, metrics.OpCreateTopic, 2, 0)
	assertReplayTelemetryOperations(t, recorder.operations, metrics.OpCreateTopic, 2, 0)
	assertReplayTopicAttribution(t, recorder.requests, metrics.OpCreateTopic, createdTopic.GetTopicId())
	assertReplayTopicAttribution(t, recorder.operations, metrics.OpCreateTopic, createdTopic.GetTopicId())
	assertReplayTelemetryOperations(t, recorder.requests, metrics.OpSubscribe, 2, 0)
	assertReplayTelemetryOperations(t, recorder.operations, metrics.OpSubscribe, 2, 0)
	assertReplayTelemetryOperations(t, recorder.requests, metrics.OpPublish, 3, 1)
	assertReplayTelemetryOperations(t, recorder.operations, metrics.OpPublish, 3, 1)

	var exposition bytes.Buffer
	vm.WritePrometheus(&exposition, false)
	for _, sample := range []string{
		`plainq_topic_messages_published_total{topic="` + createdTopic.GetTopicId() + `"} 1`,
		`plainq_topic_published_bytes_total{topic="` + createdTopic.GetTopicId() + `"} 4`,
		`plainq_topic_deliveries_total{topic="` + createdTopic.GetTopicId() + `"} 1`,
		`plainq_topic_fanout_count{topic="` + createdTopic.GetTopicId() + `"} 1`,
		`plainq_topic_subscriptions_created_total{topic="` + createdTopic.GetTopicId() + `"} 1`,
	} {
		if !strings.Contains(exposition.String(), sample) {
			t.Fatalf("Prometheus exposition does not contain %q", sample)
		}
	}
}

func replayTelemetryContext(ctx context.Context, key string) context.Context {
	return metadata.NewIncomingContext(ctx, metadata.Pairs("idempotency-key", key))
}

func assertReplayTelemetryOperations(
	t *testing.T,
	events []telemetry.TopicOperationEvent,
	operation string,
	wantTotal, wantErrors int,
) {
	t.Helper()

	var total, failures int
	for _, event := range events {
		if event.Operation != operation {
			continue
		}

		total++
		if event.Result == metrics.ResultError {
			failures++
		}
	}
	if total != wantTotal || failures != wantErrors {
		t.Fatalf("%s events/errors = %d/%d, want %d/%d", operation, total, failures, wantTotal, wantErrors)
	}
}

func assertReplayTopicAttribution(
	t *testing.T,
	events []telemetry.TopicOperationEvent,
	operation, wantTopicID string,
) {
	t.Helper()

	for _, event := range events {
		if event.Operation == operation && event.TopicID != wantTopicID {
			t.Fatalf("%s topic attribution = %q, want %q", operation, event.TopicID, wantTopicID)
		}
	}
}

type replayTelemetryRecorder struct {
	requests             []telemetry.TopicOperationEvent
	operations           []telemetry.TopicOperationEvent
	publishes            []telemetry.TopicPublishEvent
	subscriptionsCreated []string
	subscriptionsDeleted []string
	states               []telemetry.TopicStateEvent
}

func (*replayTelemetryRecorder) RecordSend(string, uint64, uint64)  {}
func (*replayTelemetryRecorder) RecordReceive(string, uint64, bool) {}
func (*replayTelemetryRecorder) RecordDelete(string, uint64)        {}
func (*replayTelemetryRecorder) RecordRedelivery(string, uint64)    {}
func (*replayTelemetryRecorder) RecordDrop(string, uint64)          {}
func (*replayTelemetryRecorder) RecordDLQ(string, uint64)           {}
func (*replayTelemetryRecorder) IncrementQueues()                   {}
func (*replayTelemetryRecorder) DecrementQueues()                   {}
func (*replayTelemetryRecorder) SetQueuesExist(int64)               {}

func (r *replayTelemetryRecorder) RecordTopicRequest(event telemetry.TopicOperationEvent) {
	r.requests = append(r.requests, event)
}

func (r *replayTelemetryRecorder) RecordTopicOperation(event telemetry.TopicOperationEvent) {
	r.operations = append(r.operations, event)
}

func (r *replayTelemetryRecorder) RecordTopicPublish(event telemetry.TopicPublishEvent) {
	r.publishes = append(r.publishes, event)
}

func (r *replayTelemetryRecorder) RecordTopicSubscriptionCreated(topicID string) {
	r.subscriptionsCreated = append(r.subscriptionsCreated, topicID)
}

func (r *replayTelemetryRecorder) RecordTopicSubscriptionDeleted(topicID string) {
	r.subscriptionsDeleted = append(r.subscriptionsDeleted, topicID)
}

func (r *replayTelemetryRecorder) RecordTopicState(event telemetry.TopicStateEvent) {
	r.states = append(r.states, event)
}

func (*replayTelemetryRecorder) RecordTopicStateUnavailable() {}

var _ telemetry.Recorder = (*replayTelemetryRecorder)(nil)
var _ telemetry.TopicRecorder = (*replayTelemetryRecorder)(nil)
