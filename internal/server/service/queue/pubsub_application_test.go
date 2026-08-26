package queue

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"testing"

	"github.com/marsolab/plainq/internal/cluster/consensus"
	"github.com/marsolab/plainq/internal/metrics"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/telemetry"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/idkit"
)

func TestPubSubApplicationInvalidDecodedRequestRecordsRequestOnly(t *testing.T) {
	recorder := &applicationRecorder{}
	observer := telemetry.NewObserver(metrics.BackendSQLite)
	observer.SetRecorder(recorder)
	storageCalls := 0
	storage := &mockStorage{createTopicFunc: func(context.Context, *CreateTopicRequest) (*CreateTopicResponse, error) {
		storageCalls++
		return nil, errors.New("storage must not be called")
	}}
	app := newPubSubApplication(NewObservedStorage(storage, observer), observer, slog.Default())

	response, err := app.createTopic(context.Background(), &CreateTopicRequest{})

	if response != nil || !errors.Is(err, pqerr.ErrInvalidInput) {
		t.Fatalf("createTopic() = %#v, %v; want nil, %v", response, err, pqerr.ErrInvalidInput)
	}
	if storageCalls != 0 {
		t.Fatalf("storage calls = %d, want 0", storageCalls)
	}
	assertApplicationOperations(t, recorder.requests, []telemetry.TopicOperationEvent{{
		Backend: metrics.BackendSQLite, Operation: metrics.OpCreateTopic, Result: metrics.ResultError,
	}})
	if len(recorder.operations) != 0 {
		t.Fatalf("storage operations = %#v, want none", recorder.operations)
	}
}

func TestPubSubApplicationSuccessfulRequestRecordsRequestAndStorage(t *testing.T) {
	topicID := idkit.XID()
	recorder := &applicationRecorder{}
	observer := telemetry.NewObserver(metrics.BackendSQLite)
	observer.SetRecorder(recorder)
	storage := &mockStorage{
		createTopicFunc: func(context.Context, *CreateTopicRequest) (*CreateTopicResponse, error) {
			return &CreateTopicResponse{TopicID: topicID}, nil
		},
		topicInventoryFunc: func(context.Context) (TopicInventory, error) {
			return TopicInventory{TopicsExist: 1, SubscriptionCounts: map[string]int64{topicID: 0}}, nil
		},
	}
	app := newPubSubApplication(NewObservedStorage(storage, observer), observer, slog.Default())

	response, err := app.createTopic(context.Background(), &CreateTopicRequest{TopicName: "events"})
	if err != nil || response == nil || response.TopicID != topicID {
		t.Fatalf("createTopic() = %#v, %v; want topic %q", response, err, topicID)
	}
	assertApplicationOperations(t, recorder.requests, []telemetry.TopicOperationEvent{{
		Backend: metrics.BackendSQLite, Operation: metrics.OpCreateTopic, Result: metrics.ResultOK, TopicID: topicID,
	}})
	assertApplicationOperations(t, recorder.operations, []telemetry.TopicOperationEvent{{
		Backend: metrics.BackendSQLite, Operation: metrics.OpCreateTopic, Result: metrics.ResultOK, TopicID: topicID,
	}})
	if len(recorder.states) != 1 || recorder.states[0].TopicsExist != 1 || recorder.states[0].Subscriptions[topicID] != 0 {
		t.Fatalf("topic states = %#v, want one exact reconciliation", recorder.states)
	}
}

func TestPubSubApplicationMalformedTopicIDRecordsSystemRequestOnly(t *testing.T) {
	recorder := &applicationRecorder{}
	storageCalls := 0
	app := newApplicationForTest(&mockStorage{deleteTopicFunc: func(context.Context, string) (*DeleteTopicResult, error) {
		storageCalls++
		return nil, nil
	}}, recorder)

	err := app.deleteTopic(context.Background(), "not-an-xid")
	if !errors.Is(err, pqerr.ErrInvalidID) {
		t.Fatalf("deleteTopic() error = %v, want %v", err, pqerr.ErrInvalidID)
	}
	if storageCalls != 0 {
		t.Fatalf("storage calls = %d, want 0", storageCalls)
	}
	assertApplicationOperations(t, recorder.requests, []telemetry.TopicOperationEvent{{
		Backend: metrics.BackendSQLite, Operation: metrics.OpDeleteTopic, Result: metrics.ResultError,
	}})
	if len(recorder.operations) != 0 {
		t.Fatalf("storage operations = %#v, want none", recorder.operations)
	}
}

func TestPubSubApplicationValidTopicInvalidPayloadRecordsTopicRequest(t *testing.T) {
	topicID := idkit.XID()
	recorder := &applicationRecorder{}
	storageCalls := 0
	app := newApplicationForTest(&mockStorage{publishFunc: func(context.Context, string, *PublishRequest) (*PublishResponse, error) {
		storageCalls++
		return nil, nil
	}}, recorder)

	response, err := app.publish(context.Background(), topicID, &PublishRequest{})
	if response != nil || !errors.Is(err, pqerr.ErrInvalidInput) {
		t.Fatalf("publish() = %#v, %v; want nil, %v", response, err, pqerr.ErrInvalidInput)
	}
	if storageCalls != 0 {
		t.Fatalf("storage calls = %d, want 0", storageCalls)
	}
	assertApplicationOperations(t, recorder.requests, []telemetry.TopicOperationEvent{{
		Backend: metrics.BackendSQLite, Operation: metrics.OpPublish, Result: metrics.ResultError, TopicID: topicID,
	}})
	if len(recorder.operations) != 0 {
		t.Fatalf("storage operations = %#v, want none", recorder.operations)
	}
}

func TestPubSubApplicationPartialPublishRecordsOutcomeOnce(t *testing.T) {
	topicID := idkit.XID()
	response := &PublishResponse{
		TopicID:        topicID,
		QueueIDs:       []string{idkit.XID()},
		MessageIDs:     []string{"message-1", "message-2"},
		DeliveredCount: 2,
	}
	partial := &PartialPublishError{Outcome: PublishOutcome{
		Response:           response,
		SelectedQueues:     3,
		FailedDeliveries:   1,
		FailedDestinations: 1,
	}, Causes: []error{pqerr.ErrUnavailable}}
	recorder := &applicationRecorder{}
	app := newApplicationForTest(&mockStorage{publishFunc: func(context.Context, string, *PublishRequest) (*PublishResponse, error) {
		return nil, partial
	}}, recorder)
	input := &PublishRequest{Messages: []PublishMessage{{Body: []byte("ab")}, {Body: []byte("cde")}}}

	got, err := app.publish(context.Background(), topicID, input)
	if got != nil || !errors.Is(err, pqerr.ErrPartialFanout) {
		t.Fatalf("publish() = %#v, %v; want nil partial error", got, err)
	}
	if want := []telemetry.TopicPublishEvent{{
		TopicID: topicID, Messages: 2, Bytes: 5, Destinations: 3, Delivered: 2, Failed: 1,
	}}; !reflect.DeepEqual(recorder.publishes, want) {
		t.Fatalf("publish events = %#v, want %#v", recorder.publishes, want)
	}
	assertApplicationOperations(t, recorder.requests, []telemetry.TopicOperationEvent{{
		Backend: metrics.BackendSQLite, Operation: metrics.OpPublish, Result: metrics.ResultError, TopicID: topicID,
	}})
	assertApplicationOperations(t, recorder.operations, []telemetry.TopicOperationEvent{{
		Backend: metrics.BackendSQLite, Operation: metrics.OpPublish, Result: metrics.ResultError, TopicID: topicID,
	}})
}

func TestPubSubApplicationCountsEveryCascadeBinding(t *testing.T) {
	topicID := idkit.XID()
	otherTopicID := idkit.XID()
	recorder := &applicationRecorder{}
	inventoryCalls := 0
	app := newApplicationForTest(&mockStorage{
		deleteTopicFunc: func(context.Context, string) (*DeleteTopicResult, error) {
			return &DeleteTopicResult{RemovedSubscriptions: []Subscription{
				{TopicID: topicID},
				{TopicID: otherTopicID},
				{TopicID: topicID},
			}}, nil
		},
		topicInventoryFunc: func(context.Context) (TopicInventory, error) {
			inventoryCalls++
			return TopicInventory{TopicsExist: 1, SubscriptionCounts: map[string]int64{otherTopicID: 0}}, nil
		},
	}, recorder)

	if err := app.deleteTopic(context.Background(), topicID); err != nil {
		t.Fatalf("deleteTopic() error = %v", err)
	}
	if want := []string{topicID, otherTopicID, topicID}; !reflect.DeepEqual(recorder.deleted, want) {
		t.Fatalf("deleted lifecycle events = %#v, want %#v", recorder.deleted, want)
	}
	if inventoryCalls != 1 || len(recorder.states) != 1 {
		t.Fatalf("inventory calls/states = %d/%d, want 1/1", inventoryCalls, len(recorder.states))
	}
}

func TestDeleteQueueRecordsSubscriptionCascadeWithoutTopicRequest(t *testing.T) {
	topicID := idkit.XID()
	otherTopicID := idkit.XID()
	recorder := &applicationRecorder{}
	inventoryCalls := 0
	app := newApplicationForTest(&mockStorage{
		deleteQueueFunc: func(context.Context, *v1.DeleteQueueRequest) (*DeleteQueueResult, error) {
			return &DeleteQueueResult{RemovedSubscriptions: []Subscription{{TopicID: topicID}, {TopicID: otherTopicID}}}, nil
		},
		topicInventoryFunc: func(context.Context) (TopicInventory, error) {
			inventoryCalls++
			return TopicInventory{TopicsExist: 2, SubscriptionCounts: map[string]int64{topicID: 0, otherTopicID: 0}}, nil
		},
	}, recorder)

	output, err := app.deleteQueue(context.Background(), &v1.DeleteQueueRequest{QueueId: validXID, Force: true})
	if err != nil || output == nil {
		t.Fatalf("deleteQueue() = %#v, %v; want result", output, err)
	}
	if len(recorder.requests) != 0 {
		t.Fatalf("topic requests = %#v, want none", recorder.requests)
	}
	if want := []string{topicID, otherTopicID}; !reflect.DeepEqual(recorder.deleted, want) {
		t.Fatalf("deleted lifecycle events = %#v, want %#v", recorder.deleted, want)
	}
	if inventoryCalls != 1 || len(recorder.states) != 1 {
		t.Fatalf("inventory calls/states = %d/%d, want 1/1", inventoryCalls, len(recorder.states))
	}
}

func TestCommitUnknownDoesNotFabricatePublishOrLifecycleEffects(t *testing.T) {
	topicID := idkit.XID()
	partial := &PartialPublishError{Outcome: PublishOutcome{
		Response:           &PublishResponse{TopicID: topicID, DeliveredCount: 1},
		SelectedQueues:     2,
		FailedDeliveries:   1,
		FailedDestinations: 1,
	}}

	t.Run("publish", func(t *testing.T) {
		recorder := &applicationRecorder{}
		app := newApplicationForTest(&mockStorage{publishFunc: func(context.Context, string, *PublishRequest) (*PublishResponse, error) {
			return partial.Outcome.Response, errors.Join(consensus.ErrCommitUnknown, partial)
		}}, recorder)

		response, err := app.publish(context.Background(), topicID, &PublishRequest{Messages: []PublishMessage{{Body: []byte("x")}}})
		if response == nil || !errors.Is(err, consensus.ErrCommitUnknown) {
			t.Fatalf("publish() = %#v, %v; want side response plus commit unknown", response, err)
		}
		if len(recorder.publishes) != 0 {
			t.Fatalf("publish events = %#v, want none", recorder.publishes)
		}
	})

	t.Run("generic publish error with response", func(t *testing.T) {
		recorder := &applicationRecorder{}
		genericErr := errors.New("connection reset")
		app := newApplicationForTest(&mockStorage{publishFunc: func(context.Context, string, *PublishRequest) (*PublishResponse, error) {
			return &PublishResponse{TopicID: topicID, DeliveredCount: 1}, genericErr
		}}, recorder)

		response, err := app.publish(context.Background(), topicID, &PublishRequest{Messages: []PublishMessage{{Body: []byte("x")}}})
		if response == nil || !errors.Is(err, genericErr) {
			t.Fatalf("publish() = %#v, %v; want side response plus generic error", response, err)
		}
		if len(recorder.publishes) != 0 {
			t.Fatalf("publish events = %#v, want none", recorder.publishes)
		}
	})

	t.Run("delete", func(t *testing.T) {
		recorder := &applicationRecorder{}
		inventoryCalls := 0
		app := newApplicationForTest(&mockStorage{
			deleteTopicFunc: func(context.Context, string) (*DeleteTopicResult, error) {
				return &DeleteTopicResult{RemovedSubscriptions: []Subscription{{TopicID: topicID}}}, consensus.ErrCommitUnknown
			},
			topicInventoryFunc: func(context.Context) (TopicInventory, error) {
				inventoryCalls++
				return TopicInventory{}, nil
			},
		}, recorder)

		err := app.deleteTopic(context.Background(), topicID)
		if !errors.Is(err, consensus.ErrCommitUnknown) {
			t.Fatalf("deleteTopic() error = %v, want commit unknown", err)
		}
		if len(recorder.deleted) != 0 || inventoryCalls != 0 || len(recorder.states) != 0 {
			t.Fatalf("effects = deleted %#v inventory %d states %#v, want none", recorder.deleted, inventoryCalls, recorder.states)
		}
	})
}

func TestPubSubApplicationValidationAttributionOrder(t *testing.T) {
	topicID := idkit.XID()
	tests := []struct {
		name      string
		operation string
		wantTopic string
		call      func(*pubSubApplication) error
	}{
		{
			name: "malformed topic is system-only", operation: metrics.OpPublish,
			call: func(app *pubSubApplication) error {
				_, err := app.publish(context.Background(), "bad", &PublishRequest{Messages: []PublishMessage{{}}})
				return err
			},
		},
		{
			name: "valid topic then invalid payload", operation: metrics.OpPublish, wantTopic: topicID,
			call: func(app *pubSubApplication) error {
				_, err := app.publish(context.Background(), topicID, &PublishRequest{})
				return err
			},
		},
		{
			name: "valid topic then invalid queue", operation: metrics.OpSubscribe, wantTopic: topicID,
			call: func(app *pubSubApplication) error {
				_, err := app.subscribe(context.Background(), topicID, &SubscribeRequest{QueueID: "bad"})
				return err
			},
		},
		{
			name: "valid topic then invalid subscription", operation: metrics.OpUnsubscribe, wantTopic: topicID,
			call: func(app *pubSubApplication) error {
				return app.unsubscribe(context.Background(), topicID, "bad")
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &applicationRecorder{}
			app := newApplicationForTest(&mockStorage{}, recorder)
			if err := tc.call(app); err == nil {
				t.Fatal("validation returned nil error")
			}
			assertApplicationOperations(t, recorder.requests, []telemetry.TopicOperationEvent{{
				Backend: metrics.BackendSQLite, Operation: tc.operation, Result: metrics.ResultError, TopicID: tc.wantTopic,
			}})
			if len(recorder.operations) != 0 {
				t.Fatalf("storage operations = %#v, want none", recorder.operations)
			}
		})
	}
}

func TestPubSubApplicationPreservesValidatedQueueIDCasing(t *testing.T) {
	topicID := idkit.XID()
	queueID := "C5S8B4P9E8RG5U5FGQ10"
	recorder := &applicationRecorder{}
	app := newApplicationForTest(&mockStorage{
		subscribeFunc: func(_ context.Context, _ string, input *SubscribeRequest) (*SubscribeResponse, error) {
			if input.QueueID != queueID {
				t.Fatalf("storage queue ID = %q, want original %q", input.QueueID, queueID)
			}
			return &SubscribeResponse{SubscriptionID: idkit.XID()}, nil
		},
	}, recorder)

	if _, err := app.subscribe(context.Background(), topicID, &SubscribeRequest{QueueID: queueID}); err != nil {
		t.Fatalf("subscribe() error = %v", err)
	}
}

func TestSubscribeAndDeleteQueueNormalizeMalformedQueueID(t *testing.T) {
	topicID := idkit.XID()
	recorder := &applicationRecorder{}
	app := newApplicationForTest(&mockStorage{}, recorder)

	if _, err := app.subscribe(context.Background(), topicID, &SubscribeRequest{QueueID: "bad"}); !errors.Is(err, pqerr.ErrInvalidID) {
		t.Fatalf("subscribe() error = %v, want %v", err, pqerr.ErrInvalidID)
	}
	if _, err := app.deleteQueue(context.Background(), &v1.DeleteQueueRequest{QueueId: "bad"}); !errors.Is(err, pqerr.ErrInvalidID) {
		t.Fatalf("deleteQueue() error = %v, want %v", err, pqerr.ErrInvalidID)
	}
	assertApplicationOperations(t, recorder.requests, []telemetry.TopicOperationEvent{{
		Backend: metrics.BackendSQLite, Operation: metrics.OpSubscribe, Result: metrics.ResultError, TopicID: topicID,
	}})
	if len(recorder.operations) != 0 {
		t.Fatalf("storage operations = %#v, want none", recorder.operations)
	}
}

func TestPubSubApplicationReconciliationFailureIsNonfatal(t *testing.T) {
	topicID := idkit.XID()
	recorder := &applicationRecorder{}
	app := newApplicationForTest(&mockStorage{
		subscribeFunc: func(context.Context, string, *SubscribeRequest) (*SubscribeResponse, error) {
			return &SubscribeResponse{SubscriptionID: idkit.XID()}, nil
		},
		topicInventoryFunc: func(context.Context) (TopicInventory, error) {
			return TopicInventory{}, errors.New("inventory unavailable")
		},
	}, recorder)

	response, err := app.subscribe(context.Background(), topicID, &SubscribeRequest{QueueID: validXID})
	if err != nil || response == nil {
		t.Fatalf("subscribe() = %#v, %v; want committed success", response, err)
	}
	if want := []string{topicID}; !reflect.DeepEqual(recorder.created, want) {
		t.Fatalf("created lifecycle = %#v, want %#v", recorder.created, want)
	}
	if recorder.unavailable != 1 || len(recorder.states) != 0 {
		t.Fatalf("unavailable/states = %d/%#v, want 1/none", recorder.unavailable, recorder.states)
	}
}

func TestServiceRejectsNilObserver(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewService() accepted a nil observer")
		}
	}()

	NewService(nil, slog.Default(), &mockStorage{}, nil)
}

func TestPublishOutcomeHelpers(t *testing.T) {
	response := &PublishResponse{QueueIDs: []string{"q1", "q2"}, DeliveredCount: 2}
	partial := &PartialPublishError{Outcome: PublishOutcome{SelectedQueues: 3, FailedDeliveries: 1}}
	tests := []struct {
		name                            string
		output                          *PublishResponse
		err                             error
		destinations, delivered, failed uint64
	}{
		{name: "success", output: response, destinations: 2, delivered: 2},
		{name: "zero subscribers", output: &PublishResponse{}},
		{name: "partial", output: response, err: partial, destinations: 3, delivered: 2, failed: 1},
		{name: "missing topic", err: pqerr.ErrNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := selectedDestinations(tc.output, tc.err); got != tc.destinations {
				t.Fatalf("selectedDestinations() = %d, want %d", got, tc.destinations)
			}
			if got := deliveredCount(tc.output); got != tc.delivered {
				t.Fatalf("deliveredCount() = %d, want %d", got, tc.delivered)
			}
			if got := failedDeliveries(tc.err); got != tc.failed {
				t.Fatalf("failedDeliveries() = %d, want %d", got, tc.failed)
			}
		})
	}
}

func newApplicationForTest(storage Storage, recorder *applicationRecorder) *pubSubApplication {
	observer := telemetry.NewObserver(metrics.BackendSQLite)
	observer.SetRecorder(recorder)

	return newPubSubApplication(NewObservedStorage(storage, observer), observer, slog.Default())
}

func assertApplicationOperations(t *testing.T, got, want []telemetry.TopicOperationEvent) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("operations = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i].Backend != want[i].Backend || got[i].Operation != want[i].Operation || got[i].Result != want[i].Result || got[i].TopicID != want[i].TopicID {
			t.Fatalf("operation[%d] = %#v, want %#v", i, got[i], want[i])
		}
		if got[i].Duration <= 0 {
			t.Fatalf("operation[%d] duration = %v, want positive", i, got[i].Duration)
		}
	}
}

type applicationRecorder struct {
	requests    []telemetry.TopicOperationEvent
	operations  []telemetry.TopicOperationEvent
	publishes   []telemetry.TopicPublishEvent
	created     []string
	deleted     []string
	states      []telemetry.TopicStateEvent
	unavailable int
}

func (*applicationRecorder) RecordSend(string, uint64, uint64)  {}
func (*applicationRecorder) RecordReceive(string, uint64, bool) {}
func (*applicationRecorder) RecordDelete(string, uint64)        {}
func (*applicationRecorder) RecordRedelivery(string, uint64)    {}
func (*applicationRecorder) RecordDrop(string, uint64)          {}
func (*applicationRecorder) RecordDLQ(string, uint64)           {}
func (*applicationRecorder) IncrementQueues()                   {}
func (*applicationRecorder) DecrementQueues()                   {}
func (*applicationRecorder) SetQueuesExist(int64)               {}
func (r *applicationRecorder) RecordTopicRequest(event telemetry.TopicOperationEvent) {
	r.requests = append(r.requests, event)
}
func (r *applicationRecorder) RecordTopicOperation(event telemetry.TopicOperationEvent) {
	r.operations = append(r.operations, event)
}
func (r *applicationRecorder) RecordTopicPublish(event telemetry.TopicPublishEvent) {
	r.publishes = append(r.publishes, event)
}
func (r *applicationRecorder) RecordTopicSubscriptionCreated(topicID string) {
	r.created = append(r.created, topicID)
}
func (r *applicationRecorder) RecordTopicSubscriptionDeleted(topicID string) {
	r.deleted = append(r.deleted, topicID)
}
func (r *applicationRecorder) RecordTopicState(event telemetry.TopicStateEvent) {
	r.states = append(r.states, event)
}
func (r *applicationRecorder) RecordTopicStateUnavailable() { r.unavailable++ }

var _ telemetry.Recorder = (*applicationRecorder)(nil)
var _ telemetry.TopicRecorder = (*applicationRecorder)(nil)
