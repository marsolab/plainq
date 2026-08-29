package main

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	hraft "github.com/hashicorp/raft"
	"github.com/marsolab/plainq/internal/cluster"
	"github.com/marsolab/plainq/internal/cluster/command"
	clusterfsm "github.com/marsolab/plainq/internal/cluster/fsm"
	"github.com/marsolab/plainq/internal/metrics"
	"github.com/marsolab/plainq/internal/server/config"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/server/service/telemetry"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/marsolab/servekit/logkit"
)

func TestTursoUsesTursoTelemetryBackend(t *testing.T) {
	if got := telemetryBackend(storageDriverTurso); got != metrics.BackendTurso {
		t.Fatalf("telemetryBackend(turso) = %q, want %q", got, metrics.BackendTurso)
	}
	wiring := newQueueTelemetryWiring(storageDriverTurso, false)
	if wiring.local.Backend() != metrics.BackendTurso || wiring.logical != wiring.local {
		t.Fatalf("standalone observers = %q/%p/%p, want one Turso observer",
			wiring.local.Backend(), wiring.local, wiring.logical)
	}
}

func TestClusterIngressUsesClusterBackend(t *testing.T) {
	wiring := newQueueTelemetryWiring(storageDriverSQLite, true)
	if wiring.local.Backend() != metrics.BackendSQLite {
		t.Fatalf("local backend = %q, want sqlite", wiring.local.Backend())
	}
	if wiring.logical == wiring.local || wiring.logical.Backend() != metrics.BackendCluster {
		t.Fatalf("logical observer = %p backend %q, want distinct cluster observer",
			wiring.logical, wiring.logical.Backend())
	}
	captureCalled := false
	if err := wiring.logical.CaptureTopicState(func() (telemetry.TopicStateEvent, error) {
		captureCalled = true
		return telemetry.TopicStateEvent{}, nil
	}); err != nil {
		t.Fatalf("logical CaptureTopicState() = %v", err)
	}
	if captureCalled {
		t.Fatal("cluster ingress observer captured exact topic state")
	}
}

func TestSQLiteJournalModeParsingIsCaseInsensitive(t *testing.T) {
	for input, want := range map[string]litekit.JournalMode{
		"delete":   litekit.Delete,
		"Truncate": litekit.Truncate,
		"PERSIST":  litekit.Persist,
		"memory":   litekit.Memory,
		"WaL":      litekit.WAL,
		"OFF":      litekit.Off,
	} {
		t.Run(input, func(t *testing.T) {
			got, err := sqliteJournalMode(input)
			if err != nil || got != want {
				t.Fatalf("sqliteJournalMode(%q) = %v, %v; want %v, nil", input, got, err, want)
			}
		})
	}
	if _, err := sqliteJournalMode("not-a-mode"); err == nil {
		t.Fatal("sqliteJournalMode(invalid) succeeded")
	}
}

type inventoryStorage struct {
	queue.Storage
	inventory queue.TopicInventory
	err       error
}

type blockingInventoryStorage struct {
	queue.Storage
	started chan struct{}
	release chan struct{}
}

func (s *blockingInventoryStorage) TopicInventory(context.Context) (queue.TopicInventory, error) {
	close(s.started)
	<-s.release
	return queue.TopicInventory{
		TopicsExist:        1,
		SubscriptionCounts: map[string]int64{"startup-old": 1},
	}, nil
}

func (s *inventoryStorage) TopicInventory(context.Context) (queue.TopicInventory, error) {
	return s.inventory, s.err
}

type inventoryRecorder struct {
	state                *telemetry.TopicStateEvent
	unavailable          int
	topicRequests        int
	topicOperations      int
	topicPublishes       int
	subscriptionsCreated int
	subscriptionsDeleted int
}

func (*inventoryRecorder) RecordSend(string, uint64, uint64)  {}
func (*inventoryRecorder) RecordReceive(string, uint64, bool) {}
func (*inventoryRecorder) RecordDelete(string, uint64)        {}
func (*inventoryRecorder) RecordRedelivery(string, uint64)    {}
func (*inventoryRecorder) RecordDrop(string, uint64)          {}
func (*inventoryRecorder) RecordDLQ(string, uint64)           {}
func (*inventoryRecorder) IncrementQueues()                   {}
func (*inventoryRecorder) DecrementQueues()                   {}
func (*inventoryRecorder) SetQueuesExist(int64)               {}
func (r *inventoryRecorder) RecordTopicRequest(telemetry.TopicOperationEvent) {
	r.topicRequests++
}
func (r *inventoryRecorder) RecordTopicOperation(telemetry.TopicOperationEvent) {
	r.topicOperations++
}
func (r *inventoryRecorder) RecordTopicPublish(telemetry.TopicPublishEvent) {
	r.topicPublishes++
}
func (r *inventoryRecorder) RecordTopicSubscriptionCreated(string) {
	r.subscriptionsCreated++
}
func (r *inventoryRecorder) RecordTopicSubscriptionDeleted(string) {
	r.subscriptionsDeleted++
}
func (r *inventoryRecorder) RecordTopicState(state telemetry.TopicStateEvent) { r.state = &state }
func (r *inventoryRecorder) RecordTopicStateUnavailable()                     { r.unavailable++ }

type testReplicaApplyGuard struct{}

func (testReplicaApplyGuard) BeginPublishApply() error  { return nil }
func (testReplicaApplyGuard) FinishPublishApply() error { return nil }
func (testReplicaApplyGuard) Check() error              { return nil }

func TestFollowerApplyDoesNotDuplicateLogicalTopicCounters(t *testing.T) {
	wiring := newQueueTelemetryWiring(storageDriverSQLite, true)
	localRecorder := new(inventoryRecorder)
	logicalRecorder := new(inventoryRecorder)
	wiring.local.SetRecorder(localRecorder)
	wiring.logical.SetRecorder(logicalRecorder)

	cfg := config.Config{
		StorageDriver:      storageDriverSQLite,
		StorageDBPath:      filepath.Join(t.TempDir(), "follower.db"),
		StorageJournalMode: "wal",
	}
	clusterCfg := cluster.Config{Enabled: true}
	logger := logkit.NewNop()
	backend, err := initStorageBackend(&cfg, logger)
	if err != nil {
		t.Fatalf("initialize follower backend: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	storage, closeStorage, err := wiring.initPhysicalQueueStorage(&cfg, &clusterCfg, logger, backend)
	if err != nil {
		t.Fatalf("initialize follower storage: %v", err)
	}
	t.Cleanup(func() { _ = closeStorage() })
	replicated, ok := storage.(queue.ReplicatedStorage)
	if !ok {
		t.Fatalf("production follower storage = %T, want replicated storage", storage)
	}

	machine := clusterfsm.New(
		replicated,
		nil,
		testReplicaApplyGuard{},
		func(fatalErr error) { panic(fatalErr) },
		clusterfsm.WithTopicStateReconciler(wiring.reconcileTopicState),
	)

	apply := func(index uint64, cmd *command.Command) {
		t.Helper()
		encoded, encodeErr := cmd.Encode()
		if encodeErr != nil {
			t.Fatalf("encode %s command: %v", cmd.Op, encodeErr)
		}
		if result := machine.Apply(&hraft.Log{Index: index, Type: hraft.LogCommand, Data: encoded}); result != nil {
			if applyErr, ok := result.(error); ok {
				t.Fatalf("apply %s command: %v", cmd.Op, applyErr)
			}
		}
	}
	protoCommand := func(op command.Op, message interface{ MarshalVT() ([]byte, error) }, ids ...string) *command.Command {
		t.Helper()
		payload, marshalErr := message.MarshalVT()
		if marshalErr != nil {
			t.Fatalf("marshal %s command: %v", op, marshalErr)
		}
		return &command.Command{Op: op, Timestamp: time.Now().UnixNano(), IDs: ids, Payload: payload}
	}
	jsonCommand := func(op command.Op, target string, value any, ids ...string) *command.Command {
		t.Helper()
		payload, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatalf("marshal %s command: %v", op, marshalErr)
		}
		return &command.Command{Op: op, Timestamp: time.Now().UnixNano(), Target: target, IDs: ids, Payload: payload}
	}

	apply(1, protoCommand(command.OpCreateQueue, &v1.CreateQueueRequest{QueueName: "follower-queue"}, "queueone"))
	apply(2, jsonCommand(command.OpCreateTopic, "", &queue.CreateTopicRequest{TopicName: "follower-topic"}, "topicone"))
	apply(3, jsonCommand(command.OpSubscribe, "topicone", &queue.SubscribeRequest{QueueID: "queueone"}, "subone"))
	apply(4, jsonCommand(command.OpPublish, "topicone", &queue.PublishRequest{
		Messages: []queue.PublishMessage{{Body: []byte("payload")}},
	}, "messageone"))

	if localRecorder.state == nil || localRecorder.state.TopicsExist != 1 || localRecorder.state.Subscriptions["topicone"] != 1 {
		t.Fatalf("follower exact state = %#v, want one topic with one subscription", localRecorder.state)
	}

	apply(5, &command.Command{
		Op: command.OpUnsubscribe, Timestamp: time.Now().UnixNano(), Target: "topicone", IDs: []string{"subone"},
	})
	apply(6, jsonCommand(command.OpSubscribe, "topicone", &queue.SubscribeRequest{QueueID: "queueone"}, "subtwo"))
	apply(7, &command.Command{Op: command.OpDeleteTopic, Timestamp: time.Now().UnixNano(), Target: "topicone"})
	if localRecorder.state == nil || localRecorder.state.TopicsExist != 0 || len(localRecorder.state.Subscriptions) != 0 {
		t.Fatalf("follower exact state after deletion = %#v, want no topics or subscriptions", localRecorder.state)
	}

	if localRecorder.topicRequests != 0 || localRecorder.topicOperations != 0 || localRecorder.topicPublishes != 0 ||
		localRecorder.subscriptionsCreated != 0 || localRecorder.subscriptionsDeleted != 0 {
		t.Fatalf(
			"follower local logical counters = request:%d operation:%d publish:%d created:%d deleted:%d, want all zero",
			localRecorder.topicRequests,
			localRecorder.topicOperations,
			localRecorder.topicPublishes,
			localRecorder.subscriptionsCreated,
			localRecorder.subscriptionsDeleted,
		)
	}
	if logicalRecorder.state != nil || logicalRecorder.topicRequests != 0 || logicalRecorder.topicOperations != 0 ||
		logicalRecorder.topicPublishes != 0 || logicalRecorder.subscriptionsCreated != 0 || logicalRecorder.subscriptionsDeleted != 0 {
		t.Fatalf("follower logical recorder changed: %#v", logicalRecorder)
	}
}

func TestStartupInventoryReplaysBeforeCollectorAttachment(t *testing.T) {
	observer := telemetry.NewObserver(metrics.BackendSQLite)
	storage := &inventoryStorage{inventory: queue.TopicInventory{
		TopicsExist:        1,
		SubscriptionCounts: map[string]int64{"topicone": 2},
	}}
	if err := replayStartupTopicInventory(context.Background(), storage, observer); err != nil {
		t.Fatalf("replayStartupTopicInventory() = %v", err)
	}
	recorder := new(inventoryRecorder)
	observer.SetRecorder(recorder)
	if recorder.state == nil || recorder.state.TopicsExist != 1 || recorder.state.Subscriptions["topicone"] != 2 {
		t.Fatalf("attached recorder state = %#v, want startup inventory", recorder.state)
	}

	inventoryErr := errors.New("inventory failed")
	bad := &inventoryStorage{err: inventoryErr}
	if err := replayStartupTopicInventory(context.Background(), bad, observer); !errors.Is(err, inventoryErr) {
		t.Fatalf("failed startup inventory = %v, want %v", err, inventoryErr)
	}
}

func TestBlockedStartupInventoryCannotOverwriteNewerFSMState(t *testing.T) {
	observer := telemetry.NewObserver(metrics.BackendSQLite)
	storage := &blockingInventoryStorage{started: make(chan struct{}), release: make(chan struct{})}
	startupDone := make(chan error, 1)
	go func() {
		startupDone <- replayStartupTopicInventory(context.Background(), storage, observer)
	}()
	<-storage.started

	reconcileDone := make(chan struct{})
	go func() {
		observer.ReconcileTopicState(telemetry.TopicStateEvent{
			TopicsExist:   1,
			Subscriptions: map[string]int64{"fsm-new": 2},
		})
		close(reconcileDone)
	}()
	select {
	case <-reconcileDone:
		t.Fatal("newer FSM state overtook blocked startup capture")
	case <-time.After(25 * time.Millisecond):
	}

	close(storage.release)
	if err := <-startupDone; err != nil {
		t.Fatalf("replayStartupTopicInventory() = %v", err)
	}
	<-reconcileDone

	recorder := new(inventoryRecorder)
	observer.SetRecorder(recorder)
	if recorder.state == nil || recorder.state.Subscriptions["fsm-new"] != 2 {
		t.Fatalf("attached recorder state = %#v, want newer FSM inventory", recorder.state)
	}
	if _, stale := recorder.state.Subscriptions["startup-old"]; stale {
		t.Fatalf("attached recorder retained stale startup inventory: %#v", recorder.state)
	}
}

func TestHelmUsesSeparateLivenessAndReadinessRoutes(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not installed")
	}

	output, err := exec.Command(
		helm, "template", "test", "../deploy/helm/plainq",
		"--set", "auth.enabled=false",
		"--set", "config.healthRoute=/ready",
		"--set", "config.healthLivenessRoute=/alive",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, output)
	}

	manifest := string(output)
	for _, want := range []string{
		"- -health.route=/ready",
		"- -health.liveness.route=/alive",
		"livenessProbe:\n            failureThreshold: 3\n            httpGet:\n              path: /alive",
		"readinessProbe:\n            failureThreshold: 3\n            httpGet:\n              path: /ready",
	} {
		if !strings.Contains(manifest, want) {
			t.Errorf("rendered manifest missing %q", want)
		}
	}
}

type telemetryCloserForTest struct {
	events *[]string
}

func (c *telemetryCloserForTest) Close() error {
	*c.events = append(*c.events, "database closed")

	return nil
}

type contextServerForTest struct {
	events *[]string
	err    error
}

func (s *contextServerForTest) Serve(context.Context) error {
	*s.events = append(*s.events, "collector stopped")

	return s.err
}

func TestTelemetryDBClosesAfterCollectorStops(t *testing.T) {
	t.Run("serve completion", func(t *testing.T) {
		var events []string
		serveErr := errors.New("serve stopped")
		db := &telemetryCloserForTest{events: &events}
		server := &contextServerForTest{events: &events, err: serveErr}

		err := serveWithTelemetryDB(
			context.Background(),
			logkit.NewNop(),
			db,
			func() (contextServer, error) { return server, nil },
		)
		if !errors.Is(err, serveErr) {
			t.Fatalf("serve error = %v, want %v", err, serveErr)
		}
		assertLifecycleEvents(t, events, []string{"collector stopped", "database closed"})
	})

	t.Run("construction failure", func(t *testing.T) {
		var events []string
		constructionErr := errors.New("construction failed")
		db := &telemetryCloserForTest{events: &events}

		err := serveWithTelemetryDB(
			context.Background(),
			logkit.NewNop(),
			db,
			func() (contextServer, error) { return nil, constructionErr },
		)
		if !errors.Is(err, constructionErr) {
			t.Fatalf("construction error = %v, want %v", err, constructionErr)
		}
		assertLifecycleEvents(t, events, []string{"database closed"})
	})
}

func assertLifecycleEvents(t *testing.T, got, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("lifecycle events = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("lifecycle events = %v, want %v", got, want)
		}
	}
}
