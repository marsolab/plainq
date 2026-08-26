package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/metrics"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/server/service/telemetry"
)

func TestTursoUsesTursoTelemetryBackend(t *testing.T) {
	if got := telemetryBackend(storageDriverTurso); got != metrics.BackendTurso {
		t.Fatalf("telemetryBackend(turso) = %q, want %q", got, metrics.BackendTurso)
	}
	local, logical := newTelemetryObservers(storageDriverTurso, false)
	if local.Backend() != metrics.BackendTurso || logical != local {
		t.Fatalf("standalone observers = %q/%p/%p, want one Turso observer", local.Backend(), local, logical)
	}
}

func TestClusterIngressUsesClusterBackend(t *testing.T) {
	local, logical := newTelemetryObservers(storageDriverSQLite, true)
	if local.Backend() != metrics.BackendSQLite {
		t.Fatalf("local backend = %q, want sqlite", local.Backend())
	}
	if logical == local || logical.Backend() != metrics.BackendCluster {
		t.Fatalf("logical observer = %p backend %q, want distinct cluster observer", logical, logical.Backend())
	}
	captureCalled := false
	if err := logical.CaptureTopicState(func() (telemetry.TopicStateEvent, error) {
		captureCalled = true
		return telemetry.TopicStateEvent{}, nil
	}); err != nil {
		t.Fatalf("logical CaptureTopicState() = %v", err)
	}
	if captureCalled {
		t.Fatal("cluster ingress observer captured exact topic state")
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
	state       *telemetry.TopicStateEvent
	unavailable int
}

func (*inventoryRecorder) RecordSend(string, uint64, uint64)                  {}
func (*inventoryRecorder) RecordReceive(string, uint64, bool)                 {}
func (*inventoryRecorder) RecordDelete(string, uint64)                        {}
func (*inventoryRecorder) RecordRedelivery(string, uint64)                    {}
func (*inventoryRecorder) RecordDrop(string, uint64)                          {}
func (*inventoryRecorder) RecordDLQ(string, uint64)                           {}
func (*inventoryRecorder) IncrementQueues()                                   {}
func (*inventoryRecorder) DecrementQueues()                                   {}
func (*inventoryRecorder) SetQueuesExist(int64)                               {}
func (*inventoryRecorder) RecordTopicRequest(telemetry.TopicOperationEvent)   {}
func (*inventoryRecorder) RecordTopicOperation(telemetry.TopicOperationEvent) {}
func (*inventoryRecorder) RecordTopicPublish(telemetry.TopicPublishEvent)     {}
func (*inventoryRecorder) RecordTopicSubscriptionCreated(string)              {}
func (*inventoryRecorder) RecordTopicSubscriptionDeleted(string)              {}
func (r *inventoryRecorder) RecordTopicState(state telemetry.TopicStateEvent) { r.state = &state }
func (r *inventoryRecorder) RecordTopicStateUnavailable()                     { r.unavailable++ }

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
