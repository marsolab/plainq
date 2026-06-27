package tui

import (
	"context"
	"errors"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"google.golang.org/grpc"
)

// fakeClient is a programmable in-memory implementation of Client for tests.
type fakeClient struct {
	queues   []*v1.DescribeQueueResponse
	received []*v1.ReceiveMessage
	listErr  error

	lastSend   *v1.SendRequest
	lastDelete *v1.DeleteQueueRequest
	lastPurge  *v1.PurgeQueueRequest
}

func (f *fakeClient) ListQueues(_ context.Context, _ *v1.ListQueuesRequest, _ ...grpc.CallOption) (*v1.ListQueuesResponse, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}

	return &v1.ListQueuesResponse{Queues: f.queues}, nil
}

func (f *fakeClient) DescribeQueue(_ context.Context, in *v1.DescribeQueueRequest, _ ...grpc.CallOption) (*v1.DescribeQueueResponse, error) {
	return &v1.DescribeQueueResponse{QueueId: in.GetQueueId()}, nil
}

func (f *fakeClient) Receive(_ context.Context, _ *v1.ReceiveRequest, _ ...grpc.CallOption) (*v1.ReceiveResponse, error) {
	return &v1.ReceiveResponse{Messages: f.received}, nil
}

func (f *fakeClient) Send(_ context.Context, in *v1.SendRequest, _ ...grpc.CallOption) (*v1.SendResponse, error) {
	f.lastSend = in

	return &v1.SendResponse{MessageIds: []string{"m1"}}, nil
}

func (f *fakeClient) PurgeQueue(_ context.Context, in *v1.PurgeQueueRequest, _ ...grpc.CallOption) (*v1.PurgeQueueResponse, error) {
	f.lastPurge = in

	return &v1.PurgeQueueResponse{MessagesCount: 3}, nil
}

func (f *fakeClient) DeleteQueue(_ context.Context, in *v1.DeleteQueueRequest, _ ...grpc.CallOption) (*v1.DeleteQueueResponse, error) {
	f.lastDelete = in

	return &v1.DeleteQueueResponse{}, nil
}

func sampleQueues() []*v1.DescribeQueueResponse {
	return []*v1.DescribeQueueResponse{
		{QueueId: "D8VEKIMGOO6F7O6LNLN0", QueueName: "orders", VisibilityTimeoutSeconds: 30, MaxReceiveAttempts: 5},
		{QueueId: "D8VEKIMGOO6F7O6LNLN1", QueueName: "events", VisibilityTimeoutSeconds: 60, MaxReceiveAttempts: 3},
	}
}

func asModel(t *testing.T, m tea.Model) model {
	t.Helper()

	typed, ok := m.(model)
	if !ok {
		t.Fatalf("expected model, got %T", m)
	}

	return typed
}

func TestListQueuesCmd(t *testing.T) {
	fake := &fakeClient{queues: sampleQueues()}

	msg := listQueuesCmd(fake)()

	loaded, ok := msg.(queuesLoadedMsg)
	if !ok {
		t.Fatalf("expected queuesLoadedMsg, got %T", msg)
	}

	if len(loaded.queues) != 2 {
		t.Fatalf("expected 2 queues, got %d", len(loaded.queues))
	}
}

func TestListQueuesCmdError(t *testing.T) {
	fake := &fakeClient{listErr: errors.New("boom")}

	msg := listQueuesCmd(fake)()

	if _, ok := msg.(errMsg); !ok {
		t.Fatalf("expected errMsg, got %T", msg)
	}
}

func TestOnQueuesLoadedPopulatesTable(t *testing.T) {
	m := newModel("localhost:8080", &fakeClient{})

	m = m.onQueuesLoaded(sampleQueues())

	if got := len(m.table.Rows()); got != 2 {
		t.Fatalf("expected 2 rows, got %d", got)
	}

	if m.loading {
		t.Fatal("loading should be false after load")
	}

	if q := m.currentQueue(); q == nil || q.GetQueueName() != "orders" {
		t.Fatalf("unexpected current queue: %v", q)
	}
}

func TestEnterOpensDetail(t *testing.T) {
	m := newModel("localhost:8080", &fakeClient{})
	m = m.onQueuesLoaded(sampleQueues())

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	updated := asModel(t, next)

	if updated.state != stateDetail {
		t.Fatalf("expected stateDetail, got %d", updated.state)
	}

	if updated.selected == nil || updated.selected.GetQueueName() != "orders" {
		t.Fatalf("expected selected orders, got %v", updated.selected)
	}
}

func TestSendKeyEntersComposer(t *testing.T) {
	m := newModel("localhost:8080", &fakeClient{})
	m = m.onQueuesLoaded(sampleQueues())
	m.state = stateDetail
	m.selected = sampleQueues()[0]

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	updated := asModel(t, next)

	if updated.state != stateSend {
		t.Fatalf("expected stateSend, got %d", updated.state)
	}
}

func TestSubmitSendDispatches(t *testing.T) {
	fake := &fakeClient{}
	m := newModel("localhost:8080", fake)
	m.state = stateSend
	m.selected = sampleQueues()[0]
	m.input.SetValue("payload")

	next, cmd := m.submitSend()
	updated := asModel(t, next)

	if updated.state != stateDetail {
		t.Fatalf("expected stateDetail after submit, got %d", updated.state)
	}

	if cmd == nil {
		t.Fatal("expected a send command")
	}

	if _, ok := cmd().(sentMsg); !ok {
		t.Fatal("expected sentMsg from send command")
	}

	if fake.lastSend == nil || string(fake.lastSend.GetMessages()[0].GetBody()) != "payload" {
		t.Fatalf("send did not carry the body: %v", fake.lastSend)
	}
}

func TestDeleteKeyDispatches(t *testing.T) {
	fake := &fakeClient{}
	m := newModel("localhost:8080", fake)
	m = m.onQueuesLoaded(sampleQueues())

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	if cmd == nil {
		t.Fatal("expected a delete command")
	}

	if _, ok := cmd().(deletedMsg); !ok {
		t.Fatal("expected deletedMsg from delete command")
	}

	if fake.lastDelete == nil || fake.lastDelete.GetQueueId() != "D8VEKIMGOO6F7O6LNLN0" {
		t.Fatalf("delete did not target the selected queue: %v", fake.lastDelete)
	}
}

func TestEvictionPolicyName(t *testing.T) {
	cases := map[v1.EvictionPolicy]string{
		v1.EvictionPolicy_EVICTION_POLICY_DROP:        "drop",
		v1.EvictionPolicy_EVICTION_POLICY_DEAD_LETTER: "dead-letter",
		v1.EvictionPolicy_EVICTION_POLICY_REORDER:     "reorder",
		v1.EvictionPolicy_EVICTION_POLICY_UNSPECIFIED: "unspecified",
	}

	for policy, want := range cases {
		if got := evictionPolicyName(policy); got != want {
			t.Errorf("policy %v: got %q want %q", policy, got, want)
		}
	}
}

func TestViewRendersWithoutPanic(t *testing.T) {
	m := newModel("localhost:8080", &fakeClient{})
	m = m.onQueuesLoaded(sampleQueues())

	if m.View() == "" {
		t.Fatal("list view should not be empty")
	}

	m.state = stateDetail
	m.selected = sampleQueues()[0]

	if m.View() == "" {
		t.Fatal("detail view should not be empty")
	}

	m.state = stateSend

	if m.View() == "" {
		t.Fatal("send view should not be empty")
	}
}
