package plainqapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marsolab/plainq/operator/internal/plainqapi"
)

// fakeServer is a stand-in for a PlainQ HTTP listener. It implements the
// subset of routes the operator depends on, with the same shapes the real
// handlers emit.
type fakeServer struct {
	t *testing.T

	// queues by ID.
	queues map[string]plainqapi.Queue

	// topics by ID.
	topics map[string]*plainqapi.Topic

	// status returned by the cluster endpoints.
	status plainqapi.ClusterStatus

	// needsOnboarding drives the onboarding endpoints.
	needsOnboarding bool

	// registrationEnabled drives whether signup is refused.
	registrationEnabled bool

	// signIns counts token acquisitions, so tests can assert caching.
	signIns atomic.Int64

	// listCalls counts queue list calls, so tests can assert paging.
	listCalls atomic.Int64

	// nextID hands out server-assigned identifiers.
	nextID atomic.Int64

	// removedMembers records supervised drains.
	removedMembers []string

	// snapshots counts forced snapshots.
	snapshots atomic.Int64

	// tokenExpiry is how long an issued token lasts.
	tokenExpiry time.Duration
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()

	return &fakeServer{
		t:                   t,
		queues:              map[string]plainqapi.Queue{},
		topics:              map[string]*plainqapi.Topic{},
		registrationEnabled: true,
		tokenExpiry:         time.Hour,
	}
}

func (f *fakeServer) id(prefix string) string {
	return prefix + "_" + strconv.FormatInt(f.nextID.Add(1), 10)
}

func (f *fakeServer) start() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/account/signin", func(w http.ResponseWriter, _ *http.Request) {
		f.signIns.Add(1)

		writeJSON(w, http.StatusOK, map[string]any{
			"AccessToken":  "token-" + strconv.FormatInt(f.signIns.Load(), 10),
			"RefreshToken": "refresh",
			"CreatedAt":    time.Now(),
			"ExpiresAt":    time.Now().Add(f.tokenExpiry),
		})
	})

	mux.HandleFunc("POST /api/v1/account/signup", func(w http.ResponseWriter, _ *http.Request) {
		if !f.registrationEnabled {
			// Mirrors signUpHandler: the flag is checked before the body is
			// read, and an admin token does not exempt it.
			http.Error(w, "unauthorized: user registration is disabled", http.StatusUnauthorized)

			return
		}

		writeJSON(w, http.StatusCreated, map[string]any{"id": f.id("a")})
	})

	mux.HandleFunc("GET /api/v1/onboarding/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"needsOnboarding": f.needsOnboarding,
			"hasAdminUsers":   !f.needsOnboarding,
		})
	})

	mux.HandleFunc("POST /api/v1/onboarding/complete", func(w http.ResponseWriter, _ *http.Request) {
		if !f.needsOnboarding {
			http.Error(w, "invalid argument: onboarding has already been completed", http.StatusBadRequest)

			return
		}

		f.needsOnboarding = false

		writeJSON(w, http.StatusCreated, map[string]any{"id": f.id("a")})
	})

	mux.HandleFunc("GET /api/v1/queue", func(w http.ResponseWriter, r *http.Request) {
		if !f.authorized(w, r) {
			return
		}

		f.listCalls.Add(1)
		f.writeQueuePage(w, r)
	})

	mux.HandleFunc("POST /api/v1/queue", func(w http.ResponseWriter, r *http.Request) {
		if !f.authorized(w, r) {
			return
		}

		var req plainqapi.CreateQueueRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
		}

		id := f.id("q")
		f.queues[id] = plainqapi.Queue{
			QueueID:                  id,
			QueueName:                req.QueueName,
			RetentionPeriodSeconds:   req.RetentionPeriodSeconds,
			VisibilityTimeoutSeconds: req.VisibilityTimeoutSeconds,
			MaxReceiveAttempts:       req.MaxReceiveAttempts,
			EvictionPolicy:           req.EvictionPolicy,
			DeadLetterQueueID:        req.DeadLetterQueueID,
		}

		writeJSON(w, http.StatusCreated, map[string]any{"queueId": id})
	})

	mux.HandleFunc("GET /api/v1/queue/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !f.authorized(w, r) {
			return
		}

		queue, ok := f.queues[r.PathValue("id")]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)

			return
		}

		writeJSON(w, http.StatusOK, queue)
	})

	mux.HandleFunc("DELETE /api/v1/queue/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !f.authorized(w, r) {
			return
		}

		delete(f.queues, r.PathValue("id"))
		writeJSON(w, http.StatusOK, map[string]any{})
	})

	mux.HandleFunc("GET /api/v1/queue/topics", func(w http.ResponseWriter, r *http.Request) {
		if !f.authorized(w, r) {
			return
		}

		topics := make([]plainqapi.Topic, 0, len(f.topics))
		for _, topic := range f.topics {
			topics = append(topics, *topic)
		}

		writeJSON(w, http.StatusOK, map[string]any{"topics": topics})
	})

	mux.HandleFunc("POST /api/v1/queue/topics", func(w http.ResponseWriter, r *http.Request) {
		if !f.authorized(w, r) {
			return
		}

		var req struct {
			TopicName string `json:"topicName"`
		}

		_ = json.NewDecoder(r.Body).Decode(&req)

		id := f.id("t")
		f.topics[id] = &plainqapi.Topic{TopicID: id, TopicName: req.TopicName}

		writeJSON(w, http.StatusCreated, map[string]any{"topicId": id})
	})

	mux.HandleFunc("POST /api/v1/queue/topics/{topicID}/subscriptions", func(w http.ResponseWriter, r *http.Request) {
		if !f.authorized(w, r) {
			return
		}

		var req struct {
			QueueID string `json:"queueId"`
		}

		_ = json.NewDecoder(r.Body).Decode(&req)

		topic, ok := f.topics[r.PathValue("topicID")]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)

			return
		}

		id := f.id("s")
		topic.Subscriptions = append(topic.Subscriptions, plainqapi.Subscription{
			SubscriptionID: id,
			TopicID:        topic.TopicID,
			QueueID:        req.QueueID,
		})

		writeJSON(w, http.StatusCreated, map[string]any{"subscriptionId": id})
	})

	mux.HandleFunc("DELETE /api/v1/queue/topics/{topicID}/subscriptions/{subID}",
		func(w http.ResponseWriter, r *http.Request) {
			if !f.authorized(w, r) {
				return
			}

			topic, ok := f.topics[r.PathValue("topicID")]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)

				return
			}

			kept := topic.Subscriptions[:0]

			for _, sub := range topic.Subscriptions {
				if sub.SubscriptionID != r.PathValue("subID") {
					kept = append(kept, sub)
				}
			}

			topic.Subscriptions = kept

			writeJSON(w, http.StatusOK, map[string]any{})
		})

	mux.HandleFunc("GET /api/v1/cluster", func(w http.ResponseWriter, r *http.Request) {
		if !f.authorized(w, r) {
			return
		}

		writeJSON(w, http.StatusOK, f.status)
	})

	mux.HandleFunc("GET /api/v1/cluster/members", func(w http.ResponseWriter, r *http.Request) {
		if !f.authorized(w, r) {
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"members": f.status.Members,
			"quorum":  f.status.Quorum,
			"voters":  f.status.Voters,
			"healthy": f.status.Healthy,
		})
	})

	mux.HandleFunc("DELETE /api/v1/cluster/members/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !f.authorized(w, r) {
			return
		}

		f.removedMembers = append(f.removedMembers, r.PathValue("id"))
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})

	mux.HandleFunc("POST /api/v1/cluster/snapshot", func(w http.ResponseWriter, r *http.Request) {
		if !f.authorized(w, r) {
			return
		}

		f.snapshots.Add(1)
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})

	server := httptest.NewServer(mux)
	f.t.Cleanup(server.Close)

	return server
}

// authorized rejects unauthenticated requests the way the real middleware
// does, so the client's token handling is genuinely exercised.
func (f *fakeServer) authorized(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") == "" {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)

		return false
	}

	return true
}

// writeQueuePage serves one page, honouring the prefix filter and cursor the
// real handler supports.
func (f *fakeServer) writeQueuePage(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	cursor := r.URL.Query().Get("cursor")

	// Deterministic order by ID, which is what a cursor needs.
	ids := make([]string, 0, len(f.queues))
	for id := range f.queues {
		ids = append(ids, id)
	}

	sortStrings(ids)

	matched := make([]plainqapi.Queue, 0, len(ids))

	for _, id := range ids {
		queue := f.queues[id]
		if prefix != "" && !hasPrefix(queue.QueueName, prefix) {
			continue
		}

		matched = append(matched, queue)
	}

	// One queue per page, so paging is actually exercised.
	const pageSize = 1

	start := 0

	if cursor != "" {
		for i, queue := range matched {
			if queue.QueueID == cursor {
				start = i + 1

				break
			}
		}
	}

	end := min(start+pageSize, len(matched))

	page := matched[start:end]
	hasMore := end < len(matched)
	next := ""

	if hasMore && len(page) > 0 {
		next = page[len(page)-1].QueueID
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"queues":     page,
		"nextCursor": next,
		"hasMore":    hasMore,
		"totalCount": len(matched),
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(value)
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func newClient(t *testing.T, f *fakeServer) *plainqapi.Client {
	t.Helper()

	server := f.start()

	return plainqapi.New(server.URL, plainqapi.WithCredentials(plainqapi.Credentials{
		Email:    "admin@example.com",
		Password: "hunter2",
	}))
}

func TestResolveQueueByNameMatchesExactlyNotByPrefix(t *testing.T) {
	t.Parallel()

	fake := newFakeServer(t)
	client := newClient(t, fake)
	ctx := t.Context()

	// "orders" is a prefix of "orders-dlq", so a naive prefix scan that took
	// the first result would resolve the wrong queue.
	dlqID, err := client.CreateQueue(ctx, plainqapi.CreateQueueRequest{QueueName: "orders-dlq"})
	if err != nil {
		t.Fatalf("create dlq: %v", err)
	}

	ordersID, err := client.CreateQueue(ctx, plainqapi.CreateQueueRequest{QueueName: "orders"})
	if err != nil {
		t.Fatalf("create orders: %v", err)
	}

	resolved, err := client.ResolveQueueByName(ctx, "orders")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if resolved.QueueID != ordersID {
		t.Fatalf("resolved %q, want %q (dlq is %q)", resolved.QueueID, ordersID, dlqID)
	}
}

func TestResolveQueueByNamePagesUntilFound(t *testing.T) {
	t.Parallel()

	fake := newFakeServer(t)
	client := newClient(t, fake)
	ctx := t.Context()

	// Every one of these matches the prefix "orders", and the exact match is
	// created last so it sorts last by ID. The fake serves one queue per
	// page, so reaching it means following the cursor to the end — which is
	// exactly the case a single-page scan would get wrong.
	for _, name := range []string{"orders-a", "orders-b", "orders-c"} {
		if _, err := client.CreateQueue(ctx, plainqapi.CreateQueueRequest{QueueName: name}); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}

	want, err := client.CreateQueue(ctx, plainqapi.CreateQueueRequest{QueueName: "orders"})
	if err != nil {
		t.Fatalf("create orders: %v", err)
	}

	fake.listCalls.Store(0)

	resolved, err := client.ResolveQueueByName(ctx, "orders")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if resolved.QueueID != want {
		t.Fatalf("resolved %q, want %q", resolved.QueueID, want)
	}

	if calls := fake.listCalls.Load(); calls < 2 {
		t.Fatalf("expected the scan to page, got %d list call(s)", calls)
	}
}

func TestResolveQueueByNameNotFound(t *testing.T) {
	t.Parallel()

	fake := newFakeServer(t)
	client := newClient(t, fake)

	_, err := client.ResolveQueueByName(t.Context(), "absent")
	if !errors.Is(err, plainqapi.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestTokenIsCachedAcrossCalls(t *testing.T) {
	t.Parallel()

	fake := newFakeServer(t)
	client := newClient(t, fake)
	ctx := t.Context()

	for range 5 {
		if _, err := client.ListQueues(ctx, ""); err != nil {
			t.Fatalf("list: %v", err)
		}
	}

	if signIns := fake.signIns.Load(); signIns != 1 {
		t.Fatalf("signed in %d times, want 1", signIns)
	}
}

func TestTokenIsRenewedBeforeExpiry(t *testing.T) {
	t.Parallel()

	fake := newFakeServer(t)
	fake.tokenExpiry = 90 * time.Second
	server := fake.start()

	// A token with 90s of life is renewed once the 60s leeway bites.
	now := time.Now()
	client := plainqapi.New(server.URL,
		plainqapi.WithCredentials(plainqapi.Credentials{Email: "a@example.com", Password: "p"}),
		plainqapi.WithClock(func() time.Time { return now }),
	)

	ctx := t.Context()

	if _, err := client.ListQueues(ctx, ""); err != nil {
		t.Fatalf("first list: %v", err)
	}

	now = now.Add(45 * time.Second)

	if _, err := client.ListQueues(ctx, ""); err != nil {
		t.Fatalf("second list: %v", err)
	}

	if signIns := fake.signIns.Load(); signIns != 2 {
		t.Fatalf("signed in %d times, want 2 (renewal within leeway)", signIns)
	}
}

func TestSignUpReportsRegistrationDisabled(t *testing.T) {
	t.Parallel()

	fake := newFakeServer(t)
	fake.registrationEnabled = false
	client := newClient(t, fake)

	err := client.SignUp(t.Context(), "svc@example.com", "hunter2", "")
	if !errors.Is(err, plainqapi.ErrRegistrationDisabled) {
		t.Fatalf("got %v, want ErrRegistrationDisabled", err)
	}

	// It must not be mistaken for a credential problem, or the reconciler
	// would retry a configuration error forever.
	if errors.Is(err, plainqapi.ErrUnauthorized) {
		t.Fatal("registration-disabled must not classify as ErrUnauthorized")
	}
}

func TestCompleteOnboardingIsIdempotentFromTheCallerSide(t *testing.T) {
	t.Parallel()

	fake := newFakeServer(t)
	fake.needsOnboarding = true
	client := newClient(t, fake)
	ctx := t.Context()

	status, err := client.OnboardingStatus(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}

	if !status.NeedsOnboarding {
		t.Fatal("expected onboarding to be needed")
	}

	if err := client.CompleteOnboarding(ctx, "admin@example.com", "hunter2", "Admin"); err != nil {
		t.Fatalf("complete: %v", err)
	}

	// The endpoint self-closes. A second call fails, and the status endpoint
	// is how a caller distinguishes "already done" from "broken".
	if err := client.CompleteOnboarding(ctx, "admin@example.com", "hunter2", "Admin"); err == nil {
		t.Fatal("expected the second onboarding to be refused")
	}

	status, err = client.OnboardingStatus(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}

	if status.NeedsOnboarding {
		t.Fatal("expected onboarding to be complete")
	}
}

func TestWaitForAppliedBlocksUntilSourceCatchesUp(t *testing.T) {
	t.Parallel()

	fake := newFakeServer(t)
	fake.status = plainqapi.ClusterStatus{
		Enabled:      true,
		NodeID:       "orders-2",
		CommitIndex:  100,
		AppliedIndex: 90,
		Healthy:      true,
	}

	client := newClient(t, fake)

	// A node 10 entries behind must not satisfy the wait, however healthy
	// the cluster claims to be.
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()

	_, err := client.WaitForApplied(ctx, 100)
	if !errors.Is(err, plainqapi.ErrSourceLagging) {
		t.Fatalf("got %v, want ErrSourceLagging", err)
	}
}

func TestWaitForAppliedReturnsOnceCaughtUp(t *testing.T) {
	t.Parallel()

	fake := newFakeServer(t)
	fake.status = plainqapi.ClusterStatus{
		Enabled:      true,
		NodeID:       "orders-2",
		CommitIndex:  100,
		AppliedIndex: 100,
		Healthy:      true,
	}

	client := newClient(t, fake)

	applied, err := client.WaitForApplied(t.Context(), 100)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}

	if applied != 100 {
		t.Fatalf("applied %d, want 100", applied)
	}
}

func TestSelectBackupSourceNeverPicksTheLeader(t *testing.T) {
	t.Parallel()

	members := []plainqapi.ClusterMember{
		{ID: "orders-0", Suffrage: plainqapi.SuffrageVoter, Reachable: true, Leader: true},
		{ID: "orders-1", Suffrage: plainqapi.SuffrageVoter, Reachable: true},
		{ID: "orders-2", Suffrage: plainqapi.SuffrageNonVoter, Reachable: true},
	}

	for _, prefer := range []string{"NonVoter", "Follower", "Any"} {
		source, ok := plainqapi.SelectBackupSource(members, prefer)
		if !ok {
			t.Fatalf("%s: no source selected", prefer)
		}

		if source.Leader {
			t.Fatalf("%s: selected the leader", prefer)
		}
	}
}

func TestSelectBackupSourcePrefersNonVoter(t *testing.T) {
	t.Parallel()

	members := []plainqapi.ClusterMember{
		{ID: "orders-0", Suffrage: plainqapi.SuffrageVoter, Reachable: true, Leader: true},
		{ID: "orders-1", Suffrage: plainqapi.SuffrageVoter, Reachable: true},
		{ID: "orders-2", Suffrage: plainqapi.SuffrageNonVoter, Reachable: true},
	}

	source, ok := plainqapi.SelectBackupSource(members, "NonVoter")
	if !ok || source.ID != "orders-2" {
		t.Fatalf("selected %+v, want the non-voter orders-2", source)
	}
}

func TestSelectBackupSourceSkipsUnreachableNodes(t *testing.T) {
	t.Parallel()

	members := []plainqapi.ClusterMember{
		{ID: "orders-0", Suffrage: plainqapi.SuffrageVoter, Reachable: true, Leader: true},
		{ID: "orders-1", Suffrage: plainqapi.SuffrageVoter, Reachable: false},
		{ID: "orders-2", Suffrage: plainqapi.SuffrageNonVoter, Reachable: false},
	}

	// Only the leader is reachable, so NonVoter and Follower must both fail
	// rather than fall back to it.
	if _, ok := plainqapi.SelectBackupSource(members, "NonVoter"); ok {
		t.Fatal("expected no source when only the leader is reachable")
	}

	source, ok := plainqapi.SelectBackupSource(members, "Any")
	if !ok || source.ID != "orders-0" {
		t.Fatalf("Any should fall back to the leader, got %+v", source)
	}
}

func TestRemoveMemberAndSnapshot(t *testing.T) {
	t.Parallel()

	fake := newFakeServer(t)
	client := newClient(t, fake)
	ctx := t.Context()

	if err := client.RemoveMember(ctx, "orders-2"); err != nil {
		t.Fatalf("remove: %v", err)
	}

	if err := client.Snapshot(ctx); err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	if len(fake.removedMembers) != 1 || fake.removedMembers[0] != "orders-2" {
		t.Fatalf("removed %v, want [orders-2]", fake.removedMembers)
	}

	if fake.snapshots.Load() != 1 {
		t.Fatalf("snapshots %d, want 1", fake.snapshots.Load())
	}
}

func TestTopicSubscriptionsRoundTrip(t *testing.T) {
	t.Parallel()

	fake := newFakeServer(t)
	client := newClient(t, fake)
	ctx := t.Context()

	topicID, err := client.CreateTopic(ctx, "order-events")
	if err != nil {
		t.Fatalf("create topic: %v", err)
	}

	subID, err := client.Subscribe(ctx, topicID, "q_1")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	topic, err := client.ResolveTopicByName(ctx, "order-events")
	if err != nil {
		t.Fatalf("resolve topic: %v", err)
	}

	if len(topic.Subscriptions) != 1 || topic.Subscriptions[0].SubscriptionID != subID {
		t.Fatalf("subscriptions %+v, want one with id %q", topic.Subscriptions, subID)
	}

	if err := client.Unsubscribe(ctx, topicID, subID); err != nil {
		t.Fatalf("unsubscribe: %v", err)
	}

	topic, err = client.ResolveTopicByName(ctx, "order-events")
	if err != nil {
		t.Fatalf("resolve topic: %v", err)
	}

	if len(topic.Subscriptions) != 0 {
		t.Fatalf("subscriptions %+v, want none", topic.Subscriptions)
	}
}

func TestDeleteQueueToleratesAlreadyGone(t *testing.T) {
	t.Parallel()

	fake := newFakeServer(t)
	client := newClient(t, fake)

	// A finalizer runs more than once. Deleting a queue that is already gone
	// must not wedge it.
	if err := client.DeleteQueue(t.Context(), "q_absent"); err != nil {
		t.Fatalf("delete: %v", err)
	}
}
