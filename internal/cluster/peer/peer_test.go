package peer

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/cluster/command"
	"github.com/marsolab/plainq/internal/cluster/consensus"
	"github.com/marsolab/plainq/internal/cluster/publishwire"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/shared/deleteresult"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/maxatome/go-testdeep/td"
)

// stubApplier is a consensus engine with a scripted answer.
type stubApplier struct {
	response any
	err      error
	seen     []byte
	calls    int
}

func (s *stubApplier) Apply(_ context.Context, data []byte) (any, error) {
	s.calls++
	s.seen = append([]byte(nil), data...)

	return s.response, s.err
}

func TestForwardRejectsCommandOneByteOverLimitBeforeApply(t *testing.T) {
	applier := new(stubApplier)
	server := NewServer(ServerConfig{Applier: applier, Membership: &stubMembership{}})
	req := httptest.NewRequest(
		http.MethodPost,
		"/v2/forward",
		bytes.NewReader(make([]byte, command.MaxEncodedBytes+1)),
	)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge || w.Header().Get(errorHeader) != "capacity" {
		t.Fatalf("oversized forward status/class = %d/%q, want %d/capacity",
			w.Code, w.Header().Get(errorHeader), http.StatusRequestEntityTooLarge)
	}
	if applier.calls != 0 {
		t.Fatalf("oversized forward Apply calls = %d, want 0", applier.calls)
	}
}

func TestPeerClientRejectsOversizedCommandBeforeHTTP(t *testing.T) {
	applier := new(stubApplier)
	server := newTestServer(t, applier, &stubMembership{}, "")
	client := &Client{http: server.Client()}

	_, err := client.Forward(
		context.Background(),
		strings.TrimPrefix(server.URL, "http://"),
		make([]byte, command.MaxEncodedBytes+1),
	)
	if !errors.Is(err, pqerr.ErrCapacityExceeded) {
		t.Fatalf("Forward() = %v, want capacity error", err)
	}
	if applier.calls != 0 {
		t.Fatalf("client-preflight Apply calls = %d, want 0", applier.calls)
	}
}

// stubMembership records the membership calls it receives.
type stubMembership struct {
	added    []string
	nonVoter []string
	removed  []string
	err      error
	status   consensus.Status
}

func (s *stubMembership) AddVoter(_ context.Context, id, addr string) error {
	s.added = append(s.added, id+"@"+addr)

	return s.err
}

func (s *stubMembership) AddNonVoter(_ context.Context, id, addr string) error {
	s.nonVoter = append(s.nonVoter, id+"@"+addr)

	return s.err
}

func (s *stubMembership) RemoveServer(_ context.Context, id string) error {
	s.removed = append(s.removed, id)

	return s.err
}

func (s *stubMembership) Status() consensus.Status { return s.status }

// vtResponse is a stand-in for a schema response: it carries its own codec, so
// the server must use that rather than JSON.
type vtResponse struct{ payload []byte }

func (v *vtResponse) MarshalVT() ([]byte, error) { return v.payload, nil }

func newTestServer(t *testing.T, applier Applier, membership Membership, secret string) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(NewServer(ServerConfig{
		Applier:    applier,
		Membership: membership,
		Secret:     secret,
	}).router)

	t.Cleanup(server.Close)

	return server
}

// post issues a request the way the client would, without going through the
// cluster mux.
func post(t *testing.T, server *httptest.Server, method, path, secret, body string) *http.Response {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), method, server.URL+path, strings.NewReader(body))
	td.Require(t).CmpNoError(err)

	if secret != "" {
		req.Header.Set(secretHeader, secret)
	}

	resp, doErr := http.DefaultClient.Do(req)
	td.Require(t).CmpNoError(doErr)

	t.Cleanup(func() { _ = resp.Body.Close() })

	return resp
}

// The cluster port carries every message body in the system. A caller without
// the secret gets nothing.
func TestPeerRPCRequiresTheClusterSecret(t *testing.T) {
	applier := &stubApplier{}
	server := newTestServer(t, applier, &stubMembership{}, "correct-horse")

	resp := post(t, server, http.MethodPost, "/v1/forward", "", "payload")
	td.Cmp(t, resp.StatusCode, http.StatusUnauthorized)

	resp = post(t, server, http.MethodPost, "/v1/forward", "wrong-secret", "payload")
	td.Cmp(t, resp.StatusCode, http.StatusUnauthorized)

	td.Cmp(t, applier.seen, td.Nil(), "an unauthenticated caller never reaches consensus")

	resp = post(t, server, http.MethodPost, "/v1/forward", "correct-horse", "payload")
	td.Cmp(t, resp.StatusCode, http.StatusOK)
	td.Cmp(t, string(applier.seen), "payload")
}

// A cluster on a trusted network may run without a secret. That has to be a
// deliberate configuration, not a way to bypass one that is set.
func TestPeerRPCWithoutASecretIsOpen(t *testing.T) {
	server := newTestServer(t, &stubApplier{}, &stubMembership{}, "")

	resp := post(t, server, http.MethodPost, "/v1/forward", "", "payload")
	td.Cmp(t, resp.StatusCode, http.StatusOK)
}

// "Not the leader" is routing information, not a failure: the follower that
// asked has to know to look the leader up again rather than fail the write.
func TestForwardTranslatesConsensusErrors(t *testing.T) {
	cases := map[string]struct {
		err    error
		status int
		class  string
	}{
		"not leader":       {err: consensus.ErrNotLeader, status: http.StatusServiceUnavailable, class: "not-leader"},
		"no leader":        {err: consensus.ErrNoLeader, status: http.StatusServiceUnavailable, class: "not-leader"},
		"commit unknown":   {err: consensus.ErrCommitUnknown, status: http.StatusInternalServerError, class: "commit-unknown"},
		"shut down":        {err: consensus.ErrShutdown, status: http.StatusServiceUnavailable, class: "shutdown"},
		"not found":        {err: pqerr.ErrNotFound, status: http.StatusNotFound, class: "not-found"},
		"already exists":   {err: pqerr.ErrAlreadyExists, status: http.StatusConflict, class: "already-exists"},
		"invalid input":    {err: pqerr.ErrInvalidInput, status: http.StatusBadRequest, class: "invalid-argument"},
		"failed condition": {err: pqerr.ErrFailedPrecondition, status: http.StatusConflict, class: "failed-precondition"},
		"unavailable":      {err: pqerr.ErrUnavailable, status: http.StatusServiceUnavailable, class: "unavailable"},
		"capacity":         {err: pqerr.ErrCapacityExceeded, status: http.StatusRequestEntityTooLarge, class: "capacity"},
		"anything else":    {err: errors.New("disk on fire"), status: http.StatusInternalServerError, class: "internal"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			server := newTestServer(t, &stubApplier{err: tc.err}, &stubMembership{}, "")

			resp := post(t, server, http.MethodPost, "/v1/forward", "", "payload")

			td.Cmp(t, resp.StatusCode, tc.status)
			td.Cmp(t, resp.Header.Get(errorHeader), tc.class)
		})
	}
}

// An error class survives the hop, so `errors.Is` still works on the far side
// and the follower can act on it.
func TestPeerErrorsKeepTheirClass(t *testing.T) {
	cases := map[string]struct {
		class  string
		target error
	}{
		"not-leader":          {class: "not-leader", target: consensus.ErrNotLeader},
		"commit-unknown":      {class: "commit-unknown", target: consensus.ErrCommitUnknown},
		"shutdown":            {class: "shutdown", target: consensus.ErrShutdown},
		"not-found":           {class: "not-found", target: pqerr.ErrNotFound},
		"already-exists":      {class: "already-exists", target: pqerr.ErrAlreadyExists},
		"invalid-argument":    {class: "invalid-argument", target: pqerr.ErrInvalidInput},
		"failed-precondition": {class: "failed-precondition", target: pqerr.ErrFailedPrecondition},
		"unavailable":         {class: "unavailable", target: pqerr.ErrUnavailable},
		"capacity":            {class: "capacity", target: pqerr.ErrCapacityExceeded},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Built with Set rather than a literal map, so the key is
			// canonicalized the same way a real response's would be.
			header := http.Header{}
			header.Set(errorHeader, tc.class)

			resp := &http.Response{
				Status:     "503 Service Unavailable",
				StatusCode: http.StatusServiceUnavailable,
				Header:     header,
			}

			err := peerError("10.0.0.1:8082", resp, []byte("something went wrong"))

			td.Require(t).CmpError(err)
			td.Cmp(t, errors.Is(err, tc.target), true)
			td.Cmp(t, err.Error(), td.Contains("10.0.0.1:8082"))
			td.Cmp(t, err.Error(), td.Contains("something went wrong"))
		})
	}
}

func TestPeerClientRoundTripsTerminalWriteClassesWithoutRetryMarkers(t *testing.T) {
	tests := []struct {
		name      string
		remoteErr error
		target    error
	}{
		{name: "commit unknown", remoteErr: errors.Join(consensus.ErrCommitUnknown, consensus.ErrNotLeader), target: consensus.ErrCommitUnknown},
		{name: "failed precondition", remoteErr: pqerr.ErrFailedPrecondition, target: pqerr.ErrFailedPrecondition},
		{name: "partial fanout", remoteErr: &queue.PartialPublishError{Causes: []error{consensus.ErrNotLeader}}, target: pqerr.ErrPartialFanout},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newTestServer(t, &stubApplier{err: test.remoteErr}, &stubMembership{}, "")
			client := &Client{http: server.Client()}
			_, err := client.Forward(context.Background(), strings.TrimPrefix(server.URL, "http://"), []byte("command"))
			if !errors.Is(err, test.target) {
				t.Fatalf("Forward() error = %v, want %v", err, test.target)
			}
			if errors.Is(err, consensus.ErrNotLeader) {
				t.Fatalf("Forward() error = %v, must not retain a retryable not-leader marker", err)
			}
		})
	}
}

func TestPeerForwardGateRunsBeforeApplyAndPreservesUnavailableClass(t *testing.T) {
	applier := new(stubApplier)
	gateCalls := 0
	server := httptest.NewServer(NewServer(ServerConfig{
		Applier:    applier,
		Membership: &stubMembership{},
		ForwardGate: func() error {
			gateCalls++
			return pqerr.ErrUnavailable
		},
	}).router)
	t.Cleanup(server.Close)

	client := &Client{http: server.Client()}
	_, err := client.Forward(context.Background(), strings.TrimPrefix(server.URL, "http://"), []byte("not-even-a-command"))
	if !errors.Is(err, pqerr.ErrUnavailable) {
		t.Fatalf("Forward() error = %v, want unavailable", err)
	}
	if gateCalls != 1 {
		t.Fatalf("forward gate calls = %d, want 1", gateCalls)
	}
	if applier.seen != nil {
		t.Fatalf("applier saw payload %q after gate rejection", applier.seen)
	}
}

func TestPartialFanoutTakesPrecedenceOverNestedUnavailableAcrossPeer(t *testing.T) {
	partial := &queue.PartialPublishError{
		Outcome: queue.PublishOutcome{
			FailedDeliveries:   1,
			FailedDestinations: 1,
			DeliveryFailures:   []queue.PublishDeliveryFailure{{QueueID: "queue-1", Messages: 1}},
		},
		Causes: []error{errors.Join(pqerr.ErrUnavailable, consensus.ErrNotLeader, errors.New("destination unavailable"))},
	}
	server := newTestServer(t, &stubApplier{err: partial}, &stubMembership{}, "")

	resp := post(t, server, http.MethodPost, "/v1/forward", "", "publish-command")
	body, err := io.ReadAll(resp.Body)
	td.Require(t).CmpNoError(err)
	td.Cmp(t, resp.StatusCode, http.StatusInternalServerError)
	td.Cmp(t, resp.Header.Get(errorHeader), "partial-fanout")

	followerErr := peerError("leader:8082", resp, body)
	td.Cmp(t, errors.Is(followerErr, pqerr.ErrPartialFanout), true)
	td.Cmp(t, errors.Is(followerErr, pqerr.ErrUnavailable), false,
		"a follower must not retry a partially committed fan-out")
	td.Cmp(t, errors.Is(followerErr, consensus.ErrNotLeader), false,
		"a follower must not reroute a partially committed fan-out")

	publicErr := pqerr.AsTransport(followerErr)
	td.Cmp(t, errors.Is(publicErr, pqerr.ErrPartialFanout), true)
	td.Cmp(t, errors.Is(publicErr, pqerr.ErrUnavailable), false,
		"the reconstructed public error remains Internal")
}

func TestDeleteCapacityErrorIsFollowerRoutable(t *testing.T) {
	if deleteresult.MaxEnvelopeBytes != maxRequestBytes {
		t.Fatalf(
			"delete envelope ceiling = %d, peer ceiling = %d",
			deleteresult.MaxEnvelopeBytes,
			maxRequestBytes,
		)
	}

	capacityErr := &deleteresult.CapacityError{EncodedBytes: 129, Limit: 128}
	server := newTestServer(t, &stubApplier{err: capacityErr}, &stubMembership{}, "")

	resp := post(t, server, http.MethodPost, "/v1/forward", "", "delete-command")
	body, err := io.ReadAll(resp.Body)
	td.Require(t).CmpNoError(err)
	td.Cmp(t, resp.StatusCode, http.StatusInternalServerError)
	td.Cmp(t, resp.Header.Get(errorHeader), "internal")

	followerErr := peerError("leader:8082", resp, body)
	td.Cmp(t, errors.Is(followerErr, pqerr.ErrInvalidInput), false)
	td.Cmp(t, followerErr.Error(), td.Contains("transport capacity"))
}

// A schema response carries its own codec, delete effects use the
// mixed-version envelope, and remaining internal responses are JSON.
func TestEncodeResponse(t *testing.T) {
	encoded, err := encodeResponse(&vtResponse{payload: []byte{1, 2, 3}})
	td.Require(t).CmpNoError(err)
	td.Cmp(t, encoded, []byte{1, 2, 3}, "a schema response uses its own encoding")

	encoded, err = encodeResponse(map[string]string{"topicId": "t1"})
	td.Require(t).CmpNoError(err)
	td.Cmp(t, string(encoded), `{"topicId":"t1"}`)

	encoded, err = encodeResponse(&queue.DeleteQueueResult{RemovedSubscriptions: []queue.Subscription{{SubscriptionID: "subscription-1"}}})
	td.Require(t).CmpNoError(err)
	legacy := &v1.DeleteQueueResponse{}
	td.CmpNoError(t, legacy.UnmarshalVT(encoded), "an old follower accepts the new leader delete envelope")
	remarshaled, err := legacy.MarshalVT()
	td.Require(t).CmpNoError(err)
	td.Cmp(t, remarshaled, encoded, "an old follower preserves the unknown delete envelope")

	encoded, err = encodeResponse(&queue.DeleteTopicResult{RemovedSubscriptions: []queue.Subscription{{SubscriptionID: "subscription-2"}}})
	td.Require(t).CmpNoError(err)
	legacyTopic := &v1.DeleteTopicResponse{}
	td.CmpNoError(t, legacyTopic.UnmarshalVT(encoded), "an old follower accepts the new leader topic-delete envelope")

	encoded, err = encodeResponse(nil)
	td.Require(t).CmpNoError(err)
	td.Cmp(t, encoded, td.Nil(), "a command with no response sends no body")
}

func TestV2ForwardUsesCompactPublishOutcome(t *testing.T) {
	outcome := &queue.PublishOutcome{
		Response:           &queue.PublishResponse{TopicID: "topicone", QueueIDs: []string{"queueone"}},
		Partial:            true,
		SelectedQueues:     2,
		FailedDeliveries:   3,
		FailedDestinations: 1,
		DeliveryFailures: []queue.PublishDeliveryFailure{{
			QueueID: "queuetwo", Messages: 3, Cause: "arbitrary backend secret",
		}},
	}
	applier := &stubApplier{response: outcome}
	server := newTestServer(t, applier, &stubMembership{}, "")

	resp := post(t, server, http.MethodPost, "/v2/forward", "", "publish-command")
	body, err := io.ReadAll(resp.Body)
	td.Require(t).CmpNoError(err)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("v2 forward status = %d, want 200: %s", resp.StatusCode, body)
	}
	if bytes.Contains(body, []byte("deliveryFailures")) || bytes.Contains(body, []byte("arbitrary backend secret")) {
		t.Fatalf("compact v2 outcome leaked detailed failures: %s", body)
	}
	var decoded queue.PublishOutcome
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode v2 outcome: %v", err)
	}
	if !decoded.Partial || decoded.SelectedQueues != 2 || decoded.FailedDeliveries != 3 || decoded.FailedDestinations != 1 {
		t.Fatalf("decoded compact outcome = %#v", decoded)
	}
	if applier.calls != 1 {
		t.Fatalf("v2 Apply calls = %d, want 1", applier.calls)
	}
}

func TestV1ForwardPreservesLegacyPublishSemantics(t *testing.T) {
	t.Run("full success is PublishResponse", func(t *testing.T) {
		applier := &stubApplier{response: &queue.PublishOutcome{
			Response: &queue.PublishResponse{TopicID: "topicone", QueueIDs: []string{"queueone"}},
		}}
		server := newTestServer(t, applier, &stubMembership{}, "")
		resp := post(t, server, http.MethodPost, "/v1/forward", "", "publish-command")
		body, err := io.ReadAll(resp.Body)
		td.Require(t).CmpNoError(err)
		var legacy queue.PublishResponse
		if err := json.Unmarshal(body, &legacy); err != nil {
			t.Fatalf("decode legacy success: %v", err)
		}
		if resp.StatusCode != http.StatusOK || legacy.TopicID != "topicone" {
			t.Fatalf("legacy full status/response = %d/%#v", resp.StatusCode, legacy)
		}
		if applier.calls != 1 {
			t.Fatalf("legacy full Apply calls = %d, want 1", applier.calls)
		}
	})

	t.Run("partial is terminal legacy error", func(t *testing.T) {
		applier := &stubApplier{response: &queue.PublishOutcome{Partial: true}}
		server := newTestServer(t, applier, &stubMembership{}, "")
		resp := post(t, server, http.MethodPost, "/v1/forward", "", "publish-command")
		body, err := io.ReadAll(resp.Body)
		td.Require(t).CmpNoError(err)
		if resp.StatusCode != http.StatusInternalServerError || resp.Header.Get(errorHeader) != "partial-fanout" {
			t.Fatalf("legacy partial status/class = %d/%q", resp.StatusCode, resp.Header.Get(errorHeader))
		}
		if len(body) != 0 {
			t.Fatalf("legacy partial body = %q, want empty", body)
		}
		if applier.calls != 1 {
			t.Fatalf("legacy partial Apply calls = %d, want 1", applier.calls)
		}
	})
}

func TestNewFollowerFallsBackToLegacyLeaderExactlyOnce(t *testing.T) {
	encoded, err := (&command.Command{
		Op:      command.OpPublish,
		Target:  "topicone",
		Payload: []byte(`{"messages":[{"body":"aGk="}]}`),
	}).Encode()
	td.Require(t).CmpNoError(err)

	for _, partialResult := range []bool{false, true} {
		name := "full"
		if partialResult {
			name = "partial"
		}
		t.Run(name, func(t *testing.T) {
			applyCalls := 0
			legacy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/forward" {
					http.NotFound(w, r)
					return
				}
				applyCalls++
				if partialResult {
					w.Header().Set(errorHeader, "partial-fanout")
					http.Error(w, "partial topic fan-out", http.StatusInternalServerError)
					return
				}
				_ = json.NewEncoder(w).Encode(&queue.PublishResponse{
					TopicID: "topicone", QueueIDs: []string{"queueone"}, MessageIDs: []string{"01J00000000000000000000000"}, DeliveredCount: 1,
				})
			}))
			t.Cleanup(legacy.Close)
			client := &Client{http: legacy.Client()}

			raw, forwardErr := client.Forward(
				context.Background(), strings.TrimPrefix(legacy.URL, "http://"), encoded,
			)
			if partialResult {
				var partial *queue.PartialPublishError
				if !errors.As(forwardErr, &partial) || !partial.Outcome.Partial ||
					partial.Outcome.FailedDeliveries != 0 || partial.Outcome.FailedDestinations != 0 {
					t.Fatalf("legacy partial Forward() = %v, want typed conservative partial", forwardErr)
				}
			} else {
				if forwardErr != nil {
					t.Fatalf("legacy full Forward() = %v", forwardErr)
				}
				var outcome queue.PublishOutcome
				if err := json.Unmarshal(raw, &outcome); err != nil {
					t.Fatalf("decode converted outcome: %v", err)
				}
				if outcome.Response == nil || outcome.Response.TopicID != "topicone" || outcome.Partial {
					t.Fatalf("converted legacy outcome = %#v", outcome)
				}
			}
			if applyCalls != 1 {
				t.Fatalf("legacy leader Apply calls = %d, want 1", applyCalls)
			}
		})
	}
}

func TestNewFollowerDoesNotFallbackOnApplicationNotFound(t *testing.T) {
	v1Calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/forward" {
			v1Calls++
		}
		w.Header().Set(errorHeader, "not-found")
		http.Error(w, "topic missing", http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	client := &Client{http: server.Client()}

	_, err := client.Forward(context.Background(), strings.TrimPrefix(server.URL, "http://"), []byte("command"))
	if !errors.Is(err, pqerr.ErrNotFound) {
		t.Fatalf("Forward() = %v, want not found", err)
	}
	if v1Calls != 0 {
		t.Fatalf("application NotFound triggered %d v1 fallback calls", v1Calls)
	}
}

func TestPublishIdentifierWireFitsDerivedResponseCeiling(t *testing.T) {
	queueID := "c5s8b4p9e8rg5u5fgq10"
	messageID := queue.NewBatchIDs(time.Unix(1_700_000_000, 0).UTC())()
	if len(queueID) != publishwire.QueueIDLength || len(messageID) != publishwire.MessageIDLength {
		t.Fatalf("test XID/ULID lengths = %d/%d, want %d/%d",
			len(queueID), len(messageID), publishwire.QueueIDLength, publishwire.MessageIDLength)
	}

	for _, count := range []int{1, 10, 10_000} {
		queueIDs := make([]string, count)
		messageIDs := make([]string, count)
		for i := range count {
			queueIDs[i] = queueID
			messageIDs[i] = messageID
		}
		queueJSON, err := json.Marshal(queueIDs)
		td.Require(t).CmpNoError(err)
		messageJSON, err := json.Marshal(messageIDs)
		td.Require(t).CmpNoError(err)

		commandIDsBytes := uvarintBytes(uint64(count)) + count*(uvarintBytes(uint64(len(messageID)))+len(messageID))
		if got, limit := len(queueJSON)+len(messageJSON), 2*commandIDsBytes; got >= limit {
			t.Fatalf("%d QueueID+MessageID JSON bytes = %d, want < 2x command ID bytes (%d)",
				count, got, limit)
		}

		encodedOutcome, err := json.Marshal(compactPublishOutcomeFrom(&queue.PublishOutcome{
			Response: &queue.PublishResponse{
				TopicID:        queueID,
				QueueIDs:       queueIDs,
				MessageIDs:     messageIDs,
				DeliveredCount: count,
			},
			Partial:            true,
			SelectedQueues:     math.MaxUint64,
			FailedDeliveries:   math.MaxUint64,
			FailedDestinations: math.MaxUint64,
		}))
		td.Require(t).CmpNoError(err)
		bound, fits := publishwire.FitsCompactOutcome(uint64(count), 1, publishwire.MaxResponseBytes)
		if !fits || uint64(len(encodedOutcome)) > bound {
			t.Fatalf("%d-destination compact outcome bytes/bound = %d/%d, fits=%t",
				count, len(encodedOutcome), bound, fits)
		}
	}
	if publishwire.MaxResponseBytes != 2*command.MaxEncodedBytes+publishwire.FramingBytes {
		t.Fatalf("MaxResponseBytes = %d, want derived ceiling", publishwire.MaxResponseBytes)
	}
}

func uvarintBytes(value uint64) int {
	var encoded [binary.MaxVarintLen64]byte
	return binary.PutUvarint(encoded[:], value)
}

func TestAuthenticatedFollowerCarriesKnownPublishOutcomeLargerThanCommandLimit(t *testing.T) {
	const queueID = "c5s8b4p9e8rg5u5fgq10"
	messageID := queue.NewBatchIDs(time.Unix(1_700_000_000, 0).UTC())()
	count := command.MaxEncodedBytes/52 + 128
	messageIDs := make([]string, count)
	queueIDs := make([]string, count)
	for i := range count {
		messageIDs[i] = messageID
		queueIDs[i] = queueID
	}
	payload, err := (&command.Command{
		Op:      command.OpPublish,
		Target:  "c5s8b4p9e8rg5u5fgq11",
		IDs:     messageIDs,
		Payload: []byte(`{"messages":[{"body":"aA=="}]}`),
	}).Encode()
	td.Require(t).CmpNoError(err)
	if len(payload) >= command.MaxEncodedBytes {
		t.Fatalf("accepted command fixture = %d bytes, want under %d", len(payload), command.MaxEncodedBytes)
	}

	applier := &stubApplier{response: &queue.PublishOutcome{Response: &queue.PublishResponse{
		TopicID: "c5s8b4p9e8rg5u5fgq11", QueueIDs: queueIDs, MessageIDs: messageIDs, DeliveredCount: count,
	}}}
	server := newTestServer(t, applier, &stubMembership{}, "shared-secret")
	client := &Client{http: server.Client(), secret: "shared-secret"}
	raw, err := client.Forward(context.Background(), strings.TrimPrefix(server.URL, "http://"), payload)
	if err != nil {
		t.Fatalf("Forward() large known outcome = %v", err)
	}
	if len(raw) <= command.MaxEncodedBytes || len(raw) > publishwire.MaxResponseBytes {
		t.Fatalf("known response bytes = %d, want (%d, %d]",
			len(raw), command.MaxEncodedBytes, publishwire.MaxResponseBytes)
	}
	if !json.Valid(raw) {
		t.Fatal("large known outcome was truncated or malformed")
	}
	if got := bytes.Count(raw, []byte(queueID)); got != count {
		t.Fatalf("carried queue IDs = %d, want %d", got, count)
	}
	if got := bytes.Count(raw, []byte(messageID)); got != count {
		t.Fatalf("carried message IDs = %d, want %d", got, count)
	}
	if applier.calls != 1 {
		t.Fatalf("large known outcome Apply calls = %d, want 1", applier.calls)
	}
}

func TestBuggyPeerResponseOverflowIsFiniteAndTerminal(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write(bytes.Repeat([]byte("x"), 65))
	}))
	t.Cleanup(server.Close)
	client := &Client{http: server.Client(), responseLimit: 64}

	_, err := client.Forward(context.Background(), strings.TrimPrefix(server.URL, "http://"), []byte("command"))
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("Forward() buggy response = %v, want response-too-large", err)
	}
	if errors.Is(err, consensus.ErrNotLeader) || errors.Is(err, pqerr.ErrUnavailable) {
		t.Fatalf("response overflow = %v, must remain terminal", err)
	}
	if calls != 1 {
		t.Fatalf("buggy peer calls = %d, want 1 with no fallback/retry", calls)
	}
}

func TestServerRejectsResponseOverflowBeforeWritingSuccessStatus(t *testing.T) {
	applier := &stubApplier{response: &vtResponse{payload: bytes.Repeat([]byte("x"), 65)}}
	server := NewServer(ServerConfig{Applier: applier, Membership: &stubMembership{}})
	server.responseLimit = 64
	req := httptest.NewRequest(http.MethodPost, "/v2/forward", strings.NewReader("command"))
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError || w.Header().Get(errorHeader) != "response-too-large" {
		t.Fatalf("response overflow status/class = %d/%q, want 500/response-too-large",
			w.Code, w.Header().Get(errorHeader))
	}
	if applier.calls != 1 {
		t.Fatalf("response overflow Apply calls = %d, want 1 known committed outcome", applier.calls)
	}
}

func TestJoinAddsAMember(t *testing.T) {
	membership := &stubMembership{status: consensus.Status{NodeID: "leader-1"}}
	server := newTestServer(t, &stubApplier{}, membership, "")

	resp := post(t, server, http.MethodPost, "/v1/join", "",
		`{"nodeId": "node-2", "address": "10.0.0.2:8082"}`,
	)
	td.Cmp(t, resp.StatusCode, http.StatusOK)
	td.Cmp(t, membership.added, []string{"node-2@10.0.0.2:8082"})

	resp = post(t, server, http.MethodPost, "/v1/join", "",
		`{"nodeId": "node-3", "address": "10.0.0.3:8082", "nonVoter": true}`,
	)
	td.Cmp(t, resp.StatusCode, http.StatusOK)
	td.Cmp(t, membership.nonVoter, []string{"node-3@10.0.0.3:8082"})
}

func TestJoinRequiresIdentityAndAddress(t *testing.T) {
	membership := &stubMembership{}
	server := newTestServer(t, &stubApplier{}, membership, "")

	resp := post(t, server, http.MethodPost, "/v1/join", "", `{"nodeId": "node-2"}`)
	td.Cmp(t, resp.StatusCode, http.StatusBadRequest)

	resp = post(t, server, http.MethodPost, "/v1/join", "", `not json`)
	td.Cmp(t, resp.StatusCode, http.StatusBadRequest)

	td.Cmp(t, membership.added, td.Nil())
}

// A join asked of a follower must fail with the class the caller can act on,
// so it moves along to the next peer instead of giving up.
func TestJoinOnAFollowerReportsNotLeader(t *testing.T) {
	membership := &stubMembership{err: consensus.ErrNotLeader}
	server := newTestServer(t, &stubApplier{}, membership, "")

	resp := post(t, server, http.MethodPost, "/v1/join", "",
		`{"nodeId": "node-2", "address": "10.0.0.2:8082"}`,
	)

	td.Cmp(t, resp.StatusCode, http.StatusServiceUnavailable)
	td.Cmp(t, resp.Header.Get(errorHeader), "not-leader")
}

func TestLeaveRemovesAMember(t *testing.T) {
	membership := &stubMembership{}
	server := newTestServer(t, &stubApplier{}, membership, "")

	resp := post(t, server, http.MethodPost, "/v1/leave", "", `{"nodeId": "node-2"}`)

	td.Cmp(t, resp.StatusCode, http.StatusOK)
	td.Cmp(t, membership.removed, []string{"node-2"})
}

func TestStatusIsReported(t *testing.T) {
	membership := &stubMembership{status: consensus.Status{NodeID: "node-1", State: consensus.StateLeader}}
	server := newTestServer(t, &stubApplier{}, membership, "")

	resp := post(t, server, http.MethodGet, "/v1/status", "", "")

	td.Cmp(t, resp.StatusCode, http.StatusOK)
	td.Cmp(t, resp.Header.Get("Content-Type"), "application/json")
}
