package peer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marsolab/plainq/internal/cluster/consensus"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/maxatome/go-testdeep/td"
)

// stubApplier is a consensus engine with a scripted answer.
type stubApplier struct {
	response any
	err      error
	seen     []byte
}

func (s *stubApplier) Apply(_ context.Context, data []byte) (any, error) {
	s.seen = append([]byte(nil), data...)

	return s.response, s.err
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
		"not leader":     {err: consensus.ErrNotLeader, status: http.StatusServiceUnavailable, class: "not-leader"},
		"no leader":      {err: consensus.ErrNoLeader, status: http.StatusServiceUnavailable, class: "not-leader"},
		"shut down":      {err: consensus.ErrShutdown, status: http.StatusServiceUnavailable, class: "shutdown"},
		"not found":      {err: pqerr.ErrNotFound, status: http.StatusNotFound, class: "not-found"},
		"already exists": {err: pqerr.ErrAlreadyExists, status: http.StatusConflict, class: "already-exists"},
		"invalid input":  {err: pqerr.ErrInvalidInput, status: http.StatusBadRequest, class: "invalid-argument"},
		"anything else":  {err: errors.New("disk on fire"), status: http.StatusInternalServerError, class: "internal"},
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
		"not-leader":       {class: "not-leader", target: consensus.ErrNotLeader},
		"shutdown":         {class: "shutdown", target: consensus.ErrShutdown},
		"not-found":        {class: "not-found", target: pqerr.ErrNotFound},
		"already-exists":   {class: "already-exists", target: pqerr.ErrAlreadyExists},
		"invalid-argument": {class: "invalid-argument", target: pqerr.ErrInvalidInput},
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

// A schema response carries its own codec; anything else is JSON. The caller
// knows which to expect from the command it sent, so nothing has to be tagged.
func TestEncodeResponse(t *testing.T) {
	encoded, err := encodeResponse(&vtResponse{payload: []byte{1, 2, 3}})
	td.Require(t).CmpNoError(err)
	td.Cmp(t, encoded, []byte{1, 2, 3}, "a schema response uses its own encoding")

	encoded, err = encodeResponse(map[string]string{"topicId": "t1"})
	td.Require(t).CmpNoError(err)
	td.Cmp(t, string(encoded), `{"topicId":"t1"}`)

	encoded, err = encodeResponse(nil)
	td.Require(t).CmpNoError(err)
	td.Cmp(t, encoded, td.Nil(), "a command with no response sends no body")
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
