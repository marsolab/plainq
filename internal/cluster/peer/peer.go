// Package peer carries the internal RPC between PlainQ cluster nodes.
//
// It exists for one reason above all: only the leader can commit a write, but
// a client may talk to any node. Rather than redirect the client — which
// leaks cluster topology into every SDK and every load balancer — a follower
// hands the command to the leader itself and returns the leader's answer as
// its own.
//
// The protocol is HTTP over the cluster port, authenticated by a shared
// secret. It is internal: nothing here is a public API, and no user
// credentials cross it.
package peer

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/cluster/consensus"
	"github.com/marsolab/plainq/internal/cluster/transport"
	"github.com/marsolab/plainq/internal/metrics"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/logkit"
)

// secretHeader carries the cluster shared secret.
const secretHeader = "X-Plainq-Cluster-Secret" //nolint:gosec // header name, not a credential.

// errorHeader carries a machine-readable error class alongside the status, so
// a forwarded pqerr keeps its meaning across the hop instead of collapsing
// into "the leader said no".
const errorHeader = "X-Plainq-Cluster-Error"

// requestTimeout bounds a peer call. It is generous — the leader may be
// committing to a majority — but finite, because a follower blocked forever on
// a peer is a follower that has stopped answering its own clients.
const requestTimeout = 30 * time.Second

// maxRequestBytes caps a forwarded command. It matches the largest Send a
// client can make plus framing.
const maxRequestBytes = 64 << 20

// Applier is what the peer server hands a forwarded command to. It is the
// consensus engine, narrowed to the one method this package needs.
type Applier interface {
	Apply(ctx context.Context, data []byte) (any, error)
}

// Membership is the part of the cluster a peer can change: who is in it.
type Membership interface {
	AddVoter(ctx context.Context, id, addr string) error
	AddNonVoter(ctx context.Context, id, addr string) error
	RemoveServer(ctx context.Context, id string) error
	Status() consensus.Status
}

// JoinRequest is a node asking to be admitted to the cluster.
type JoinRequest struct {
	// NodeID is the joining node's identity.
	NodeID string `json:"nodeId"`

	// Addr is its cluster address.
	Addr string `json:"address"`

	// NonVoter asks to replicate without voting.
	NonVoter bool `json:"nonVoter,omitempty"`
}

// JoinResponse reports the outcome of a join.
type JoinResponse struct {
	// LeaderID is the node that admitted the joiner.
	LeaderID string `json:"leaderId"`

	// Servers is the configuration after the change.
	Servers []consensus.Server `json:"servers"`
}

// Server answers peer RPC on the cluster port.
type Server struct {
	applier    Applier
	membership Membership
	secret     []byte
	logger     *slog.Logger

	http   *http.Server
	router chi.Router
}

// ServerConfig configures a peer Server.
type ServerConfig struct {
	// Applier commits forwarded commands.
	Applier Applier

	// Membership admits and removes nodes.
	Membership Membership

	// Secret authenticates peers. An empty secret leaves the cluster port
	// unauthenticated, which is only acceptable on a trusted network — the
	// server config validation says so at startup.
	Secret string

	// Logger receives diagnostics.
	Logger *slog.Logger
}

// NewServer builds the peer RPC server.
func NewServer(cfg ServerConfig) *Server {
	logger := cfg.Logger
	if logger == nil {
		logger = logkit.NewNop()
	}

	s := Server{
		applier:    cfg.Applier,
		membership: cfg.Membership,
		secret:     []byte(cfg.Secret),
		logger:     logger,
		router:     chi.NewRouter(),
	}

	s.router.Route("/v1", func(r chi.Router) {
		r.Use(observe)
		r.Use(s.authenticate)

		r.Post("/forward", s.forwardHandler)
		r.Post("/join", s.joinHandler)
		r.Post("/leave", s.leaveHandler)
		r.Get("/status", s.statusHandler)
	})

	s.http = &http.Server{
		Handler:           s.router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       requestTimeout,
		WriteTimeout:      requestTimeout,
		IdleTimeout:       120 * time.Second,
	}

	return &s
}

// Serve answers peer RPC on the listener until it is closed.
func (s *Server) Serve(listener net.Listener) error {
	if err := s.http.Serve(listener); err != nil &&
		!errors.Is(err, http.ErrServerClosed) && !errors.Is(err, transport.ErrClosed) {
		return fmt.Errorf("serve cluster peer RPC: %w", err)
	}

	return nil
}

// Shutdown stops answering peer RPC.
func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.http.Shutdown(ctx); err != nil {
		return fmt.Errorf("shut down cluster peer RPC: %w", err)
	}

	return nil
}

// authenticate rejects callers that do not hold the cluster secret.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.secret) == 0 {
			next.ServeHTTP(w, r)

			return
		}

		presented := []byte(r.Header.Get(secretHeader))

		// Constant-time, and only after a length check that is itself
		// constant-time by construction — subtle.ConstantTimeCompare returns 0
		// for mismatched lengths without branching on content.
		if subtle.ConstantTimeCompare(presented, s.secret) != 1 {
			metrics.RecordPeerAuthFailure()

			s.logger.Warn("Rejected a cluster peer with an invalid secret",
				slog.String("remote", r.RemoteAddr),
				slog.String("path", r.URL.Path),
			)

			http.Error(w, "invalid cluster secret", http.StatusUnauthorized)

			return
		}

		next.ServeHTTP(w, r)
	})
}

// observe records every peer RPC this node served.
//
// The route pattern is the label, not the path, and the peer's identity is
// not a label at all: a cluster is a handful of nodes, but the useful question
// here is whether the internal RPC surface is working, not which peer asked.
func observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(recorder, r)

		var err error
		if recorder.status >= http.StatusBadRequest {
			err = errPeerRequestFailed
		}

		path := r.URL.Path
		if ctx := chi.RouteContext(r.Context()); ctx != nil && ctx.RoutePattern() != "" {
			path = ctx.RoutePattern()
		}

		metrics.RecordPeerRequest(path, start, err)
	})
}

// errPeerRequestFailed marks a peer RPC that answered with an error status. It
// never leaves this file — it exists so the recorder can express "this one
// failed" in the same vocabulary every other subsystem uses.
var errPeerRequestFailed = errors.New("peer request failed")

// statusRecorder remembers the status code a handler wrote.
type statusRecorder struct {
	http.ResponseWriter

	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// forwardHandler commits a command a follower could not commit itself.
func (s *Server) forwardHandler(w http.ResponseWriter, r *http.Request) {
	payload, readErr := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes))
	if readErr != nil {
		http.Error(w, "read forwarded command: "+readErr.Error(), http.StatusBadRequest)

		return
	}

	response, applyErr := s.applier.Apply(r.Context(), payload)
	if applyErr != nil {
		s.writeApplyError(w, applyErr)

		return
	}

	encoded, encodeErr := encodeResponse(response)
	if encodeErr != nil {
		s.logger.Error("Failed to encode a forwarded response",
			slog.String("error", encodeErr.Error()),
		)

		http.Error(w, encodeErr.Error(), http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(encoded); err != nil {
		s.logger.Debug("Failed to write a forwarded response",
			slog.String("error", err.Error()),
		)
	}
}

// writeApplyError translates a failed apply into a status the caller can act
// on. The distinction that matters most is "not the leader": the follower that
// asked has to know to look up the leader again rather than treat the write as
// failed.
func (s *Server) writeApplyError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	class := "internal"

	switch {
	case errors.Is(err, consensus.ErrNotLeader), errors.Is(err, consensus.ErrNoLeader):
		status, class = http.StatusServiceUnavailable, "not-leader"

	case errors.Is(err, consensus.ErrShutdown):
		status, class = http.StatusServiceUnavailable, "shutdown"

	case errors.Is(err, pqerr.ErrNotFound), errors.Is(err, errkit.ErrNotFound):
		status, class = http.StatusNotFound, "not-found"

	case errors.Is(err, pqerr.ErrAlreadyExists), errors.Is(err, errkit.ErrAlreadyExists):
		status, class = http.StatusConflict, "already-exists"

	case errors.Is(err, pqerr.ErrInvalidInput), errors.Is(err, pqerr.ErrInvalidID),
		errors.Is(err, errkit.ErrInvalidArgument):
		status, class = http.StatusBadRequest, "invalid-argument"
	}

	w.Header().Set(errorHeader, class)
	http.Error(w, err.Error(), status)
}

// joinHandler admits a node to the cluster configuration.
func (s *Server) joinHandler(w http.ResponseWriter, r *http.Request) {
	var request JoinRequest

	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&request); err != nil {
		http.Error(w, "decode join request: "+err.Error(), http.StatusBadRequest)

		return
	}

	if request.NodeID == "" || request.Addr == "" {
		http.Error(w, "join request needs both a node id and an address", http.StatusBadRequest)

		return
	}

	var err error

	if request.NonVoter {
		err = s.membership.AddNonVoter(r.Context(), request.NodeID, request.Addr)
	} else {
		err = s.membership.AddVoter(r.Context(), request.NodeID, request.Addr)
	}

	if err != nil {
		s.writeApplyError(w, err)

		return
	}

	status := s.membership.Status()

	s.logger.Info("Admitted a node to the cluster",
		slog.String("node_id", request.NodeID),
		slog.String("address", request.Addr),
		slog.Bool("non_voter", request.NonVoter),
	)

	writeJSON(w, http.StatusOK, JoinResponse{LeaderID: status.NodeID, Servers: status.Servers})
}

// leaveHandler removes a node from the cluster configuration.
func (s *Server) leaveHandler(w http.ResponseWriter, r *http.Request) {
	var request JoinRequest

	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&request); err != nil {
		http.Error(w, "decode leave request: "+err.Error(), http.StatusBadRequest)

		return
	}

	if request.NodeID == "" {
		http.Error(w, "leave request needs a node id", http.StatusBadRequest)

		return
	}

	if err := s.membership.RemoveServer(r.Context(), request.NodeID); err != nil {
		s.writeApplyError(w, err)

		return
	}

	s.logger.Info("Removed a node from the cluster",
		slog.String("node_id", request.NodeID),
	)

	writeJSON(w, http.StatusOK, s.membership.Status())
}

// statusHandler reports this node's view of the cluster.
func (s *Server) statusHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.membership.Status())
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	// The status line is already on the wire, so a failed encode has nowhere
	// to be reported to the caller. It means the peer hung up.
	_ = json.NewEncoder(w).Encode(value) //nolint:errcheck,errchkjson // see above.
}

// encodeResponse renders a state machine response for the wire.
//
// Schema types carry their own codec; everything else is JSON. The caller
// knows which to expect from the command it sent, so no tag is needed.
func encodeResponse(response any) ([]byte, error) {
	if response == nil {
		return nil, nil
	}

	if marshaler, ok := response.(interface{ MarshalVT() ([]byte, error) }); ok {
		encoded, err := marshaler.MarshalVT()
		if err != nil {
			return nil, fmt.Errorf("encode response: %w", err)
		}

		return encoded, nil
	}

	encoded, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("encode response: %w", err)
	}

	return encoded, nil
}

// Client calls another node's peer RPC.
type Client struct {
	mux    *transport.Mux
	secret string
	http   *http.Client
}

// NewClient builds a peer client that dials through the cluster mux, so peer
// RPC and consensus share one port and one TLS configuration.
func NewClient(mux *transport.Mux, secret string) *Client {
	// The mux dials with a timeout rather than a context; the caller's deadline
	// is translated into one here, which is the whole contract it can honor.
	//nolint:contextcheck // see above.
	dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
		timeout := requestTimeout

		if deadline, ok := ctx.Deadline(); ok {
			if remaining := time.Until(deadline); remaining > 0 {
				timeout = remaining
			}
		}

		return mux.Dial(transport.ProtoPeer, addr, timeout)
	}

	return &Client{
		mux:    mux,
		secret: secret,
		http: &http.Client{
			Timeout:   requestTimeout,
			Transport: &http.Transport{DialContext: dial, DisableCompression: true},
		},
	}
}

// Forward sends an encoded command to the leader and returns its response.
func (c *Client) Forward(ctx context.Context, addr string, payload []byte) ([]byte, error) {
	body, err := c.do(ctx, http.MethodPost, addr, "/v1/forward", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}

	return body, nil
}

// Join asks the node at addr to admit this node to the cluster.
func (c *Client) Join(ctx context.Context, addr string, request JoinRequest) (*JoinResponse, error) {
	encoded, encodeErr := json.Marshal(request)
	if encodeErr != nil {
		return nil, fmt.Errorf("encode join request: %w", encodeErr)
	}

	body, err := c.do(ctx, http.MethodPost, addr, "/v1/join", "application/json", bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}

	var response JoinResponse

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("decode join response: %w", err)
	}

	return &response, nil
}

// Leave asks the node at addr to remove nodeID from the cluster.
func (c *Client) Leave(ctx context.Context, addr, nodeID string) error {
	encoded, encodeErr := json.Marshal(JoinRequest{NodeID: nodeID})
	if encodeErr != nil {
		return fmt.Errorf("encode leave request: %w", encodeErr)
	}

	_, err := c.do(ctx, http.MethodPost, addr, "/v1/leave", "application/json", bytes.NewReader(encoded))

	return err
}

// Status fetches another node's view of the cluster.
func (c *Client) Status(ctx context.Context, addr string) (*consensus.Status, error) {
	body, err := c.do(ctx, http.MethodGet, addr, "/v1/status", "", nil)
	if err != nil {
		return nil, err
	}

	var status consensus.Status

	if err := json.Unmarshal(body, &status); err != nil {
		return nil, fmt.Errorf("decode peer status: %w", err)
	}

	return &status, nil
}

func (c *Client) do(ctx context.Context, method, addr, path, contentType string, body io.Reader) ([]byte, error) {
	// The host in the URL is what the dialer receives, so peers are addressed
	// by their cluster address rather than by a name that would need resolving
	// twice.
	url := "http://" + addr + path

	req, reqErr := http.NewRequestWithContext(ctx, method, url, body)
	if reqErr != nil {
		return nil, fmt.Errorf("build peer request: %w", reqErr)
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	if c.secret != "" {
		req.Header.Set(secretHeader, c.secret)
	}

	resp, doErr := c.http.Do(req)
	if doErr != nil {
		return nil, fmt.Errorf("call peer %s: %w", addr, doErr)
	}

	defer closeResponse(resp)

	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxRequestBytes))
	if readErr != nil {
		return nil, fmt.Errorf("read peer response from %s: %w", addr, readErr)
	}

	if resp.StatusCode == http.StatusOK {
		return responseBody, nil
	}

	return nil, peerError(addr, resp, responseBody)
}

// closeResponse drains and closes a response body so the connection returns to
// the pool. Neither result is actionable — the call already has its answer.
func closeResponse(resp *http.Response) {
	//nolint:errcheck,dogsled // draining is best-effort connection reuse.
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// peerError rebuilds an error the remote node reported, keeping the class it
// traveled with so `errors.Is` still works on this side of the hop.
func peerError(addr string, resp *http.Response, body []byte) error {
	message := strings.TrimSpace(string(body))
	if message == "" {
		message = resp.Status
	}

	base := fmt.Errorf("peer %s: %s", addr, message)

	switch resp.Header.Get(errorHeader) {
	case "not-leader":
		return fmt.Errorf("%w: %w", consensus.ErrNotLeader, base)

	case "shutdown":
		return fmt.Errorf("%w: %w", consensus.ErrShutdown, base)

	case "not-found":
		return fmt.Errorf("%w: %w", pqerr.ErrNotFound, base)

	case "already-exists":
		return fmt.Errorf("%w: %w", pqerr.ErrAlreadyExists, base)

	case "invalid-argument":
		return fmt.Errorf("%w: %w", pqerr.ErrInvalidInput, base)

	default:
		return base
	}
}
