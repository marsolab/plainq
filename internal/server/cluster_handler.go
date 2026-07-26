package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/cluster"
	"github.com/marsolab/plainq/internal/cluster/consensus"
)

// clusterOpTimeout bounds a membership change made through the API. It is
// short on purpose: an operator waiting on a curl should get an answer, and a
// membership change that cannot complete quickly has something else wrong with
// it.
const clusterOpTimeout = 20 * time.Second

// ClusterNode is the part of a cluster node this handler needs. Taking an
// interface keeps the HTTP layer testable without standing up consensus.
type ClusterNode interface {
	Status() cluster.Status
	Join(ctx context.Context, nodeID, addr string, nonVoter bool) error
	Remove(ctx context.Context, nodeID string) error
	Snapshot(ctx context.Context) error
}

// ClusterHandler answers the cluster API.
//
// It is the honest view of a distributed system: what this node believes, not
// what the cluster wishes were true. A follower reports itself as a follower
// and names the leader; it does not proxy the question and pretend to be
// authoritative.
type ClusterHandler struct {
	node   ClusterNode
	logger *slog.Logger
}

// NewClusterHandler returns a handler over the given node.
func NewClusterHandler(node ClusterNode, logger *slog.Logger) *ClusterHandler {
	return &ClusterHandler{node: node, logger: logger}
}

// Routes mounts the cluster API.
func (h *ClusterHandler) Routes(r chi.Router) {
	r.Get("/", h.status)
	r.Get("/members", h.members)
	r.Post("/members", h.join)
	r.Delete("/members/{id}", h.remove)
	r.Post("/snapshot", h.snapshot)
}

func (h *ClusterHandler) status(w http.ResponseWriter, _ *http.Request) {
	writeClusterJSON(w, http.StatusOK, h.node.Status())
}

func (h *ClusterHandler) members(w http.ResponseWriter, _ *http.Request) {
	status := h.node.Status()

	writeClusterJSON(w, http.StatusOK, map[string]any{
		"members": status.Members,
		"quorum":  status.Quorum,
		"voters":  status.Voters,
		"healthy": status.Healthy,
	})
}

// joinRequest is an operator adding a node by hand — the escape hatch for a
// cluster that discovery cannot see, or that an operator would rather assemble
// deliberately.
type joinRequest struct {
	NodeID   string `json:"nodeId"`
	Addr     string `json:"address"`
	NonVoter bool   `json:"nonVoter,omitempty"`
}

func (h *ClusterHandler) join(w http.ResponseWriter, r *http.Request) {
	var request joinRequest

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		writeClusterError(w, http.StatusBadRequest, "decode request: "+err.Error())

		return
	}

	if request.NodeID == "" || request.Addr == "" {
		writeClusterError(w, http.StatusBadRequest, "both nodeId and address are required")

		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), clusterOpTimeout)
	defer cancel()

	if err := h.node.Join(ctx, request.NodeID, request.Addr, request.NonVoter); err != nil {
		h.writeNodeError(w, err)

		return
	}

	writeClusterJSON(w, http.StatusOK, h.node.Status())
}

func (h *ClusterHandler) remove(w http.ResponseWriter, r *http.Request) {
	nodeID := chi.URLParam(r, "id")
	if nodeID == "" {
		writeClusterError(w, http.StatusBadRequest, "a node id is required")

		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), clusterOpTimeout)
	defer cancel()

	if err := h.node.Remove(ctx, nodeID); err != nil {
		h.writeNodeError(w, err)

		return
	}

	writeClusterJSON(w, http.StatusOK, h.node.Status())
}

func (h *ClusterHandler) snapshot(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), clusterOpTimeout)
	defer cancel()

	if err := h.node.Snapshot(ctx); err != nil {
		h.writeNodeError(w, err)

		return
	}

	writeClusterJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// writeNodeError turns a cluster failure into a status an operator can act on.
// "Not the leader" is the one that matters: it is not an error so much as an
// instruction about where to ask.
func (h *ClusterHandler) writeNodeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, consensus.ErrNotLeader):
		status := h.node.Status()

		writeClusterJSON(w, http.StatusConflict, map[string]any{
			"error":         "this node is not the cluster leader",
			"leaderId":      status.LeaderID,
			"leaderAddress": status.LeaderAddr,
		})

	case errors.Is(err, consensus.ErrNoLeader):
		writeClusterError(w, http.StatusServiceUnavailable,
			"the cluster has no leader right now; an election is in progress or quorum is lost",
		)

	default:
		h.logger.Error("Cluster API request failed",
			slog.String("error", err.Error()),
		)

		writeClusterError(w, http.StatusInternalServerError, err.Error())
	}
}

func writeClusterJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(value)
}

func writeClusterError(w http.ResponseWriter, status int, message string) {
	writeClusterJSON(w, status, map[string]string{"error": message})
}

// disabledClusterHandler answers when the server is not clustered.
//
// Answering 404 would be a lie by omission — the route exists, the feature is
// simply off — and a dashboard cannot tell "old server" from "single node"
// out of a 404. A 200 saying "not enabled" is the useful answer.
func disabledClusterHandler(w http.ResponseWriter, _ *http.Request) {
	writeClusterJSON(w, http.StatusOK, cluster.Status{Enabled: false})
}
