package plainqapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Suffrage values as the consensus layer spells them.
const (
	SuffrageVoter    = "voter"
	SuffrageNonVoter = "non-voter"
	SuffrageStaging  = "staging"
)

// ClusterStatus is one node's view of the cluster: what consensus agreed and
// what gossip can see, side by side.
type ClusterStatus struct {
	Enabled    bool   `json:"enabled"`
	NodeID     string `json:"nodeId"`
	State      string `json:"state"`
	LeaderID   string `json:"leaderId"`
	LeaderAddr string `json:"leaderAddress"`

	Term         uint64 `json:"term"`
	CommitIndex  uint64 `json:"commitIndex"`
	AppliedIndex uint64 `json:"appliedIndex"`
	LastIndex    uint64 `json:"lastIndex"`

	LastContact string `json:"lastContact,omitempty"`
	Engine      string `json:"engine"`

	Members []ClusterMember `json:"members"`

	Quorum  int  `json:"quorum"`
	Voters  int  `json:"voters"`
	Healthy bool `json:"healthy"`

	AppliedCommands uint64 `json:"appliedCommands"`
	FailedCommands  uint64 `json:"failedCommands"`
}

// ClusterMember is one node as both layers see it.
type ClusterMember struct {
	ID         string `json:"id"`
	Addr       string `json:"address"`
	GossipAddr string `json:"gossipAddress,omitempty"`
	Suffrage   string `json:"suffrage,omitempty"`
	Reachable  bool   `json:"reachable"`
	Leader     bool   `json:"leader"`
	Self       bool   `json:"self"`
	Version    string `json:"version,omitempty"`
}

// IsVoter reports whether the member counts toward quorum.
func (m ClusterMember) IsVoter() bool { return m.Suffrage == SuffrageVoter }

// membersResponse is what GET /api/v1/cluster/members returns.
type membersResponse struct {
	Members []ClusterMember `json:"members"`
	Quorum  int             `json:"quorum"`
	Voters  int             `json:"voters"`
	Healthy bool            `json:"healthy"`
}

// ClusterStatus returns this node's view. Note that it is a *node's* view:
// asking the Service gets whichever pod answered, so a caller that needs a
// specific node must address it directly via ForBaseURL.
func (c *Client) ClusterStatus(ctx context.Context) (*ClusterStatus, error) {
	var status ClusterStatus

	if err := c.do(ctx, request{
		method: http.MethodGet,
		path:   "/api/v1/cluster",
		out:    &status,
	}); err != nil {
		return nil, fmt.Errorf("cluster status: %w", err)
	}

	return &status, nil
}

// ClusterMembers returns the merged membership view.
func (c *Client) ClusterMembers(ctx context.Context) ([]ClusterMember, error) {
	var resp membersResponse

	if err := c.do(ctx, request{
		method: http.MethodGet,
		path:   "/api/v1/cluster/members",
		out:    &resp,
	}); err != nil {
		return nil, fmt.Errorf("cluster members: %w", err)
	}

	return resp.Members, nil
}

// RemoveMember removes a node from the Raft configuration.
//
// This is the call that makes a supervised scale-in different from
// `kubectl scale`: the voter leaves the configuration before the pod leaves
// the cluster, so quorum is recomputed by consensus rather than discovered
// after the fact.
func (c *Client) RemoveMember(ctx context.Context, nodeID string) error {
	err := c.do(ctx, request{
		method: http.MethodDelete,
		path:   "/api/v1/cluster/members/" + url.PathEscape(nodeID),
	})
	if err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("remove member %q: %w", nodeID, err)
	}

	return nil
}

// JoinMember adds a node to the Raft configuration.
func (c *Client) JoinMember(ctx context.Context, nodeID, addr string) error {
	if err := c.do(ctx, request{
		method: http.MethodPost,
		path:   "/api/v1/cluster/members",
		body:   map[string]string{"nodeId": nodeID, "address": addr},
	}); err != nil {
		return fmt.Errorf("join member %q: %w", nodeID, err)
	}

	return nil
}

// Snapshot forces a state snapshot, compacting the consensus log.
func (c *Client) Snapshot(ctx context.Context) error {
	if err := c.do(ctx, request{
		method: http.MethodPost,
		path:   "/api/v1/cluster/snapshot",
	}); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}

	return nil
}

// ErrSourceLagging is returned when a backup source never catches up to the
// leader within the allotted time.
var ErrSourceLagging = errors.New("plainqapi: source node did not reach the leader's commit index")

// appliedPollInterval is how often WaitForApplied re-reads a node's status.
const appliedPollInterval = time.Second

// WaitForApplied blocks until this client's node has applied every entry the
// leader had committed at targetIndex, or the context expires.
//
// This exists because cluster health does not imply a given follower is
// current. ClusterStatus.Healthy is `leader present && reachable voters >=
// quorum` — it says nothing about applied index, so a node can be reachable,
// voting, and several entries behind while the cluster reports healthy.
// Backing such a node up produces an artifact that silently omits writes the
// cluster already acknowledged, which is the worst way for a backup to fail:
// by succeeding.
func (c *Client) WaitForApplied(ctx context.Context, targetIndex uint64) (uint64, error) {
	ticker := time.NewTicker(appliedPollInterval)
	defer ticker.Stop()

	for {
		status, err := c.ClusterStatus(ctx)
		if err != nil {
			return 0, err
		}

		if status.AppliedIndex >= targetIndex {
			return status.AppliedIndex, nil
		}

		select {
		case <-ctx.Done():
			return status.AppliedIndex, fmt.Errorf("%w: applied %d, need %d: %w",
				ErrSourceLagging, status.AppliedIndex, targetIndex, ctx.Err())

		case <-ticker.C:
		}
	}
}

// SelectBackupSource picks the node a backup should be taken from.
//
// Never the leader: it is carrying the writes, and a VACUUM INTO or a volume
// read competes with them. A non-voter is best because it is not in the
// quorum path at all; a follower is next.
//
// prefer is one of "NonVoter", "Follower" or "Any".
//
//nolint:gocyclo,cyclop // A preference table; the branches are the specification.
func SelectBackupSource(members []ClusterMember, prefer string) (ClusterMember, bool) {
	var nonVoter, follower, leader *ClusterMember

	for i := range members {
		m := &members[i]

		if !m.Reachable {
			continue
		}

		switch {
		case m.Leader:
			leader = m

		case m.Suffrage == SuffrageNonVoter:
			if nonVoter == nil {
				nonVoter = m
			}

		case m.IsVoter():
			if follower == nil {
				follower = m
			}
		}
	}

	switch prefer {
	case "NonVoter":
		if nonVoter != nil {
			return *nonVoter, true
		}

		if follower != nil {
			return *follower, true
		}

	case "Follower":
		if follower != nil {
			return *follower, true
		}

		if nonVoter != nil {
			return *nonVoter, true
		}

	case "Any":
		if nonVoter != nil {
			return *nonVoter, true
		}

		if follower != nil {
			return *follower, true
		}

		if leader != nil {
			return *leader, true
		}
	}

	return ClusterMember{}, false
}
