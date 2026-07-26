package cluster

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"

	"github.com/marsolab/plainq/internal/cluster/consensus"
	"github.com/marsolab/plainq/internal/cluster/gossip"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
)

// listAllQueuesLimit is the page size the leader's sweeper reads queues in.
const listAllQueuesLimit = 1000

// Status is a node's complete view of the cluster, as an operator or the
// Houston dashboard would want it: what the consensus layer agreed, and what
// gossip can actually see, side by side. They differ during a failure, and the
// difference is the most useful thing on the page.
type Status struct {
	// Enabled reports whether this server is clustered at all.
	Enabled bool `json:"enabled"`

	// NodeID is this node's identity.
	NodeID string `json:"nodeId"`

	// State is this node's consensus role.
	State consensus.State `json:"state"`

	// Leader identifies the current leader, empty during an election.
	LeaderID   string `json:"leaderId"`
	LeaderAddr string `json:"leaderAddress"`

	// Term, CommitIndex and AppliedIndex describe the log.
	Term         uint64 `json:"term"`
	CommitIndex  uint64 `json:"commitIndex"`
	AppliedIndex uint64 `json:"appliedIndex"`
	LastIndex    uint64 `json:"lastIndex"`

	// LastContact is how long ago this follower heard from the leader. It is
	// zero on the leader.
	LastContact string `json:"lastContact,omitempty"`

	// Engine names the consensus implementation.
	Engine string `json:"engine"`

	// Members merges the consensus configuration with the gossip view.
	Members []Member `json:"members"`

	// Quorum is how many voters a write needs, and Voters is how many exist.
	// An operator comparing the two learns, at a glance, how many more
	// failures this cluster survives.
	Quorum int `json:"quorum"`
	Voters int `json:"voters"`

	// Healthy reports whether the cluster can currently commit a write.
	Healthy bool `json:"healthy"`

	// AppliedCommands and FailedCommands count what the state machine did.
	AppliedCommands uint64 `json:"appliedCommands"`
	FailedCommands  uint64 `json:"failedCommands"`
}

// Member is one node, as both layers see it.
type Member struct {
	// ID is the node's cluster identity.
	ID string `json:"id"`

	// Addr is its consensus address.
	Addr string `json:"address"`

	// GossipAddr is its membership address.
	GossipAddr string `json:"gossipAddress,omitempty"`

	// Suffrage is its standing in the consensus configuration. Empty means
	// gossip can see it but consensus has not admitted it — a node mid-join,
	// or one the leader has not reconciled yet.
	Suffrage consensus.Suffrage `json:"suffrage,omitempty"`

	// Reachable reports whether gossip currently sees the node. A configured
	// member that is not reachable is the shape of a failure.
	Reachable bool `json:"reachable"`

	// Leader marks the current leader.
	Leader bool `json:"leader"`

	// Self marks the node answering the request.
	Self bool `json:"self"`

	// Version is the peer's build, when it gossiped one. A mixed set during a
	// rolling upgrade is worth seeing.
	Version string `json:"version,omitempty"`
}

// Status returns this node's view of the cluster.
//
//nolint:cyclop // Merging two membership views is a flat pass over each.
func (n *Node) Status() Status {
	consensusStatus := n.consensus.Status()
	applied, failed := n.fsm.Stats()

	status := Status{
		Enabled:         true,
		NodeID:          n.cfg.NodeID,
		State:           consensusStatus.State,
		LeaderID:        consensusStatus.LeaderID,
		LeaderAddr:      consensusStatus.LeaderAddr,
		Term:            consensusStatus.Term,
		CommitIndex:     consensusStatus.CommitIndex,
		AppliedIndex:    consensusStatus.AppliedIndex,
		LastIndex:       consensusStatus.LastIndex,
		Engine:          consensusStatus.Engine,
		AppliedCommands: applied,
		FailedCommands:  failed,
	}

	if contact := n.consensus.LastContact(); contact > 0 {
		status.LastContact = contact.Round(time.Millisecond).String()
	}

	reachable := make(map[string]gossip.Member)

	if n.gossip != nil {
		for _, member := range n.gossip.Members() {
			reachable[member.ID] = member
		}
	}

	seen := make(map[string]bool, len(consensusStatus.Servers))

	// Reachable voters decide whether the cluster can commit anything; the
	// quorum it is compared against is derived from the total, below.
	reachableVoters := 0

	for _, server := range consensusStatus.Servers {
		member := Member{
			ID:       server.ID,
			Addr:     server.Addr,
			Suffrage: server.Suffrage,
			Leader:   server.ID == consensusStatus.LeaderID,
			Self:     server.ID == n.cfg.NodeID,

			// This node can always reach itself, whether or not it appears in
			// its own gossip view yet.
			Reachable: server.ID == n.cfg.NodeID,
		}

		if alive, ok := reachable[server.ID]; ok {
			member.Reachable = true
			member.GossipAddr = alive.Addr
			member.Version = alive.Version
		}

		if server.Suffrage == consensus.SuffrageVoter {
			status.Voters++

			if member.Reachable {
				reachableVoters++
			}
		}

		seen[server.ID] = true

		status.Members = append(status.Members, member)
	}

	// Members gossip sees but consensus has not admitted. Surfacing them is
	// how an operator sees a node that is up but stuck outside the cluster.
	for id, alive := range reachable {
		if seen[id] {
			continue
		}

		status.Members = append(status.Members, Member{
			ID:         id,
			Addr:       alive.RaftAddr,
			GossipAddr: alive.Addr,
			Reachable:  true,
			Self:       id == n.cfg.NodeID,
			Version:    alive.Version,
		})
	}

	status.Quorum = status.Voters/2 + 1
	status.Healthy = consensusStatus.LeaderID != "" && reachableVoters >= status.Quorum

	// A stable order, so a status page does not reshuffle between refreshes.
	sort.Slice(status.Members, func(i, j int) bool { return status.Members[i].ID < status.Members[j].ID })

	return status
}

// listAllQueues builds one page of the request the leader's sweeper walks.
func listAllQueues(cursor string) *v1.ListQueuesRequest {
	return &v1.ListQueuesRequest{Limit: listAllQueuesLimit, Cursor: cursor}
}

// splitHostPortInt splits host:port, returning the port as an int.
//
//nolint:nonamedreturns // a bare (string, int) pair reads as nothing in particular.
func splitHostPortInt(addr string) (host string, port int, err error) {
	host, rawPort, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return "", 0, fmt.Errorf("parse address %q: %w", addr, splitErr)
	}

	parsed, convErr := strconv.Atoi(rawPort)
	if convErr != nil {
		return "", 0, fmt.Errorf("parse port of address %q: %w", addr, convErr)
	}

	return host, parsed, nil
}
