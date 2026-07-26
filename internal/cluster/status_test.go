package cluster

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/cluster/consensus"
	"github.com/maxatome/go-testdeep/td"
)

// The status page's job is to be honest about disagreement: what consensus
// agreed, and what gossip can actually see, side by side.
func TestStatusReportsBothViews(t *testing.T) {
	if testing.Short() {
		t.Skip("starts three raft nodes")
	}

	cluster := newTestCluster(t, 3)

	leader := cluster.leader(30 * time.Second)

	cluster.waitFor(30*time.Second, func() bool {
		return len(leader.node.Status().Members) == 3
	}, "every node is in the configuration")

	status := leader.node.Status()

	td.Cmp(t, status.Enabled, true)
	td.Cmp(t, status.State, consensus.StateLeader)
	td.Cmp(t, status.LeaderID, leader.id)
	td.Cmp(t, status.Voters, 3)
	td.Cmp(t, status.Quorum, 2, "a three-node cluster commits on two")
	td.Cmp(t, status.Healthy, true)
	td.Cmp(t, status.Engine, "raft")
	td.Cmp(t, status.Term > 0, true)

	// Members come back in a stable order, so a status page does not reshuffle
	// between refreshes.
	ids := make([]string, 0, len(status.Members))
	for _, member := range status.Members {
		ids = append(ids, member.ID)
	}

	td.Cmp(t, ids, []string{"node-1", "node-2", "node-3"})

	var self, other Member

	for _, member := range status.Members {
		if member.Self {
			self = member
		} else {
			other = member
		}
	}

	td.Cmp(t, self.ID, leader.id)
	td.Cmp(t, self.Leader, true)
	td.Cmp(t, self.Reachable, true)
	td.Cmp(t, self.Suffrage, consensus.SuffrageVoter)

	td.Cmp(t, other.Reachable, true, "gossip can see the other nodes")
	td.Cmp(t, other.GossipAddr, td.Not(""), "and reports where")
	td.Cmp(t, other.Version, "test", "including the build they are running")
}

// Losing a node has to show up as a shrunken reachable set while the
// configuration still lists it — that difference is what tells an operator
// something is wrong rather than merely different.
func TestStatusShowsAnUnreachableMember(t *testing.T) {
	if testing.Short() {
		t.Skip("starts three raft nodes")
	}

	cluster := newTestCluster(t, 3)

	leader := cluster.leader(30 * time.Second)

	cluster.waitFor(30*time.Second, func() bool {
		return len(leader.node.Status().Members) == 3
	}, "every node is in the configuration")

	departing := cluster.follower()
	td.Require(t).CmpNoError(departing.node.Close())

	cluster.waitFor(30*time.Second, func() bool {
		for _, member := range leader.node.Status().Members {
			if member.ID == departing.id {
				return !member.Reachable
			}
		}

		return false
	}, "the stopped node reads as unreachable")

	status := leader.node.Status()

	td.Cmp(t, status.Voters, 3, "it is still in the configuration")
	td.Cmp(t, status.Healthy, true, "two of three is still a quorum")
}

// A server that is not clustered answers the same shape with Enabled false,
// rather than a 404 a dashboard cannot tell from an old build.
func TestDisabledClusterStatusShape(t *testing.T) {
	var status Status

	td.Cmp(t, status.Enabled, false)
	td.Cmp(t, status.Members, td.Nil())
}

func TestJoinAndRemoveThroughTheNode(t *testing.T) {
	if testing.Short() {
		t.Skip("starts three raft nodes")
	}

	ctx := context.Background()

	cluster := newTestCluster(t, 3)

	leader := cluster.leader(30 * time.Second)

	// Adding a node that is not running is legitimate — the configuration
	// change commits, and the node catches up when it starts.
	td.Require(t).CmpNoError(leader.node.Join(ctx, "node-9", "127.0.0.1:19999", true))

	cluster.waitFor(20*time.Second, func() bool {
		for _, member := range leader.node.Status().Members {
			if member.ID == "node-9" {
				return member.Suffrage == consensus.SuffrageNonVoter
			}
		}

		return false
	}, "the added node appears as a non-voter")

	td.Cmp(t, leader.node.Status().Voters, 3, "a non-voter does not change quorum")

	td.Require(t).CmpNoError(leader.node.Remove(ctx, "node-9"))

	cluster.waitFor(20*time.Second, func() bool {
		for _, member := range leader.node.Status().Members {
			if member.ID == "node-9" {
				return false
			}
		}

		return true
	}, "the node is removed again")
}

// A follower cannot change the configuration, and the error says so in the one
// way a caller can act on.
func TestJoinOnAFollowerIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("starts three raft nodes")
	}

	cluster := newTestCluster(t, 3)

	cluster.leader(30 * time.Second)

	err := cluster.follower().node.Join(context.Background(), "node-9", "127.0.0.1:19999", false)

	td.Require(t).CmpError(err)
	td.Cmp(t, errors.Is(err, consensus.ErrNotLeader), true, "the caller can tell where to ask instead")
}
