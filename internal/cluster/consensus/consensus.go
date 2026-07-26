// Package consensus is the agreement layer under a PlainQ cluster.
//
// The interface here is deliberately small and deliberately not Raft-shaped:
// propose a command, learn who leads, change the membership. PlainQ ships a
// Raft engine (see the raft sub-package), but nothing above this line knows
// that — which is what keeps a different engine, Paxos included, a matter of
// writing one implementation rather than rewriting the queue.
package consensus

import (
	"context"
	"errors"
	"io"
	"time"
)

// Errors the queue layer acts on.
var (
	// ErrNotLeader means this node cannot commit the command itself. The
	// caller's move is to forward it to the leader, not to retry locally.
	ErrNotLeader = errors.New("consensus: node is not the leader")

	// ErrNoLeader means the cluster currently has no leader — an election is
	// in progress, or quorum is lost. Unlike ErrNotLeader there is nowhere to
	// forward to; the caller waits or fails.
	ErrNoLeader = errors.New("consensus: cluster has no leader")

	// ErrShutdown means the engine is stopped.
	ErrShutdown = errors.New("consensus: engine is shut down")
)

// State is a node's role in the consensus protocol.
type State string

// The states a node can be in.
const (
	// StateLeader means this node accepts writes and replicates them.
	StateLeader State = "leader"

	// StateFollower means this node replicates the leader's log.
	StateFollower State = "follower"

	// StateCandidate means this node is standing for election.
	StateCandidate State = "candidate"

	// StateShutdown means the engine has stopped.
	StateShutdown State = "shutdown"
)

// Suffrage is a server's standing in the configuration.
type Suffrage string

// The suffrage values.
const (
	// SuffrageVoter counts toward quorum and can become leader.
	SuffrageVoter Suffrage = "voter"

	// SuffrageNonVoter replicates the log without voting.
	SuffrageNonVoter Suffrage = "non-voter"

	// SuffrageStaging is a server catching up before it is promoted.
	SuffrageStaging Suffrage = "staging"
)

// Server is one member of the consensus configuration.
type Server struct {
	// ID is the server's stable cluster identity.
	ID string `json:"id"`

	// Addr is its consensus transport address.
	Addr string `json:"address"`

	// Suffrage is its standing.
	Suffrage Suffrage `json:"suffrage"`
}

// Status is a point-in-time view of the engine, as an operator would want it.
type Status struct {
	// NodeID is this node's identity.
	NodeID string `json:"nodeId"`

	// State is this node's role.
	State State `json:"state"`

	// LeaderID and LeaderAddr identify the current leader; both are empty
	// during an election.
	LeaderID   string `json:"leaderId"`
	LeaderAddr string `json:"leaderAddress"`

	// Term is the current consensus term.
	Term uint64 `json:"term"`

	// LastIndex is the last log index this node has stored.
	LastIndex uint64 `json:"lastIndex"`

	// CommitIndex is the highest index known to be committed.
	CommitIndex uint64 `json:"commitIndex"`

	// AppliedIndex is the highest index this node has applied to storage. The
	// gap between it and CommitIndex is this replica's lag.
	AppliedIndex uint64 `json:"appliedIndex"`

	// Servers is the committed configuration.
	Servers []Server `json:"servers"`

	// Engine names the implementation, e.g. "raft".
	Engine string `json:"engine"`
}

// Consensus is the agreement engine.
type Consensus interface {
	// Apply proposes a command and waits for it to be committed and applied.
	// It returns whatever the state machine returned for that command.
	//
	// It returns ErrNotLeader when this node cannot propose. That is not a
	// failure — it is routing information, and the caller is expected to use
	// it.
	Apply(ctx context.Context, data []byte) (any, error)

	// IsLeader reports whether this node currently leads. It is a hint: by
	// the time a caller acts on it, leadership may have moved. Apply is the
	// authority, because it fails when leadership is lost mid-flight.
	IsLeader() bool

	// Leader returns the current leader's id and address, or ErrNoLeader.
	Leader() (id, addr string, err error)

	// Status returns the current view of the engine.
	Status() Status

	// AddVoter adds (or promotes) a server as a full member.
	AddVoter(ctx context.Context, id, addr string) error

	// AddNonVoter adds a server that replicates without voting.
	AddNonVoter(ctx context.Context, id, addr string) error

	// RemoveServer drops a server from the configuration.
	RemoveServer(ctx context.Context, id string) error

	// Bootstrap forms a new cluster with the given servers. It fails if this
	// node already has state, which is what keeps a restart from silently
	// forking the cluster.
	Bootstrap(servers []Server) error

	// Barrier blocks until every command committed before the call has been
	// applied locally. A linearizable read takes one first.
	Barrier(ctx context.Context) error

	// LeaderCh signals leadership changes on this node: true when it becomes
	// leader, false when it stops being one. Leader-only work — the sweeper,
	// membership reconciliation — starts and stops on this.
	LeaderCh() <-chan bool

	// Snapshot forces a state machine snapshot, which also truncates the log.
	Snapshot(ctx context.Context) error

	// LastContact returns how long ago this follower last heard from the
	// leader. It is zero on the leader itself.
	LastContact() time.Duration

	io.Closer
}
