// Package gossip carries cluster membership between PlainQ nodes.
//
// Consensus decides who votes; gossip decides who is *there*. The two answer
// different questions and a cluster needs both: Raft cannot tell a node that
// is briefly slow from one that is gone, and it must not — reconfiguring on
// every hiccup is how a cluster loses quorum. A gossip layer detects failures
// in seconds without a quorum, and hands that view to the leader, which then
// decides — deliberately, and at its own pace — what to do about it.
package gossip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// State is a member's liveness as gossip sees it.
type State string

// The states a member can be in.
const (
	// StateAlive means the member responds to probes.
	StateAlive State = "alive"

	// StateSuspect means probes are failing but the cluster has not yet
	// agreed the member is gone.
	StateSuspect State = "suspect"

	// StateLeft means the member announced its departure.
	StateLeft State = "left"

	// StateFailed means the cluster agreed the member is unreachable.
	StateFailed State = "failed"
)

// Role is what a node asks to be in the consensus configuration.
type Role string

// The roles a node can advertise.
const (
	// RoleVoter is a full member: it votes in elections and counts toward
	// quorum.
	RoleVoter Role = "voter"

	// RoleNonVoter replicates the log but never votes. Useful for read
	// replicas and for growing a cluster without disturbing quorum.
	RoleNonVoter Role = "non-voter"
)

// Meta is the payload every node gossips about itself.
//
// It is the join handshake: a node that appears in gossip has, in the same
// breath, told everyone where its consensus port is and whether it wants to
// vote — so the leader can act on a new member without a second round trip.
type Meta struct {
	// ID is the node's cluster identity, stable across restarts.
	ID string `json:"id"`

	// RaftAddr is where this node's consensus transport listens.
	RaftAddr string `json:"raft_addr"`

	// Role is the membership the node asks for.
	Role Role `json:"role"`

	// Version is the PlainQ build, surfaced in cluster status so a rolling
	// upgrade is visible.
	Version string `json:"version,omitempty"`

	// Tags are free-form operator labels (rack, zone, tier).
	Tags map[string]string `json:"tags,omitempty"`
}

// Encode renders the metadata for the wire. Gossip metadata is capped by the
// transport (memberlist allows 512 bytes), so tags are dropped rather than
// letting an over-long payload fail the node's own broadcast.
func (m Meta) Encode(limit int) ([]byte, error) {
	encoded, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("encode gossip metadata: %w", err)
	}

	if len(encoded) <= limit {
		return encoded, nil
	}

	trimmed := m
	trimmed.Tags = nil

	encoded, err = json.Marshal(trimmed)
	if err != nil {
		return nil, fmt.Errorf("encode gossip metadata: %w", err)
	}

	if len(encoded) > limit {
		return nil, fmt.Errorf("gossip metadata is %d bytes, over the %d byte limit", len(encoded), limit)
	}

	return encoded, nil
}

// DecodeMeta parses metadata gossiped by another node.
func DecodeMeta(raw []byte) (Meta, error) {
	var meta Meta

	if len(raw) == 0 {
		return meta, nil
	}

	if err := json.Unmarshal(raw, &meta); err != nil {
		return meta, fmt.Errorf("decode gossip metadata: %w", err)
	}

	return meta, nil
}

// Member is one node as gossip sees it.
type Member struct {
	// Meta is what the member says about itself.
	Meta

	// Name is the transport-level name, which is the node id.
	Name string

	// Addr is the member's gossip address as host:port.
	Addr string

	// State is the member's liveness.
	State State
}

// EventType distinguishes the membership changes a subscriber sees.
type EventType string

// The event types.
const (
	// EventJoin is a member becoming visible.
	EventJoin EventType = "join"

	// EventLeave is a member becoming unreachable or announcing departure.
	EventLeave EventType = "leave"

	// EventUpdate is a member changing its metadata.
	EventUpdate EventType = "update"
)

// Event is a membership change.
type Event struct {
	Type   EventType
	Member Member
}

// Gossip is the membership layer.
type Gossip interface {
	// Join contacts the given addresses and merges their view with this
	// node's. It returns the number of hosts successfully contacted; joining
	// zero hosts is not an error, because a node that starts first has nobody
	// to join yet.
	Join(ctx context.Context, addrs []string) (int, error)

	// Members returns every member currently known, including this node.
	Members() []Member

	// Local returns this node's own member record.
	Local() Member

	// UpdateMeta re-broadcasts this node's metadata after it changes.
	UpdateMeta(meta Meta) error

	// Events returns the stream of membership changes.
	//
	// The channel is never closed — subscribers stop on their own signal —
	// because the layer cannot know that the transport has no callback still
	// in flight. A slow reader misses events rather than blocking the gossip
	// layer, so subscribers treat the stream as a hint and Members as the
	// truth.
	Events() <-chan Event

	// Leave announces departure and waits for the news to propagate, so the
	// rest of the cluster records a clean exit rather than a failure.
	Leave(timeout time.Duration) error

	io.Closer
}
