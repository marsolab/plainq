package cluster

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/cluster/consensus"
)

type leaveLeaderResult struct {
	id   string
	addr string
	err  error
}

type scriptedLeaveMembership struct {
	leaders      []leaveLeaderResult
	lastLeader   leaveLeaderResult
	remoteErrors []error
	localError   error
	leaderCalls  int
	localCalls   int
	remoteAddrs  []string
	events       []string
}

func (m *scriptedLeaveMembership) Leader() (string, string, error) {
	m.leaderCalls++
	m.events = append(m.events, "leader")

	if len(m.leaders) > 0 {
		m.lastLeader = m.leaders[0]
		m.leaders = m.leaders[1:]
	}

	return m.lastLeader.id, m.lastLeader.addr, m.lastLeader.err
}

func (m *scriptedLeaveMembership) RemoveLocal(context.Context, string) error {
	m.localCalls++
	m.events = append(m.events, "local")

	return m.localError
}

func (m *scriptedLeaveMembership) RemoveRemote(_ context.Context, addr, _ string) error {
	m.remoteAddrs = append(m.remoteAddrs, addr)
	m.events = append(m.events, "remote:"+addr)

	if len(m.remoteErrors) == 0 {
		return nil
	}

	err := m.remoteErrors[0]
	m.remoteErrors = m.remoteErrors[1:]

	return err
}

func TestLeaveNodeReResolvesLeaderAcrossElection(t *testing.T) {
	membership := &scriptedLeaveMembership{
		leaders: []leaveLeaderResult{
			{err: consensus.ErrNoLeader},
			{id: "stale-leader", addr: "127.0.0.1:7001"},
			{id: "current-leader", addr: "127.0.0.1:7002"},
		},
		remoteErrors: []error{consensus.ErrNotLeader, nil},
	}
	announcements := 0

	err := leaveNode(context.Background(), "departing", membership, func(time.Duration) error {
		announcements++
		membership.events = append(membership.events, "gossip")

		return nil
	})
	if err != nil {
		t.Fatalf("leaveNode() = %v, want success", err)
	}

	wantEvents := []string{
		"leader",
		"leader", "remote:127.0.0.1:7001",
		"leader", "remote:127.0.0.1:7002",
		"gossip",
	}
	if !slices.Equal(membership.events, wantEvents) {
		t.Fatalf("leave events = %v, want %v", membership.events, wantEvents)
	}
	if announcements != 1 {
		t.Fatalf("gossip announcements = %d, want 1", announcements)
	}
}

func TestLeaveNodeDoesNotAnnounceGossipAfterTerminalRemovalFailure(t *testing.T) {
	terminal := errors.New("peer transport unavailable")

	tests := []struct {
		name       string
		membership *scriptedLeaveMembership
	}{
		{
			name: "resolve leader",
			membership: &scriptedLeaveMembership{
				leaders: []leaveLeaderResult{{err: terminal}},
			},
		},
		{
			name: "remove through leader",
			membership: &scriptedLeaveMembership{
				leaders:      []leaveLeaderResult{{id: "leader", addr: "127.0.0.1:7001"}},
				remoteErrors: []error{terminal},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			announcements := 0

			err := leaveNode(context.Background(), "departing", test.membership, func(time.Duration) error {
				announcements++

				return nil
			})
			if !errors.Is(err, terminal) {
				t.Fatalf("leaveNode() = %v, want terminal removal error", err)
			}
			if test.membership.leaderCalls != 1 {
				t.Fatalf("Leader() calls = %d, want no retry", test.membership.leaderCalls)
			}
			if announcements != 0 {
				t.Fatalf("gossip announcements = %d, want 0", announcements)
			}
		})
	}
}

func TestLeaveNodeStopsRetryingWhenContextEnds(t *testing.T) {
	membership := &scriptedLeaveMembership{
		lastLeader: leaveLeaderResult{err: consensus.ErrNoLeader},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	announcements := 0

	err := leaveNode(ctx, "departing", membership, func(time.Duration) error {
		announcements++

		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("leaveNode() = %v, want context cancellation", err)
	}
	if announcements != 0 {
		t.Fatalf("gossip announcements = %d, want 0", announcements)
	}
}
