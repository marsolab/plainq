package cluster

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/marsolab/plainq/internal/cluster/consensus"
)

const leaveRetryInterval = 25 * time.Millisecond

// leaveMembership is the consensus boundary a node crosses while leaving.
// Keeping it narrow makes the election-sensitive sequence independently
// testable from the transport and gossip implementations.
type leaveMembership interface {
	Leader() (id, addr string, err error)
	RemoveLocal(ctx context.Context, nodeID string) error
	RemoveRemote(ctx context.Context, addr, nodeID string) error
}

type nodeLeaveMembership struct{ node *Node }

func (m nodeLeaveMembership) Leader() (id, addr string, err error) {
	id, addr, err = m.node.consensus.Leader()
	if err != nil {
		return "", "", fmt.Errorf("resolve consensus leader: %w", err)
	}

	return id, addr, nil
}

func (m nodeLeaveMembership) RemoveLocal(ctx context.Context, nodeID string) error {
	return m.node.Remove(ctx, nodeID)
}

func (m nodeLeaveMembership) RemoveRemote(ctx context.Context, addr, nodeID string) error {
	if err := m.node.peerClient.Leave(ctx, addr, nodeID); err != nil {
		return fmt.Errorf("ask leader %s to remove cluster member %q: %w", addr, nodeID, err)
	}

	return nil
}

func leaveNode(
	ctx context.Context,
	nodeID string,
	membership leaveMembership,
	announce func(time.Duration) error,
) error {
	removeCtx, cancel := context.WithTimeout(ctx, leaveTimeout)
	defer cancel()

	if err := removeNodeForLeave(removeCtx, nodeID, membership); err != nil {
		return err
	}

	if err := announce(leaveTimeout); err != nil {
		return err
	}

	return nil
}

func removeNodeForLeave(ctx context.Context, nodeID string, membership leaveMembership) error {
	var lastErr error

	for {
		if err := ctx.Err(); err != nil {
			return leaveRemovalError(nodeID, errors.Join(lastErr, err))
		}

		leaderID, leaderAddr, err := membership.Leader()
		if err == nil {
			if leaderID == nodeID {
				err = membership.RemoveLocal(ctx, nodeID)
			} else {
				err = membership.RemoveRemote(ctx, leaderAddr, nodeID)
			}
		}

		if err == nil {
			return nil
		}
		if !errors.Is(err, consensus.ErrNoLeader) && !errors.Is(err, consensus.ErrNotLeader) {
			return leaveRemovalError(nodeID, err)
		}

		lastErr = err

		timer := time.NewTimer(leaveRetryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()

			return leaveRemovalError(nodeID, errors.Join(lastErr, ctx.Err()))
		case <-timer.C:
		}
	}
}

func leaveRemovalError(nodeID string, err error) error {
	return fmt.Errorf("remove cluster member %q before leaving: %w", nodeID, err)
}
