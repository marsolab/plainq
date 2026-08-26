package cluster

import (
	"context"
	"fmt"
	"math"

	"github.com/marsolab/plainq/internal/cluster/command"
	"github.com/marsolab/plainq/internal/cluster/consensus"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/shared/deleteresult"
	"golang.org/x/sync/semaphore"
)

var _ consensus.Consensus = (*proposalGuard)(nil)

const proposalGateCapacity int64 = math.MaxInt64

// proposalGuard lets ordinary proposals overlap while giving deletes fair,
// leader-local exclusivity. Delete admission therefore observes the exact
// state the following log entry will mutate without putting a version-dependent
// decision inside the replicated FSM.
type proposalGuard struct {
	consensus.Consensus

	gate      *semaphore.Weighted
	preflight queue.DeleteEffectPreflighter

	// deleteResultLimit is fixed to the peer response ceiling in production.
	// Focused tests lower it without introducing a runtime configuration knob.
	deleteResultLimit int
}

func newProposalGuard(engine consensus.Consensus, preflight queue.DeleteEffectPreflighter) *proposalGuard {
	return &proposalGuard{
		Consensus:         engine,
		gate:              semaphore.NewWeighted(proposalGateCapacity),
		preflight:         preflight,
		deleteResultLimit: deleteresult.MaxEnvelopeBytes,
	}
}

// Apply admits ordinary writes concurrently and gives a delete exclusive
// admission from its barrier through its underlying Apply call.
func (g *proposalGuard) Apply(ctx context.Context, data []byte) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	cmd, decodeErr := command.Decode(data)
	deleteProposal := decodeErr == nil && (cmd.Op == command.OpDeleteTopic || cmd.Op == command.OpDeleteQueue)
	weight := int64(1)
	if deleteProposal {
		weight = proposalGateCapacity
	}
	if err := g.gate.Acquire(ctx, weight); err != nil {
		return nil, err
	}
	defer g.gate.Release(weight)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !deleteProposal {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		return g.Consensus.Apply(ctx, data)
	}

	if !g.Consensus.IsLeader() {
		return nil, consensus.ErrNotLeader
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := g.Consensus.Barrier(ctx); err != nil {
		return nil, fmt.Errorf("barrier before %s proposal: %w", cmd.Op, err)
	}

	if err := g.preflightDelete(ctx, cmd); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return g.Consensus.Apply(ctx, data)
}

func (g *proposalGuard) preflightDelete(ctx context.Context, cmd *command.Command) error {
	switch cmd.Op {
	case command.OpDeleteTopic:
		if err := g.preflight.PreflightDeleteTopic(ctx, cmd.Target, g.deleteResultLimit); err != nil {
			return fmt.Errorf("preflight delete topic %q: %w", cmd.Target, err)
		}

		return nil

	case command.OpDeleteQueue:
		input := new(v1.DeleteQueueRequest)
		if err := input.UnmarshalVT(cmd.Payload); err != nil {
			return fmt.Errorf("decode delete queue proposal preflight: %w", err)
		}
		if err := g.preflight.PreflightDeleteQueue(ctx, input, g.deleteResultLimit); err != nil {
			return fmt.Errorf("preflight delete queue %q: %w", input.GetQueueId(), err)
		}

		return nil

	default:
		return fmt.Errorf("preflight unsupported delete operation %q", cmd.Op)
	}
}
