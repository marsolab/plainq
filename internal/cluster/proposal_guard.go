package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"math"

	"github.com/marsolab/plainq/internal/cluster/command"
	"github.com/marsolab/plainq/internal/cluster/consensus"
	"github.com/marsolab/plainq/internal/cluster/publishwire"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/shared/deleteresult"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"golang.org/x/sync/semaphore"
)

var _ consensus.Consensus = (*proposalGuard)(nil)

const proposalGateCapacity int64 = math.MaxInt64

type proposalPreflighter interface {
	queue.DeleteEffectPreflighter
	TopicInventory(ctx context.Context) (queue.TopicInventory, error)
}

// proposalGuard lets ordinary proposals overlap while giving deletes and
// publishes fair, leader-local exclusivity. Admission therefore observes the
// exact state the following log entry will mutate without putting a
// version-dependent decision inside the replicated FSM.
type proposalGuard struct {
	consensus.Consensus

	gate      *semaphore.Weighted
	preflight proposalPreflighter

	// deleteResultLimit is fixed to the peer response ceiling in production.
	// Focused tests lower it without introducing a runtime configuration knob.
	deleteResultLimit int
}

func newProposalGuard(engine consensus.Consensus, preflight proposalPreflighter) *proposalGuard {
	return &proposalGuard{
		Consensus:         engine,
		gate:              semaphore.NewWeighted(proposalGateCapacity),
		preflight:         preflight,
		deleteResultLimit: deleteresult.MaxEnvelopeBytes,
	}
}

// Apply admits ordinary writes concurrently and gives a delete or publish
// exclusive admission from its barrier through its underlying Apply call.
func (g *proposalGuard) Apply(ctx context.Context, data []byte) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	cmd, decodeErr := command.Decode(data)
	exclusiveProposal := decodeErr == nil && isExclusiveProposal(cmd.Op)

	weight := int64(1)
	if exclusiveProposal {
		weight = proposalGateCapacity
	}

	if err := g.gate.Acquire(ctx, weight); err != nil {
		return nil, fmt.Errorf("acquire proposal admission: %w", err)
	}
	defer g.gate.Release(weight)

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !exclusiveProposal {
		return g.applyConsensus(ctx, data)
	}

	return g.applyExclusive(ctx, data, cmd)
}

func isExclusiveProposal(op command.Op) bool {
	return op == command.OpDeleteTopic || op == command.OpDeleteQueue || op == command.OpPublish
}

func (g *proposalGuard) applyExclusive(ctx context.Context, data []byte, cmd *command.Command) (any, error) {
	if !g.IsLeader() {
		return nil, consensus.ErrNotLeader
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := g.Barrier(ctx); err != nil {
		return nil, fmt.Errorf("barrier before %s proposal: %w", cmd.Op, err)
	}

	if err := g.preflightProposal(ctx, cmd); err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return g.applyConsensus(ctx, data)
}

func (g *proposalGuard) applyConsensus(ctx context.Context, data []byte) (any, error) {
	response, err := g.Consensus.Apply(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("apply consensus proposal: %w", err)
	}

	return response, nil
}

func (g *proposalGuard) preflightProposal(ctx context.Context, cmd *command.Command) error {
	if cmd.Op == command.OpPublish {
		return g.preflightPublish(ctx, cmd)
	}

	return g.preflightDelete(ctx, cmd)
}

func (g *proposalGuard) preflightPublish(ctx context.Context, cmd *command.Command) error {
	request := new(queue.PublishRequest)
	if err := json.Unmarshal(cmd.Payload, request); err != nil {
		return fmt.Errorf("decode publish proposal preflight: %w", err)
	}

	inventory, err := g.preflight.TopicInventory(ctx)
	if err != nil {
		return fmt.Errorf("read topic inventory before publish %q: %w", cmd.Target, err)
	}

	subscriptionCount, exists := inventory.SubscriptionCounts[cmd.Target]
	if !exists {
		return fmt.Errorf("preflight publish topic %q: %w", cmd.Target, pqerr.ErrNotFound)
	}

	if subscriptionCount < 0 {
		return fmt.Errorf(
			"preflight publish topic %q: negative subscription count %d",
			cmd.Target,
			subscriptionCount,
		)
	}

	bound, fits := publishwire.FitsCompactOutcome(
		uint64(subscriptionCount),
		uint64(len(request.Messages)),
		uint64(publishwire.MaxResponseBytes),
	)
	if !fits {
		return fmt.Errorf(
			"%w: compact publish outcome for topic %q is bounded at %d bytes; limit is %d bytes",
			pqerr.ErrCapacityExceeded,
			cmd.Target,
			bound,
			publishwire.MaxResponseBytes,
		)
	}

	return nil
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

	case command.OpUnknown,
		command.OpCreateQueue,
		command.OpPurgeQueue,
		command.OpSend,
		command.OpReceive,
		command.OpDelete,
		command.OpCreateTopic,
		command.OpSubscribe,
		command.OpUnsubscribe,
		command.OpPublish,
		command.OpSweep:
		return fmt.Errorf("preflight unsupported delete operation %q", cmd.Op)
	}

	return fmt.Errorf("preflight unsupported delete operation %q", cmd.Op)
}
