package cluster

import (
	"context"
	"fmt"
	"sync"

	"github.com/marsolab/plainq/internal/cluster/command"
	"github.com/marsolab/plainq/internal/cluster/consensus"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/shared/deleteresult"
)

var _ consensus.Consensus = (*proposalGuard)(nil)

// proposalGuard serializes every queue proposal through one leader-local
// critical section. Delete effect sizing therefore observes the exact state
// the following log entry will mutate, without putting a version-dependent
// decision inside the replicated FSM.
type proposalGuard struct {
	consensus.Consensus

	mu        sync.Mutex
	previewer queue.DeleteEffectPreviewer
	marshal   func(any, int) ([]byte, error)

	// deleteResultLimit is fixed to the peer response ceiling in production.
	// Focused tests lower it without introducing a runtime configuration knob.
	deleteResultLimit int
}

func newProposalGuard(engine consensus.Consensus, previewer queue.DeleteEffectPreviewer) *proposalGuard {
	return &proposalGuard{
		Consensus:         engine,
		previewer:         previewer,
		marshal:           deleteresult.Marshal,
		deleteResultLimit: deleteresult.MaxEnvelopeBytes,
	}
}

// Apply serializes all queue proposals and preflights delete effects on the
// leader before the command can enter the Raft log.
func (g *proposalGuard) Apply(ctx context.Context, data []byte) (any, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	cmd, err := command.Decode(data)
	if err != nil || (cmd.Op != command.OpDeleteTopic && cmd.Op != command.OpDeleteQueue) {
		return g.Consensus.Apply(ctx, data)
	}

	if !g.Consensus.IsLeader() {
		return nil, consensus.ErrNotLeader
	}
	if err := g.Consensus.Barrier(ctx); err != nil {
		return nil, fmt.Errorf("barrier before %s proposal: %w", cmd.Op, err)
	}

	result, err := g.previewDelete(ctx, cmd)
	if err != nil {
		return nil, err
	}
	if _, err := g.marshal(result, g.deleteResultLimit); err != nil {
		return nil, fmt.Errorf("preflight %s result: %w", cmd.Op, err)
	}

	return g.Consensus.Apply(ctx, data)
}

func (g *proposalGuard) previewDelete(ctx context.Context, cmd *command.Command) (any, error) {
	switch cmd.Op {
	case command.OpDeleteTopic:
		result, err := g.previewer.PreviewDeleteTopic(ctx, cmd.Target)
		if err != nil {
			return nil, fmt.Errorf("preview delete topic %q: %w", cmd.Target, err)
		}

		return result, nil

	case command.OpDeleteQueue:
		input := new(v1.DeleteQueueRequest)
		if err := input.UnmarshalVT(cmd.Payload); err != nil {
			return nil, fmt.Errorf("decode delete queue proposal preview: %w", err)
		}
		result, err := g.previewer.PreviewDeleteQueue(ctx, input.GetQueueId())
		if err != nil {
			return nil, fmt.Errorf("preview delete queue %q: %w", input.GetQueueId(), err)
		}

		return result, nil

	default:
		return nil, fmt.Errorf("preview unsupported delete operation %q", cmd.Op)
	}
}
