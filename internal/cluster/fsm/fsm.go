// Package fsm applies the consensus log to a local queue store.
//
// This is the point where agreement becomes state. Every node runs the same
// FSM over the same log, so the FSM is the one place in PlainQ that must be
// purely a function of its input: no clocks, no generated ids, no branching on
// anything the node knows and its peers do not. Everything ambiguous was
// resolved by the leader before the command was proposed.
package fsm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	hraft "github.com/hashicorp/raft"
	"github.com/marsolab/plainq/internal/cluster/command"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/servekit/logkit"
)

// applyTimeout bounds one command's work against storage. A command that hangs
// blocks the whole log — every node's, not just this one's — so it is given a
// generous ceiling rather than none at all.
const applyTimeout = 60 * time.Second

// Compilation time check that FSM implements raft's state machine contract.
var _ hraft.FSM = (*FSM)(nil)

// FSM applies committed commands to a queue store.
type FSM struct {
	storage queue.ReplicatedStorage
	logger  *slog.Logger

	// appliedIndex is the last log index applied, for status reporting.
	appliedIndex atomic.Uint64

	// applied counts commands by op, for metrics.
	applied atomic.Uint64

	// failed counts commands whose application returned an error. A non-zero
	// value is not corruption — a rejected CreateQueue is a legitimate outcome
	// — but a climbing one is worth an operator's attention.
	failed atomic.Uint64
}

// New returns an FSM over the given local store.
func New(storage queue.ReplicatedStorage, logger *slog.Logger) *FSM {
	if logger == nil {
		logger = logkit.NewNop()
	}

	return &FSM{storage: storage, logger: logger}
}

// AppliedIndex returns the last log index this state machine applied.
func (f *FSM) AppliedIndex() uint64 { return f.appliedIndex.Load() }

// Stats returns counters for the metrics endpoint.
//
//nolint:nonamedreturns // two bare uint64s in a row need naming to be readable.
func (f *FSM) Stats() (applied, failed uint64) {
	return f.applied.Load(), f.failed.Load()
}

// Apply implements raft.FSM.
//
// The returned value travels back to whoever proposed the command on the
// leader and is ignored everywhere else. An error is returned as a value
// rather than raised: the entry is committed either way, and every replica has
// to reach the same conclusion about it — including the conclusion that it
// failed.
func (f *FSM) Apply(entry *hraft.Log) any {
	defer f.appliedIndex.Store(entry.Index)

	if entry.Type != hraft.LogCommand {
		return nil
	}

	cmd, decodeErr := command.Decode(entry.Data)
	if decodeErr != nil {
		// A log entry this node cannot read is not survivable: skipping it
		// would silently fork this replica's state from the cluster's. Say so
		// loudly and return the error so the operator sees a stuck node rather
		// than a quietly wrong one.
		f.failed.Add(1)

		f.logger.Error("Refusing to apply an unreadable log entry",
			slog.Uint64("index", entry.Index),
			slog.String("error", decodeErr.Error()),
		)

		return fmt.Errorf("decode log entry %d: %w", entry.Index, decodeErr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), applyTimeout)
	defer cancel()

	// The log index seeds any identifier the command needs beyond the ones the
	// leader assigned. It is unique per entry and identical on every replica,
	// which is exactly what a derived identifier has to be.
	determinism := queue.NewDeterminism(cmd.Time(), cmd.IDs, entry.Index)
	ctx = queue.WithDeterminism(ctx, determinism)

	response, err := f.dispatch(ctx, cmd)
	if err != nil {
		f.failed.Add(1)

		f.logger.Debug("Command application failed",
			slog.Uint64("index", entry.Index),
			slog.String("op", cmd.Op.String()),
			slog.String("error", err.Error()),
		)

		return err
	}

	f.applied.Add(1)

	// A mismatch either way means the leader sized the command against state
	// that had already moved by the time it was applied. The replicas stay
	// consistent — the extras are derived, not generated — but it is worth
	// seeing, because it says a fan-out raced a subscription change.
	if remaining := determinism.Remaining(); remaining > 0 {
		f.logger.Warn("Command used fewer identifiers than the leader assigned",
			slog.Uint64("index", entry.Index),
			slog.String("op", cmd.Op.String()),
			slog.Int("unused", remaining),
		)
	}

	if extra := determinism.Overflowed(); extra > 0 {
		f.logger.Warn("Command needed more identifiers than the leader assigned",
			slog.Uint64("index", entry.Index),
			slog.String("op", cmd.Op.String()),
			slog.Int("derived", extra),
		)
	}

	return response
}

//nolint:cyclop,gocyclo // A dispatch table over the op set is naturally one branch per op.
func (f *FSM) dispatch(ctx context.Context, cmd *command.Command) (any, error) {
	switch cmd.Op {
	case command.OpCreateQueue:
		return decodeAnd(cmd, &v1.CreateQueueRequest{}, func(req *v1.CreateQueueRequest) (any, error) {
			return f.storage.CreateQueue(ctx, req)
		})

	case command.OpDeleteQueue:
		return decodeAnd(cmd, &v1.DeleteQueueRequest{}, func(req *v1.DeleteQueueRequest) (any, error) {
			return f.storage.DeleteQueue(ctx, req)
		})

	case command.OpPurgeQueue:
		return decodeAnd(cmd, &v1.PurgeQueueRequest{}, func(req *v1.PurgeQueueRequest) (any, error) {
			return f.storage.PurgeQueue(ctx, req)
		})

	case command.OpSend:
		return decodeAnd(cmd, &v1.SendRequest{}, func(req *v1.SendRequest) (any, error) {
			return f.storage.Send(ctx, req)
		})

	case command.OpReceive:
		return decodeAnd(cmd, &v1.ReceiveRequest{}, func(req *v1.ReceiveRequest) (any, error) {
			return f.storage.Receive(ctx, req)
		})

	case command.OpDelete:
		return decodeAnd(cmd, &v1.DeleteRequest{}, func(req *v1.DeleteRequest) (any, error) {
			return f.storage.Delete(ctx, req)
		})

	case command.OpCreateTopic:
		return decodeJSONAnd(cmd, func(req *queue.CreateTopicRequest) (any, error) {
			return f.storage.CreateTopic(ctx, req)
		})

	case command.OpDeleteTopic:
		if err := f.storage.DeleteTopic(ctx, cmd.Target); err != nil {
			return nil, fmt.Errorf("delete topic %q: %w", cmd.Target, err)
		}

		return nil, nil //nolint:nilnil // a delete has no response to return.

	case command.OpSubscribe:
		return decodeJSONAnd(cmd, func(req *queue.SubscribeRequest) (any, error) {
			return f.storage.Subscribe(ctx, cmd.Target, req)
		})

	case command.OpUnsubscribe:
		if len(cmd.IDs) == 0 {
			return nil, errors.New("unsubscribe command carries no subscription id")
		}

		if err := f.storage.Unsubscribe(ctx, cmd.Target, cmd.IDs[0]); err != nil {
			return nil, fmt.Errorf("unsubscribe %q from topic %q: %w", cmd.IDs[0], cmd.Target, err)
		}

		return nil, nil //nolint:nilnil // an unsubscribe has no response to return.

	case command.OpPublish:
		return decodeJSONAnd(cmd, func(req *queue.PublishRequest) (any, error) {
			return f.storage.Publish(ctx, cmd.Target, req)
		})

	case command.OpSweep:
		return f.sweep(ctx, cmd.Target)

	case command.OpUnknown:
		return nil, errors.New("command carries no operation")

	default:
		return nil, fmt.Errorf("unhandled operation %q", cmd.Op)
	}
}

// sweeper is the optional eviction entry point on a store. Sweeping is not
// part of the Storage contract — a backend is free not to need it — so the FSM
// asks rather than requires.
type sweeper interface {
	Sweep(ctx context.Context, queueID string) (uint64, error)
}

func (f *FSM) sweep(ctx context.Context, queueID string) (any, error) {
	s, ok := f.storage.(sweeper)
	if !ok {
		return nil, nil //nolint:nilnil // a backend that cannot sweep has nothing to report.
	}

	dropped, err := s.Sweep(ctx, queueID)
	if err != nil {
		return nil, fmt.Errorf("sweep queue %q: %w", queueID, err)
	}

	return dropped, nil
}

// vtUnmarshaler is the interface the generated schema types satisfy. Using
// vtproto's unmarshal rather than the reflective one keeps the hot path — Send
// and Receive — free of reflection.
type vtUnmarshaler interface {
	UnmarshalVT(data []byte) error
}

// decodeAnd unmarshals a protobuf payload and hands it to fn.
func decodeAnd[T vtUnmarshaler](cmd *command.Command, req T, fn func(T) (any, error)) (any, error) {
	if err := req.UnmarshalVT(cmd.Payload); err != nil {
		return nil, fmt.Errorf("decode %s payload: %w", cmd.Op, err)
	}

	return fn(req)
}

// decodeJSONAnd unmarshals a JSON payload and hands it to fn.
//
// The pub/sub request types are plain Go structs rather than schema messages,
// so they travel as JSON rather than protobuf. Their payloads are small and
// infrequent; the hot path — Send and Receive — does not come through here.
func decodeJSONAnd[T any](cmd *command.Command, fn func(*T) (any, error)) (any, error) {
	var req T

	if err := json.Unmarshal(cmd.Payload, &req); err != nil {
		return nil, fmt.Errorf("decode %s payload: %w", cmd.Op, err)
	}

	return fn(&req)
}
