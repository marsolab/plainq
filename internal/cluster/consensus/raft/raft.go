// Package raft implements consensus.Consensus on top of hashicorp/raft.
//
// Raft was chosen over Paxos for one practical reason above the theory: a
// queue's writes are already a totally ordered sequence of discrete commands,
// which is exactly the shape of a Raft log, and Raft treats membership change
// as part of the protocol rather than an exercise for the reader — which is
// what a cluster that discovers its own members needs.
package raft

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	hraft "github.com/hashicorp/raft"
	boltstore "github.com/hashicorp/raft-boltdb/v2"
	"github.com/marsolab/plainq/internal/cluster/consensus"
	"github.com/marsolab/plainq/internal/cluster/transport"
	"github.com/marsolab/servekit/logkit"
)

// Defaults for the log store and snapshotting. They are the hashicorp defaults
// unless noted; the ones that differ are called out where they are used.
const (
	// retainedSnapshots is how many snapshots are kept on disk. Two is enough
	// to roll back from a snapshot that turns out to be unreadable, without
	// keeping a directory of them forever.
	retainedSnapshots = 2

	// maxAppendEntries caps how many log entries travel in one replication
	// round trip.
	maxAppendEntries = 64

	// applyTimeout bounds a single Apply when the caller gave no deadline.
	applyTimeout = 10 * time.Second

	// membershipTimeout bounds a configuration change.
	membershipTimeout = 15 * time.Second

	// dialTimeout bounds a connection to a peer's consensus port.
	dialTimeout = 10 * time.Second

	// transportPool is how many idle connections per peer the transport keeps.
	transportPool = 3
)

// Compilation time check that Engine implements consensus.Consensus.
var _ consensus.Consensus = (*Engine)(nil)

// Config configures the Raft engine.
type Config struct {
	// NodeID is this node's stable cluster identity. Reusing an id for a node
	// with different state is how a cluster corrupts itself, so it must
	// outlive restarts and belong to exactly one node.
	NodeID string

	// DataDir holds the log store and the snapshots.
	DataDir string

	// FSM is the state machine the committed log is applied to.
	FSM hraft.FSM

	// Mux carries the consensus protocol. The engine takes a listener and a
	// dialer from it rather than binding its own port.
	Mux *transport.Mux

	// HeartbeatTimeout, ElectionTimeout, LeaderLeaseTimeout and CommitTimeout
	// tune failure detection. Zero takes the library default, which suits a
	// LAN; a WAN cluster wants them raised together.
	HeartbeatTimeout   time.Duration
	ElectionTimeout    time.Duration
	LeaderLeaseTimeout time.Duration
	CommitTimeout      time.Duration

	// SnapshotInterval and SnapshotThreshold decide when the log is compacted.
	SnapshotInterval  time.Duration
	SnapshotThreshold uint64

	// TrailingLogs is how many entries are kept after a snapshot so a briefly
	// lagging follower can catch up from the log instead of a full transfer.
	TrailingLogs uint64

	// Logger receives engine diagnostics.
	Logger *slog.Logger
}

// Engine is the hashicorp/raft implementation of consensus.Consensus.
type Engine struct {
	raft      *hraft.Raft
	transport *hraft.NetworkTransport
	logStore  *boltstore.BoltStore
	logger    *slog.Logger
	nodeID    string
	leaderCh  chan bool
	done      chan struct{}
}

// New starts the engine. The node begins as a follower with no configuration:
// it neither leads nor votes until it is bootstrapped or joined to a cluster.
func New(cfg Config) (*Engine, error) {
	if cfg.NodeID == "" {
		return nil, errors.New("raft: node id is required")
	}

	if cfg.FSM == nil {
		return nil, errors.New("raft: state machine is required")
	}

	if cfg.Mux == nil {
		return nil, errors.New("raft: transport mux is required")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = logkit.NewNop()
	}

	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return nil, fmt.Errorf("create raft data directory %q: %w", cfg.DataDir, err)
	}

	// One BoltDB holds both the log and the stable store. Its writes are
	// fsynced, which is what makes a committed entry survive a crash — the
	// property the whole protocol rests on.
	logStore, logStoreErr := boltstore.NewBoltStore(filepath.Join(cfg.DataDir, "raft.db"))
	if logStoreErr != nil {
		return nil, fmt.Errorf("open raft log store: %w", logStoreErr)
	}

	snapshots, snapshotErr := hraft.NewFileSnapshotStoreWithLogger(
		cfg.DataDir, retainedSnapshots, newHCLogAdapter(logger, "raft.snapshot"),
	)
	if snapshotErr != nil {
		_ = logStore.Close()

		return nil, fmt.Errorf("open raft snapshot store: %w", snapshotErr)
	}

	stream := &streamLayer{mux: cfg.Mux, listener: cfg.Mux.Listener(transport.ProtoRaft)}

	netTransport := hraft.NewNetworkTransportWithLogger(
		stream, transportPool, dialTimeout, newHCLogAdapter(logger, "raft.transport"),
	)

	raftConfig := hraft.DefaultConfig()
	raftConfig.LocalID = hraft.ServerID(cfg.NodeID)
	raftConfig.Logger = newHCLogAdapter(logger, "raft")
	raftConfig.MaxAppendEntries = maxAppendEntries

	// The engine owns leadership notifications: LeaderCh on the raft handle is
	// a single consumer, and both the reconciler and the sweeper need to know.
	notify := make(chan bool, 8)
	raftConfig.NotifyCh = notify

	applyTuning(raftConfig, cfg)

	node, raftErr := hraft.NewRaft(raftConfig, cfg.FSM, logStore, logStore, snapshots, netTransport)
	if raftErr != nil {
		_ = netTransport.Close()
		_ = logStore.Close()

		return nil, fmt.Errorf("start raft: %w", raftErr)
	}

	e := Engine{
		raft:      node,
		transport: netTransport,
		logStore:  logStore,
		logger:    logger,
		nodeID:    cfg.NodeID,
		leaderCh:  make(chan bool, 8),
		done:      make(chan struct{}),
	}

	go e.forwardLeadership(notify)

	return &e, nil
}

func applyTuning(raftConfig *hraft.Config, cfg Config) {
	if cfg.HeartbeatTimeout > 0 {
		raftConfig.HeartbeatTimeout = cfg.HeartbeatTimeout
	}

	if cfg.ElectionTimeout > 0 {
		raftConfig.ElectionTimeout = cfg.ElectionTimeout
	}

	if cfg.LeaderLeaseTimeout > 0 {
		raftConfig.LeaderLeaseTimeout = cfg.LeaderLeaseTimeout
	}

	if cfg.CommitTimeout > 0 {
		raftConfig.CommitTimeout = cfg.CommitTimeout
	}

	if cfg.SnapshotInterval > 0 {
		raftConfig.SnapshotInterval = cfg.SnapshotInterval
	}

	if cfg.SnapshotThreshold > 0 {
		raftConfig.SnapshotThreshold = cfg.SnapshotThreshold
	}

	if cfg.TrailingLogs > 0 {
		raftConfig.TrailingLogs = cfg.TrailingLogs
	}
}

// forwardLeadership fans raft's single notification channel out to the
// engine's, so several subscribers can react to a leadership change.
func (e *Engine) forwardLeadership(notify <-chan bool) {
	for {
		select {
		case <-e.done:
			return

		case isLeader, ok := <-notify:
			if !ok {
				return
			}

			select {
			case e.leaderCh <- isLeader:

			default:
				// A subscriber that is not reading leadership changes will
				// pick up the current state from Status; losing the edge is
				// better than blocking raft's own goroutine.
				e.logger.Warn("Dropped a leadership notification, subscriber is behind",
					slog.Bool("leader", isLeader),
				)
			}
		}
	}
}

// Apply implements consensus.Consensus.
func (e *Engine) Apply(ctx context.Context, data []byte) (any, error) {
	if e.raft.State() != hraft.Leader {
		return nil, consensus.ErrNotLeader
	}

	timeout := applyTimeout

	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 {
			timeout = remaining
		}
	}

	future := e.raft.Apply(data, timeout)

	if err := waitFuture(ctx, future); err != nil {
		return nil, err
	}

	// The state machine reports a failed command by returning an error value.
	// Raft has no opinion on it — the entry is committed either way — so the
	// unwrapping happens here.
	if err, isErr := future.Response().(error); isErr {
		return nil, err
	}

	return future.Response(), nil
}

// IsLeader implements consensus.Consensus.
func (e *Engine) IsLeader() bool { return e.raft.State() == hraft.Leader }

// Leader implements consensus.Consensus.
//
//nolint:nonamedreturns // two bare strings need naming; the interface names them too.
func (e *Engine) Leader() (id, addr string, err error) {
	leaderAddr, leaderID := e.raft.LeaderWithID()
	if leaderAddr == "" || leaderID == "" {
		return "", "", consensus.ErrNoLeader
	}

	return string(leaderID), string(leaderAddr), nil
}

// Status implements consensus.Consensus.
func (e *Engine) Status() consensus.Status {
	stats := e.raft.Stats()

	leaderAddr, leaderID := e.raft.LeaderWithID()

	status := consensus.Status{
		NodeID:       e.nodeID,
		State:        toState(e.raft.State()),
		LeaderID:     string(leaderID),
		LeaderAddr:   string(leaderAddr),
		Term:         parseUint(stats["term"]),
		LastIndex:    e.raft.LastIndex(),
		CommitIndex:  parseUint(stats["commit_index"]),
		AppliedIndex: e.raft.AppliedIndex(),
		Engine:       "raft",
	}

	// A configuration read can block during a leadership change. Reporting
	// status must not, so a failed read leaves the server list empty rather
	// than stalling a status endpoint.
	future := e.raft.GetConfiguration()
	if err := future.Error(); err == nil {
		for _, server := range future.Configuration().Servers {
			status.Servers = append(status.Servers, consensus.Server{
				ID:       string(server.ID),
				Addr:     string(server.Address),
				Suffrage: toSuffrage(server.Suffrage),
			})
		}
	}

	return status
}

// AddVoter implements consensus.Consensus.
func (e *Engine) AddVoter(ctx context.Context, id, addr string) error {
	if !e.IsLeader() {
		return consensus.ErrNotLeader
	}

	future := e.raft.AddVoter(hraft.ServerID(id), hraft.ServerAddress(addr), 0, membershipTimeout)

	if err := waitFuture(ctx, future); err != nil {
		return fmt.Errorf("add voter %q (%s): %w", id, addr, err)
	}

	return nil
}

// AddNonVoter implements consensus.Consensus.
func (e *Engine) AddNonVoter(ctx context.Context, id, addr string) error {
	if !e.IsLeader() {
		return consensus.ErrNotLeader
	}

	future := e.raft.AddNonvoter(hraft.ServerID(id), hraft.ServerAddress(addr), 0, membershipTimeout)

	if err := waitFuture(ctx, future); err != nil {
		return fmt.Errorf("add non-voter %q (%s): %w", id, addr, err)
	}

	return nil
}

// RemoveServer implements consensus.Consensus.
func (e *Engine) RemoveServer(ctx context.Context, id string) error {
	if !e.IsLeader() {
		return consensus.ErrNotLeader
	}

	future := e.raft.RemoveServer(hraft.ServerID(id), 0, membershipTimeout)

	if err := waitFuture(ctx, future); err != nil {
		return fmt.Errorf("remove server %q: %w", id, err)
	}

	return nil
}

// Bootstrap implements consensus.Consensus.
func (e *Engine) Bootstrap(servers []consensus.Server) error {
	configuration := hraft.Configuration{Servers: make([]hraft.Server, 0, len(servers))}

	for _, server := range servers {
		suffrage := hraft.Voter
		if server.Suffrage == consensus.SuffrageNonVoter {
			suffrage = hraft.Nonvoter
		}

		configuration.Servers = append(configuration.Servers, hraft.Server{
			ID:       hraft.ServerID(server.ID),
			Address:  hraft.ServerAddress(server.Addr),
			Suffrage: suffrage,
		})
	}

	if err := e.raft.BootstrapCluster(configuration).Error(); err != nil {
		// Raft refuses to bootstrap a node that already has state. That is the
		// guard working: a restart must rejoin its cluster, not declare a new
		// one, so the caller treats this as "already bootstrapped".
		if errors.Is(err, hraft.ErrCantBootstrap) {
			return nil
		}

		return fmt.Errorf("bootstrap cluster: %w", err)
	}

	return nil
}

// Barrier implements consensus.Consensus.
func (e *Engine) Barrier(ctx context.Context) error {
	if !e.IsLeader() {
		return consensus.ErrNotLeader
	}

	timeout := applyTimeout

	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 {
			timeout = remaining
		}
	}

	if err := waitFuture(ctx, e.raft.Barrier(timeout)); err != nil {
		return fmt.Errorf("consensus barrier: %w", err)
	}

	return nil
}

// LeaderCh implements consensus.Consensus.
func (e *Engine) LeaderCh() <-chan bool { return e.leaderCh }

// Snapshot implements consensus.Consensus.
func (e *Engine) Snapshot(ctx context.Context) error {
	if err := waitFuture(ctx, e.raft.Snapshot()); err != nil {
		return fmt.Errorf("take snapshot: %w", err)
	}

	return nil
}

// LastContact implements consensus.Consensus.
func (e *Engine) LastContact() time.Duration {
	last := e.raft.LastContact()
	if last.IsZero() {
		return 0
	}

	return time.Since(last)
}

// Close implements consensus.Consensus. A leader steps down first so the
// cluster elects a successor immediately rather than waiting out an election
// timeout on a node that is already gone.
func (e *Engine) Close() error {
	close(e.done)

	if e.IsLeader() {
		if err := e.raft.LeadershipTransfer().Error(); err != nil {
			e.logger.Debug("Could not hand off leadership before shutdown",
				slog.String("error", err.Error()),
			)
		}
	}

	var errs []error

	if err := e.raft.Shutdown().Error(); err != nil {
		errs = append(errs, fmt.Errorf("shut down raft: %w", err))
	}

	if err := e.transport.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close raft transport: %w", err))
	}

	if err := e.logStore.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close raft log store: %w", err))
	}

	return errors.Join(errs...)
}

// waitFuture waits for a raft future, honoring the caller's cancellation.
//
// Abandoning a future does not abandon the operation — raft continues with it —
// so this reports that the caller stopped waiting, not that nothing happened.
func waitFuture(ctx context.Context, future hraft.Future) error {
	done := make(chan error, 1)

	go func() { done <- future.Error() }()

	select {
	case <-ctx.Done():
		return ctx.Err()

	case err := <-done:
		if err == nil {
			return nil
		}

		// Translate raft's leadership errors into the package's, so callers
		// match on one vocabulary and can act on it.
		switch {
		case errors.Is(err, hraft.ErrNotLeader), errors.Is(err, hraft.ErrLeadershipLost),
			errors.Is(err, hraft.ErrLeadershipTransferInProgress):
			return consensus.ErrNotLeader

		case errors.Is(err, hraft.ErrRaftShutdown):
			return consensus.ErrShutdown

		default:
			return err
		}
	}
}

func toState(state hraft.RaftState) consensus.State {
	switch state {
	case hraft.Leader:
		return consensus.StateLeader

	case hraft.Follower:
		return consensus.StateFollower

	case hraft.Candidate:
		return consensus.StateCandidate

	case hraft.Shutdown:
		return consensus.StateShutdown

	default:
		return consensus.State(state.String())
	}
}

func toSuffrage(suffrage hraft.ServerSuffrage) consensus.Suffrage {
	switch suffrage {
	case hraft.Voter:
		return consensus.SuffrageVoter

	case hraft.Nonvoter:
		return consensus.SuffrageNonVoter

	case hraft.Staging:
		return consensus.SuffrageStaging

	default:
		return consensus.Suffrage(suffrage.String())
	}
}

func parseUint(raw string) uint64 {
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0
	}

	return value
}

// streamLayer adapts the cluster transport mux to raft's StreamLayer.
type streamLayer struct {
	mux      *transport.Mux
	listener net.Listener
}

// Accept implements raft.StreamLayer.
func (s *streamLayer) Accept() (net.Conn, error) {
	conn, err := s.listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("accept consensus connection: %w", err)
	}

	return conn, nil
}

// Close implements raft.StreamLayer.
func (s *streamLayer) Close() error {
	if err := s.listener.Close(); err != nil {
		return fmt.Errorf("close consensus listener: %w", err)
	}

	return nil
}

// Addr implements raft.StreamLayer.
func (s *streamLayer) Addr() net.Addr { return s.listener.Addr() }

// Dial implements raft.StreamLayer.
func (s *streamLayer) Dial(address hraft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	conn, err := s.mux.Dial(transport.ProtoRaft, string(address), timeout)
	if err != nil {
		return nil, fmt.Errorf("dial consensus peer: %w", err)
	}

	return conn, nil
}
