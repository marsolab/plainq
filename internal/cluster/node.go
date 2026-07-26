package cluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/marsolab/plainq/internal/cluster/consensus"
	raftengine "github.com/marsolab/plainq/internal/cluster/consensus/raft"
	"github.com/marsolab/plainq/internal/cluster/discovery"
	"github.com/marsolab/plainq/internal/cluster/fsm"
	"github.com/marsolab/plainq/internal/cluster/gossip"
	"github.com/marsolab/plainq/internal/cluster/peer"
	"github.com/marsolab/plainq/internal/cluster/transport"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/servekit/logkit"
)

// bootstrapPoll is how often a node waiting on bootstrap-expect re-counts its
// peers.
const bootstrapPoll = 2 * time.Second

// joinRetryInterval is how long a node waits between attempts to be admitted
// to an existing cluster.
const joinRetryInterval = 5 * time.Second

// leaveTimeout bounds the graceful gossip departure on shutdown.
const leaveTimeout = 5 * time.Second

// Node is a PlainQ server's membership in a cluster.
//
// It owns the lifecycle: bring up the transport, join the gossip pool, start
// consensus, and then — for as long as the process runs — keep the consensus
// configuration in step with what gossip can actually see.
type Node struct {
	cfg    Config
	logger *slog.Logger

	mux        *transport.Mux
	gossip     *gossip.Memberlist
	consensus  consensus.Consensus
	fsm        *fsm.FSM
	discoverer discovery.Discoverer
	peerServer *peer.Server
	peerClient *peer.Client
	store      *Store

	// lastSeen records when a member was last observed alive, so the leader
	// can tell "briefly unreachable" from "gone".
	lastSeenMu sync.Mutex
	lastSeen   map[string]time.Time

	// leaderJobs cancels the work that only the leader does.
	leaderMu   sync.Mutex
	leaderJobs context.CancelFunc

	started  bool
	stopOnce sync.Once
	done     chan struct{}
	wg       sync.WaitGroup
}

// NewNode assembles a cluster node around a local store. Nothing listens or
// connects until Start is called.
func NewNode(cfg Config, local queue.ReplicatedStorage, logger *slog.Logger) (*Node, error) {
	if logger == nil {
		logger = logkit.NewNop()
	}

	if err := cfg.Normalize(); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("cluster configuration: %w", err)
	}

	tlsConfig, tlsErr := buildTLSConfig(cfg)
	if tlsErr != nil {
		return nil, tlsErr
	}

	mux, muxErr := transport.New(transport.Config{
		BindAddr:      cfg.BindAddr,
		AdvertiseAddr: cfg.AdvertiseAddr,
		TLSConfig:     tlsConfig,
		Logger:        logger,
	})
	if muxErr != nil {
		return nil, muxErr
	}

	stateMachine := fsm.New(local, logger)

	engine, engineErr := raftengine.New(raftengine.Config{
		NodeID:             cfg.NodeID,
		DataDir:            cfg.DataDir,
		FSM:                stateMachine,
		Mux:                mux,
		HeartbeatTimeout:   cfg.HeartbeatTimeout,
		ElectionTimeout:    cfg.ElectionTimeout,
		LeaderLeaseTimeout: cfg.LeaderLeaseTimeout,
		CommitTimeout:      cfg.CommitTimeout,
		SnapshotInterval:   cfg.SnapshotInterval,
		SnapshotThreshold:  cfg.SnapshotThreshold,
		TrailingLogs:       cfg.TrailingLogs,
		Logger:             logger,
	})
	if engineErr != nil {
		_ = mux.Close()

		return nil, engineErr
	}

	peerClient := peer.NewClient(mux, cfg.Secret)

	storeOpts := []StoreOption{
		WithConsistency(cfg.Consistency),
		WithStoreLogger(logger),
	}

	if cfg.ApplyTimeout > 0 {
		storeOpts = append(storeOpts, WithApplyTimeout(cfg.ApplyTimeout))
	}

	node := Node{
		cfg:        cfg,
		logger:     logger,
		mux:        mux,
		consensus:  engine,
		fsm:        stateMachine,
		peerClient: peerClient,
		store:      NewStore(local, engine, peerClient, storeOpts...),
		lastSeen:   make(map[string]time.Time),
		done:       make(chan struct{}),
	}

	node.peerServer = peer.NewServer(peer.ServerConfig{
		Applier:    engine,
		Membership: engine,
		Secret:     cfg.Secret,
		Logger:     logger,
	})

	return &node, nil
}

// Store returns the queue.Storage the server should use. Every write through
// it is replicated.
func (n *Node) Store() *Store { return n.store }

// Start brings the node up: peer RPC, gossip, discovery, and whichever of
// bootstrap or join applies.
func (n *Node) Start(ctx context.Context) error {
	if n.started {
		return errors.New("cluster node is already started")
	}

	n.started = true

	// Peer RPC first: a node must be able to answer a join before it asks
	// anyone to admit it.
	n.wg.Add(1)

	go func() {
		defer n.wg.Done()

		if err := n.peerServer.Serve(n.mux.Listener(transport.ProtoPeer)); err != nil {
			n.logger.Error("Cluster peer RPC stopped",
				slog.String("error", err.Error()),
			)
		}
	}()

	if err := n.startGossip(); err != nil {
		return err
	}

	if err := n.startDiscovery(ctx); err != nil {
		return err
	}

	n.wg.Add(3)

	go func() { defer n.wg.Done(); n.watchGossip() }()
	go func() { defer n.wg.Done(); n.watchLeadership() }()
	go func() { defer n.wg.Done(); n.discoveryLoop() }()

	if err := n.formCluster(ctx); err != nil {
		return err
	}

	n.registerMetrics()

	n.logger.Info("Cluster node started",
		slog.String("node_id", n.cfg.NodeID),
		slog.String("cluster_addr", n.mux.Addr().String()),
		slog.String("gossip_addr", n.gossip.Local().Addr),
		slog.Bool("non_voter", n.cfg.NonVoter),
	)

	return nil
}

func (n *Node) startGossip() error {
	secret, secretErr := n.cfg.GossipSecretKey()
	if secretErr != nil {
		return secretErr
	}

	role := gossip.RoleVoter
	if n.cfg.NonVoter {
		role = gossip.RoleNonVoter
	}

	bindHost, bindPort, splitErr := splitHostPortInt(n.cfg.GossipAddr)
	if splitErr != nil {
		return splitErr
	}

	advertiseHost, advertisePort, advertiseErr := "", 0, error(nil)

	if n.cfg.GossipAdvertiseAddr != "" {
		advertiseHost, advertisePort, advertiseErr = splitHostPortInt(n.cfg.GossipAdvertiseAddr)
		if advertiseErr != nil {
			return advertiseErr
		}
	}

	memberlist, err := gossip.New(gossip.Config{
		NodeID:        n.cfg.NodeID,
		BindAddr:      bindHost,
		BindPort:      bindPort,
		AdvertiseAddr: advertiseHost,
		AdvertisePort: advertisePort,
		SecretKey:     secret,
		Profile:       gossip.Profile(n.cfg.GossipProfile),
		Logger:        n.logger,
		Meta: gossip.Meta{
			ID:       n.cfg.NodeID,
			RaftAddr: n.mux.Addr().String(),
			Role:     role,
			Version:  n.cfg.Version,
		},
	})
	if err != nil {
		return err
	}

	n.gossip = memberlist

	return nil
}

func (n *Node) startDiscovery(ctx context.Context) error {
	specs := n.cfg.DiscoverySpecs()
	if len(specs) == 0 {
		return nil
	}

	discoverer, err := discovery.ParseAll(specs...)
	if err != nil {
		return err
	}

	n.discoverer = discoverer

	// One discovery pass before anything else runs, so the first join has
	// somebody to contact rather than waiting out an interval.
	n.joinDiscovered(ctx)

	return nil
}

// formCluster decides how this node enters a cluster: by declaring one, by
// waiting for enough peers to declare one together, or by asking an existing
// cluster to admit it.
func (n *Node) formCluster(ctx context.Context) error {
	switch {
	case n.cfg.Bootstrap:
		n.logger.Info("Bootstrapping a single-node cluster",
			slog.String("node_id", n.cfg.NodeID),
		)

		return n.consensus.Bootstrap([]consensus.Server{{
			ID:       n.cfg.NodeID,
			Addr:     n.mux.Addr().String(),
			Suffrage: consensus.SuffrageVoter,
		}})

	case n.cfg.BootstrapExpect > 0:
		n.wg.Add(1)

		go func() { defer n.wg.Done(); n.bootstrapExpect(ctx) }()

		return nil

	default:
		n.wg.Add(1)

		go func() { defer n.wg.Done(); n.joinLoop(ctx) }()

		return nil
	}
}

// bootstrapExpect waits until the configured number of nodes is visible and
// then has exactly one of them form the cluster.
//
// The election is decided by node id rather than by a race: every node sorts
// the same list and only the lowest id calls Bootstrap. Two nodes bootstrapping
// independently would produce two clusters that each believe they are the
// cluster, and there is no automatic recovery from that.
func (n *Node) bootstrapExpect(ctx context.Context) {
	ticker := time.NewTicker(bootstrapPoll)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-n.done:
			return

		case <-ticker.C:
		}

		// A cluster that already exists — because a peer bootstrapped, or
		// because this node restarted — needs no bootstrapping.
		if len(n.consensus.Status().Servers) > 0 {
			return
		}

		members := n.votingMembers()
		if len(members) < n.cfg.BootstrapExpect {
			n.logger.Debug("Waiting for peers before bootstrapping",
				slog.Int("have", len(members)),
				slog.Int("expect", n.cfg.BootstrapExpect),
			)

			continue
		}

		sort.Slice(members, func(i, j int) bool { return members[i].ID < members[j].ID })

		servers := make([]consensus.Server, 0, n.cfg.BootstrapExpect)
		for _, member := range members[:n.cfg.BootstrapExpect] {
			servers = append(servers, consensus.Server{
				ID:       member.ID,
				Addr:     member.RaftAddr,
				Suffrage: consensus.SuffrageVoter,
			})
		}

		if servers[0].ID != n.cfg.NodeID {
			n.logger.Info("Deferring bootstrap to the lowest-numbered node",
				slog.String("bootstrapper", servers[0].ID),
			)

			// The chosen node will bootstrap and this one will be in its
			// configuration, so there is nothing further to do.
			return
		}

		n.logger.Info("Bootstrapping cluster",
			slog.Int("nodes", len(servers)),
		)

		if err := n.consensus.Bootstrap(servers); err != nil {
			n.logger.Error("Failed to bootstrap cluster",
				slog.String("error", err.Error()),
			)

			continue
		}

		return
	}
}

// joinLoop asks a known peer to admit this node, until one does.
func (n *Node) joinLoop(ctx context.Context) {
	ticker := time.NewTicker(joinRetryInterval)
	defer ticker.Stop()

	for {
		if len(n.consensus.Status().Servers) > 0 {
			// Either a peer admitted this node, or it restarted with a
			// configuration it already had. Either way it is a member.
			return
		}

		if n.requestJoin(ctx) {
			return
		}

		select {
		case <-ctx.Done():
			return

		case <-n.done:
			return

		case <-ticker.C:
		}
	}
}

// requestJoin asks every known peer, in turn, to admit this node. It reports
// whether one of them did.
func (n *Node) requestJoin(ctx context.Context) bool {
	request := peer.JoinRequest{
		NodeID:   n.cfg.NodeID,
		Addr:     n.mux.Addr().String(),
		NonVoter: n.cfg.NonVoter,
	}

	for _, member := range n.gossip.Members() {
		if member.ID == n.cfg.NodeID || member.RaftAddr == "" {
			continue
		}

		callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		response, err := n.peerClient.Join(callCtx, member.RaftAddr, request)

		cancel()

		if err != nil {
			// Asking a follower is expected — it does not know it is not the
			// leader until it tries — so this is a debug line, not a warning.
			n.logger.Debug("Peer did not admit this node",
				slog.String("peer", member.RaftAddr),
				slog.String("error", err.Error()),
			)

			continue
		}

		n.logger.Info("Joined cluster",
			slog.String("admitted_by", response.LeaderID),
			slog.Int("servers", len(response.Servers)),
		)

		return true
	}

	return false
}

// discoveryLoop re-runs discovery and feeds the results to gossip.
//
// It keeps running for the life of the node rather than stopping once the
// cluster forms: deployments scale, pods move, and a node that stopped looking
// would never learn about the replacement for a peer it lost.
func (n *Node) discoveryLoop() {
	if n.discoverer == nil {
		return
	}

	ticker := time.NewTicker(n.cfg.DiscoveryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-n.done:
			return

		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), n.cfg.DiscoveryInterval)
			n.joinDiscovered(ctx)
			cancel()
		}
	}
}

// joinDiscovered runs one discovery pass and hands the addresses to gossip.
func (n *Node) joinDiscovered(ctx context.Context) {
	peers, err := n.discoverer.Discover(ctx)
	if err != nil {
		n.logger.Warn("Peer discovery failed",
			slog.String("provider", n.discoverer.Name()),
			slog.String("error", err.Error()),
		)

		if len(peers) == 0 {
			return
		}
	}

	// Discovery hands back gossip addresses. A peer's consensus address is
	// part of what it gossips, so it is learned from the peer itself rather
	// than guessed at from here.
	addrs := make([]string, 0, len(peers))

	for _, p := range peers {
		if p.Addr == "" || p.Addr == n.gossip.Local().Addr {
			continue
		}

		addrs = append(addrs, p.Addr)
	}

	if len(addrs) == 0 {
		return
	}

	contacted, joinErr := n.gossip.Join(ctx, addrs)
	if joinErr != nil {
		n.logger.Debug("Could not contact any discovered peer",
			slog.Int("candidates", len(addrs)),
			slog.String("error", joinErr.Error()),
		)

		return
	}

	if contacted > 0 {
		n.logger.Debug("Contacted discovered peers",
			slog.Int("contacted", contacted),
			slog.Int("candidates", len(addrs)),
		)
	}
}

// watchGossip records liveness. The leader's reconciler reads what it writes.
func (n *Node) watchGossip() {
	events := n.gossip.Events()

	for {
		select {
		case <-n.done:
			return

		case event, ok := <-events:
			if !ok {
				return
			}

			switch event.Type {
			case gossip.EventJoin, gossip.EventUpdate:
				n.markSeen(event.Member.ID)

				n.logger.Info("Cluster member is alive",
					slog.String("node_id", event.Member.ID),
					slog.String("address", event.Member.Addr),
					slog.String("role", string(event.Member.Role)),
				)

			case gossip.EventLeave:
				n.logger.Warn("Cluster member is unreachable",
					slog.String("node_id", event.Member.ID),
					slog.String("address", event.Member.Addr),
				)
			}
		}
	}
}

// watchLeadership starts and stops the work only the leader may do.
func (n *Node) watchLeadership() {
	for {
		select {
		case <-n.done:
			n.stopLeaderJobs()

			return

		case isLeader, ok := <-n.consensus.LeaderCh():
			if !ok {
				return
			}

			if isLeader {
				n.startLeaderJobs()
			} else {
				n.logger.Info("Lost cluster leadership")
				n.stopLeaderJobs()
			}
		}
	}
}

func (n *Node) startLeaderJobs() {
	n.leaderMu.Lock()
	defer n.leaderMu.Unlock()

	if n.leaderJobs != nil {
		return
	}

	n.logger.Info("Became cluster leader",
		slog.String("node_id", n.cfg.NodeID),
	)

	ctx, cancel := context.WithCancel(context.Background())
	n.leaderJobs = cancel

	n.wg.Add(2)

	go func() { defer n.wg.Done(); n.reconcileLoop(ctx) }()
	go func() { defer n.wg.Done(); n.sweepLoop(ctx) }()
}

func (n *Node) stopLeaderJobs() {
	n.leaderMu.Lock()
	defer n.leaderMu.Unlock()

	if n.leaderJobs == nil {
		return
	}

	n.leaderJobs()
	n.leaderJobs = nil
}

// reconcileLoop keeps the consensus configuration in step with gossip.
func (n *Node) reconcileLoop(ctx context.Context) {
	ticker := time.NewTicker(n.cfg.ReconcileInterval)
	defer ticker.Stop()

	// Reconcile immediately on becoming leader: whatever changed during the
	// election is exactly what wants attention.
	n.reconcile(ctx)

	for {
		select {
		case <-ctx.Done():
			return

		case <-n.done:
			return

		case <-ticker.C:
			n.reconcile(ctx)
		}
	}
}

// reconcile adds members gossip can see and are missing from the
// configuration, and removes members that have been gone long enough.
func (n *Node) reconcile(ctx context.Context) {
	if !n.consensus.IsLeader() {
		return
	}

	status := n.consensus.Status()

	configured := make(map[string]consensus.Server, len(status.Servers))
	for _, server := range status.Servers {
		configured[server.ID] = server
	}

	alive := make(map[string]gossip.Member)

	for _, member := range n.gossip.Members() {
		if member.ID == "" || member.RaftAddr == "" {
			continue
		}

		alive[member.ID] = member
		n.markSeen(member.ID)

		if _, known := configured[member.ID]; known {
			continue
		}

		n.admit(ctx, member)
	}

	if !n.cfg.AutoRemove {
		return
	}

	for id, server := range configured {
		if id == n.cfg.NodeID {
			continue
		}

		if _, isAlive := alive[id]; isAlive {
			continue
		}

		if !n.goneLongerThan(id, n.cfg.RemoveTimeout) {
			continue
		}

		n.logger.Warn("Removing a cluster member that has been unreachable",
			slog.String("node_id", id),
			slog.String("address", server.Addr),
			slog.String("timeout", n.cfg.RemoveTimeout.String()),
		)

		if err := n.consensus.RemoveServer(ctx, id); err != nil {
			n.logger.Error("Failed to remove an unreachable cluster member",
				slog.String("node_id", id),
				slog.String("error", err.Error()),
			)

			continue
		}

		n.forget(id)
	}
}

// admit adds a member gossip found to the consensus configuration.
func (n *Node) admit(ctx context.Context, member gossip.Member) {
	var err error

	if member.Role == gossip.RoleNonVoter {
		err = n.consensus.AddNonVoter(ctx, member.ID, member.RaftAddr)
	} else {
		err = n.consensus.AddVoter(ctx, member.ID, member.RaftAddr)
	}

	if err != nil {
		n.logger.Error("Failed to add a discovered member to the cluster",
			slog.String("node_id", member.ID),
			slog.String("address", member.RaftAddr),
			slog.String("error", err.Error()),
		)

		return
	}

	n.logger.Info("Added a discovered member to the cluster",
		slog.String("node_id", member.ID),
		slog.String("address", member.RaftAddr),
		slog.String("role", string(member.Role)),
	)
}

// sweepLoop proposes queue eviction from the leader.
//
// Eviction changes replicated state, so it cannot be a local timer on every
// node — each would delete a slightly different set of rows and the replicas
// would drift apart. One node decides; the log carries the decision.
func (n *Node) sweepLoop(ctx context.Context) {
	ticker := time.NewTicker(n.cfg.SweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-n.done:
			return

		case <-ticker.C:
			n.sweep(ctx)
		}
	}
}

func (n *Node) sweep(ctx context.Context) {
	queues, err := n.store.local.ListQueues(ctx, listAllQueues())
	if err != nil {
		n.logger.Error("Failed to list queues for cluster eviction",
			slog.String("error", err.Error()),
		)

		return
	}

	for _, q := range queues.GetQueues() {
		if !n.consensus.IsLeader() {
			return
		}

		dropped, sweepErr := n.store.Sweep(ctx, q.GetQueueId())
		if sweepErr != nil {
			n.logger.Error("Cluster eviction failed for a queue",
				slog.String("queue_id", q.GetQueueId()),
				slog.String("error", sweepErr.Error()),
			)

			continue
		}

		if dropped > 0 {
			n.logger.Debug("Cluster eviction removed messages",
				slog.String("queue_id", q.GetQueueId()),
				slog.Uint64("messages", dropped),
			)
		}
	}
}

// Join admits a node to the cluster. It is the manual path — the API and the
// CLI — alongside the automatic one that reconciliation drives.
func (n *Node) Join(ctx context.Context, nodeID, addr string, nonVoter bool) error {
	if nonVoter {
		return n.consensus.AddNonVoter(ctx, nodeID, addr)
	}

	return n.consensus.AddVoter(ctx, nodeID, addr)
}

// Remove drops a node from the cluster configuration.
func (n *Node) Remove(ctx context.Context, nodeID string) error {
	if err := n.consensus.RemoveServer(ctx, nodeID); err != nil {
		return err
	}

	n.forget(nodeID)

	return nil
}

// Snapshot forces a state machine snapshot, compacting the consensus log.
func (n *Node) Snapshot(ctx context.Context) error { return n.consensus.Snapshot(ctx) }

// Leave takes this node out of the cluster deliberately: it hands leadership
// on, asks the leader to drop it from the configuration, and announces its
// departure over gossip.
//
// It is the difference between a planned scale-down and a failure. Without it,
// the remaining nodes carry a configuration entry for a node that is never
// coming back, and quorum is computed against a member that does not exist.
func (n *Node) Leave(ctx context.Context) error {
	if n.gossip == nil {
		return nil
	}

	var errs []error

	// Ask the leader to remove this node first, while it can still be reached
	// through a healthy cluster.
	if _, addr, err := n.consensus.Leader(); err == nil {
		if n.consensus.IsLeader() {
			if removeErr := n.consensus.RemoveServer(ctx, n.cfg.NodeID); removeErr != nil {
				errs = append(errs, removeErr)
			}
		} else if leaveErr := n.peerClient.Leave(ctx, addr, n.cfg.NodeID); leaveErr != nil {
			errs = append(errs, leaveErr)
		}
	}

	if err := n.gossip.Leave(leaveTimeout); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// Close stops the node. It does not leave the cluster — a restart is not a
// departure, and a node that removed itself on every shutdown could never be
// restarted into the cluster it belongs to. Call Leave for that.
func (n *Node) Close() error {
	var errs []error

	n.stopOnce.Do(func() {
		close(n.done)
		n.stopLeaderJobs()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if n.peerServer != nil {
			if err := n.peerServer.Shutdown(shutdownCtx); err != nil {
				errs = append(errs, err)
			}
		}

		if n.consensus != nil {
			if err := n.consensus.Close(); err != nil {
				errs = append(errs, err)
			}
		}

		if n.gossip != nil {
			if err := n.gossip.Close(); err != nil {
				errs = append(errs, err)
			}
		}

		if n.discoverer != nil {
			if err := n.discoverer.Close(); err != nil {
				errs = append(errs, err)
			}
		}

		if n.mux != nil {
			if err := n.mux.Close(); err != nil {
				errs = append(errs, err)
			}
		}

		n.wg.Wait()
	})

	return errors.Join(errs...)
}

func (n *Node) votingMembers() []gossip.Member {
	members := n.gossip.Members()
	voters := make([]gossip.Member, 0, len(members))

	for _, member := range members {
		if member.Role == gossip.RoleNonVoter || member.RaftAddr == "" || member.ID == "" {
			continue
		}

		voters = append(voters, member)
	}

	return voters
}

func (n *Node) markSeen(id string) {
	n.lastSeenMu.Lock()
	defer n.lastSeenMu.Unlock()

	n.lastSeen[id] = time.Now()
}

func (n *Node) forget(id string) {
	n.lastSeenMu.Lock()
	defer n.lastSeenMu.Unlock()

	delete(n.lastSeen, id)
}

// goneLongerThan reports whether a member has been absent for at least d. A
// member never seen at all is treated as absent since this node started, which
// is what makes a node in a stale configuration eventually removable.
func (n *Node) goneLongerThan(id string, d time.Duration) bool {
	n.lastSeenMu.Lock()
	defer n.lastSeenMu.Unlock()

	seen, ok := n.lastSeen[id]
	if !ok {
		n.lastSeen[id] = time.Now()

		return false
	}

	return time.Since(seen) >= d
}

// buildTLSConfig loads the cluster's mutual-TLS material. Cluster traffic
// carries every message body in the system, so both ends authenticate.
func buildTLSConfig(cfg Config) (*tls.Config, error) {
	if cfg.TLSCertFile == "" {
		return nil, nil //nolint:nilnil // no TLS configured is a valid, explicit outcome.
	}

	certificate, certErr := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if certErr != nil {
		return nil, fmt.Errorf("load cluster TLS certificate: %w", certErr)
	}

	pem, caErr := os.ReadFile(cfg.TLSCAFile)
	if caErr != nil {
		return nil, fmt.Errorf("read cluster TLS CA: %w", caErr)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("cluster TLS CA file holds no usable certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      pool,
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,

		// Nodes dial each other by IP, which no certificate is issued for.
		// Verification is against the cluster CA, which is the property that
		// matters: the peer holds a certificate this cluster issued.
		InsecureSkipVerify:    true, //nolint:gosec // see VerifyPeerCertificate below.
		VerifyPeerCertificate: verifyAgainstPool(pool),
	}, nil
}

// verifyAgainstPool checks a peer's chain against the cluster CA without
// requiring the hostname to match, since peers are addressed by IP.
func verifyAgainstPool(pool *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("cluster peer presented no certificate")
		}

		certificates := make([]*x509.Certificate, 0, len(rawCerts))

		for _, raw := range rawCerts {
			parsed, err := x509.ParseCertificate(raw)
			if err != nil {
				return fmt.Errorf("parse cluster peer certificate: %w", err)
			}

			certificates = append(certificates, parsed)
		}

		intermediates := x509.NewCertPool()
		for _, certificate := range certificates[1:] {
			intermediates.AddCert(certificate)
		}

		if _, err := certificates[0].Verify(x509.VerifyOptions{
			Roots:         pool,
			Intermediates: intermediates,
		}); err != nil {
			return fmt.Errorf("cluster peer certificate is not trusted: %w", err)
		}

		return nil
	}
}
