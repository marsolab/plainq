package metrics

import "time"

// Cluster label names.
const (
	labelNodeID       = "node_id"
	labelVersion      = "version"
	labelEngine       = "engine"
	labelState        = "state"
	labelKind         = "kind"
	labelDirection    = "direction"
	labelAction       = "action"
	labelPath         = "path"
	labelEventType    = "type"
	labelProviderName = "provider"
)

// Gossip member states, as the membership layer reports them.
const (
	GossipStateAlive   = "alive"
	GossipStateSuspect = "suspect"
	GossipStateLeft    = "left"
	GossipStateFailed  = "failed"
)

// Membership actions the leader takes when reconciling gossip against the
// consensus configuration.
const (
	MembershipAddVoter    = "add_voter"
	MembershipAddNonVoter = "add_non_voter"
	MembershipRemove      = "remove"
)

// Transport connection directions.
const (
	DirectionInbound  = "inbound"
	DirectionOutbound = "outbound"
)

// ClusterSample is the cluster state a scrape reads.
//
// It is a plain struct rather than the cluster package's own Status so that
// this package stays a leaf: metrics must not depend on the subsystems they
// measure, or every one of them ends up importing every other.
type ClusterSample struct {
	// Leader reports whether this node is the leader.
	Leader bool

	// Healthy reports whether the cluster can currently commit a write.
	Healthy bool

	// Term is the current consensus term.
	Term uint64

	// CommitIndex, AppliedIndex and LastIndex describe the log. The gap
	// between the first two is this replica's lag.
	CommitIndex  uint64
	AppliedIndex uint64
	LastIndex    uint64

	// Voters is how many voting members the configuration holds, Members how
	// many members of any kind, Reachable how many gossip can currently see,
	// and Quorum how many voters a write needs.
	Voters    int
	Members   int
	Reachable int
	Quorum    int

	// AppliedCommands and FailedCommands count what the state machine did.
	AppliedCommands uint64
	FailedCommands  uint64

	// LastContact is how long ago this follower heard from the leader.
	LastContact time.Duration
}

// Cluster metric definitions that carry the node id and are registered once
// per process.
var (
	clusterLeaderDef = define(Definition{
		Kind:   KindGauge,
		Name:   Namespace + "_cluster_leader",
		Help:   "1 on the leader, 0 on followers. Summed across a cluster this should be exactly 1.",
		Labels: []string{labelNodeID},
	})

	clusterHealthyDef = define(Definition{
		Kind:   KindGauge,
		Name:   Namespace + "_cluster_healthy",
		Help:   "1 when the cluster can commit a write. Alert on 0 — this is the metric that means the queue is down.",
		Labels: []string{labelNodeID},
	})

	clusterTermDef = define(Definition{
		Kind:   KindGauge,
		Name:   Namespace + "_cluster_term",
		Help:   "Current consensus term. Climbing steadily means the cluster keeps re-electing.",
		Labels: []string{labelNodeID},
	})

	clusterCommitIndexDef = define(Definition{
		Kind:   KindGauge,
		Name:   Namespace + "_cluster_commit_index",
		Help:   "Highest committed log index.",
		Labels: []string{labelNodeID},
	})

	clusterAppliedIndexDef = define(Definition{
		Kind:   KindGauge,
		Name:   Namespace + "_cluster_applied_index",
		Help:   "Highest log index this node has applied. Its distance from the commit index is this replica's lag.",
		Labels: []string{labelNodeID},
	})

	clusterLastIndexDef = define(Definition{
		Kind:   KindGauge,
		Name:   Namespace + "_cluster_last_index",
		Help:   "Last log index stored locally.",
		Labels: []string{labelNodeID},
	})

	clusterVotersDef = define(Definition{
		Kind:   KindGauge,
		Name:   Namespace + "_cluster_voters",
		Help:   "Voting members in the consensus configuration.",
		Labels: []string{labelNodeID},
	})

	clusterMembersDef = define(Definition{
		Kind:   KindGauge,
		Name:   Namespace + "_cluster_members",
		Help:   "Members known to this node, voters and non-voters alike.",
		Labels: []string{labelNodeID},
	})

	clusterReachableDef = define(Definition{
		Kind:   KindGauge,
		Name:   Namespace + "_cluster_members_reachable",
		Help:   "Members gossip can currently see. Below quorum and the cluster cannot commit.",
		Labels: []string{labelNodeID},
	})

	clusterQuorumDef = define(Definition{
		Kind:   KindGauge,
		Name:   Namespace + "_cluster_quorum",
		Help:   "Voters a write needs. Compare against members_reachable to see how many more failures the cluster survives.",
		Labels: []string{labelNodeID},
	})

	clusterAppliedCommandsDef = define(Definition{
		Kind:   KindCounter,
		Name:   Namespace + "_cluster_commands_applied_total",
		Help:   "Commands applied to the local replica.",
		Labels: []string{labelNodeID},
	})

	clusterFailedCommandsDef = define(Definition{
		Kind:   KindCounter,
		Name:   Namespace + "_cluster_commands_failed_total",
		Help:   "Commands that failed to apply. A rejected CreateQueue is a legitimate one; a steady climb is not.",
		Labels: []string{labelNodeID},
	})

	clusterLastContactDef = define(Definition{
		Kind:   KindGauge,
		Name:   Namespace + "_cluster_leader_last_contact_seconds",
		Help:   "How long ago this follower heard from the leader. Zero on the leader itself.",
		Labels: []string{labelNodeID},
	})
)

// Cluster metrics recorded from the code path itself.
var (
	clusterApplies = NewCounterVec(Definition{
		Name:   Namespace + "_cluster_applies_total",
		Help:   "Writes proposed through consensus by this node, by operation and outcome.",
		Labels: []string{labelOperation, labelResult},
	})

	clusterApplyDuration = NewHistogramVec(Definition{
		Name:   Namespace + "_cluster_apply_duration_seconds",
		Help:   "Time from proposing a write to it being committed and applied. This is the cost clustering adds to a write.",
		Labels: []string{labelOperation},
	}, LatencyBuckets)

	clusterForwards = NewCounterVec(Definition{
		Name:   Namespace + "_cluster_forwards_total",
		Help:   "Writes a follower handed to the leader, by outcome.",
		Labels: []string{labelOperation, labelResult},
	})

	clusterForwardDuration = NewHistogramVec(Definition{
		Name:   Namespace + "_cluster_forward_duration_seconds",
		Help:   "Round-trip time of a write forwarded to the leader, network included.",
		Labels: []string{labelOperation},
	}, LatencyBuckets)

	clusterNotLeader = NewCounterVec(Definition{
		Name:   Namespace + "_cluster_not_leader_total",
		Help:   "Writes rejected because this node is not the leader and no leader was known. Spikes during an election.",
		Labels: []string{},
	})

	clusterLeadershipChanges = NewCounterVec(Definition{
		Name:   Namespace + "_cluster_leadership_changes_total",
		Help:   "Times this node gained or lost leadership.",
		Labels: []string{labelState},
	})

	clusterFSMApplies = NewCounterVec(Definition{
		Name:   Namespace + "_cluster_fsm_applies_total",
		Help:   "Log entries applied to the local state machine, by operation and outcome.",
		Labels: []string{labelOperation, labelResult},
	})

	clusterFSMApplyDuration = NewHistogramVec(Definition{
		Name:   Namespace + "_cluster_fsm_apply_duration_seconds",
		Help:   "Time the state machine spent applying one log entry. Consistently slow means followers fall behind.",
		Labels: []string{labelOperation},
	}, LatencyBuckets)

	clusterDeterminismOverflows = NewCounterVec(Definition{
		Name: Namespace + "_cluster_determinism_overflows_total",
		Help: "Commands that needed more identifiers than the leader assigned. " +
			"Replicas stay consistent, but the command was sized against state that had already moved.",
		Labels: []string{labelOperation},
	})

	clusterSnapshots = NewCounterVec(Definition{
		Name:   Namespace + "_cluster_snapshots_total",
		Help:   "State-machine snapshots taken, by outcome.",
		Labels: []string{labelResult},
	})

	clusterSnapshotDuration = NewHistogramVec(Definition{
		Name:   Namespace + "_cluster_snapshot_duration_seconds",
		Help:   "How long it took to stream a snapshot out.",
		Labels: []string{},
	}, SlowBuckets)

	clusterSnapshotBytes = NewHistogramVec(Definition{
		Name:   Namespace + "_cluster_snapshot_bytes",
		Help:   "Size of the snapshots this node produced.",
		Labels: []string{},
	}, SizeBuckets)

	clusterSnapshotRecords = NewCounterVec(Definition{
		Name:   Namespace + "_cluster_snapshot_records_total",
		Help:   "Records written into snapshots, by kind.",
		Labels: []string{labelKind},
	})

	clusterRestores = NewCounterVec(Definition{
		Name:   Namespace + "_cluster_restores_total",
		Help:   "Snapshot restores, by outcome. A restore means this node was too far behind to catch up from the log.",
		Labels: []string{labelResult},
	})

	clusterRestoreDuration = NewHistogramVec(Definition{
		Name:   Namespace + "_cluster_restore_duration_seconds",
		Help:   "How long it took to restore from a snapshot. The node is not serving reads for this long.",
		Labels: []string{},
	}, SlowBuckets)

	clusterRestoreRecords = NewCounterVec(Definition{
		Name:   Namespace + "_cluster_restore_records_total",
		Help:   "Records read out of snapshots during a restore, by kind.",
		Labels: []string{labelKind},
	})

	clusterMembershipChanges = NewCounterVec(Definition{
		Name:   Namespace + "_cluster_membership_changes_total",
		Help:   "Membership changes the leader made while reconciling gossip against the configuration.",
		Labels: []string{labelAction, labelResult},
	})

	clusterSweeps = NewCounterVec(Definition{
		Name:   Namespace + "_cluster_sweeps_total",
		Help:   "Retention sweeps the leader proposed through the log, by outcome.",
		Labels: []string{labelResult},
	})

	gossipEvents = NewCounterVec(Definition{
		Name:   Namespace + "_cluster_gossip_events_total",
		Help:   "Membership events observed, by type. A steady stream of join/leave pairs is a flapping node.",
		Labels: []string{labelEventType},
	})

	gossipMembers = NewGaugeVec(Definition{
		Name:   Namespace + "_cluster_gossip_members",
		Help:   "Members in the gossip view, by state.",
		Labels: []string{labelState},
	})

	gossipJoins = NewCounterVec(Definition{
		Name:   Namespace + "_cluster_gossip_joins_total",
		Help:   "Attempts to join the gossip pool, by outcome.",
		Labels: []string{labelResult},
	})

	gossipJoinPeers = NewHistogramVec(Definition{
		Name:   Namespace + "_cluster_gossip_join_peers",
		Help:   "How many peers each join attempt reached.",
		Labels: []string{},
	}, CountBuckets)

	discoveryRuns = NewCounterVec(Definition{
		Name:   Namespace + "_cluster_discovery_runs_total",
		Help:   "Discovery queries by provider and outcome. A provider failing every run is a misconfigured cluster that has not noticed yet.",
		Labels: []string{labelProviderName, labelResult},
	})

	discoveryDuration = NewHistogramVec(Definition{
		Name:   Namespace + "_cluster_discovery_duration_seconds",
		Help:   "How long a discovery provider took to answer.",
		Labels: []string{labelProviderName},
	}, LatencyBuckets)

	discoveryPeers = NewGaugeVec(Definition{
		Name:   Namespace + "_cluster_discovery_peers",
		Help:   "Peers the last successful discovery run returned, by provider.",
		Labels: []string{labelProviderName},
	})

	peerRequests = NewCounterVec(Definition{
		Name:   Namespace + "_cluster_peer_requests_total",
		Help:   "Internal peer RPCs served, by path and outcome.",
		Labels: []string{labelPath, labelResult},
	})

	peerRequestDuration = NewHistogramVec(Definition{
		Name:   Namespace + "_cluster_peer_request_duration_seconds",
		Help:   "Latency of internal peer RPCs, server side.",
		Labels: []string{labelPath},
	}, LatencyBuckets)

	peerAuthFailures = NewCounterVec(Definition{
		Name: Namespace + "_cluster_peer_auth_failures_total",
		Help: "Peer RPCs rejected for a bad or missing shared secret. " +
			"On a private network this should be flat at zero; it climbing means something is reaching the cluster port that should not be.",
		Labels: []string{},
	})

	transportConnections = NewCounterVec(Definition{
		Name:   Namespace + "_cluster_transport_connections_total",
		Help:   "Connections on the multiplexed cluster port, by protocol and direction.",
		Labels: []string{labelProtocol, labelDirection},
	})

	transportHandshakeFailures = NewCounterVec(Definition{
		Name:   Namespace + "_cluster_transport_handshake_failures_total",
		Help:   "Inbound connections dropped before a protocol could be identified.",
		Labels: []string{},
	})
)

// Snapshot record kinds.
const (
	RecordQueue        = "queue"
	RecordMessage      = "message"
	RecordTopic        = "topic"
	RecordSubscription = "subscription"
)

// Leadership transitions.
const (
	LeadershipGained = "gained"
	LeadershipLost   = "lost"
)

// clusterNodeInfoDef carries this node's identity as labels on a constant 1.
var clusterNodeInfoDef = define(Definition{
	Kind:   KindGauge,
	Name:   Namespace + "_cluster_node_info",
	Help:   "Constant 1 carrying this node's identity, build and consensus engine as labels.",
	Labels: []string{labelNodeID, labelVersion, labelEngine},
})

// RegisterClusterNode publishes this node's cluster state.
//
// Every series reads through to sample at scrape time. That is deliberate:
// the alternative — a background loop pushing values — reports the cluster as
// it was at the last tick, and the moments worth capturing are exactly the
// ones a five-second loop smooths away.
func RegisterClusterNode(nodeID, version, engine string, sample func() ClusterSample) {
	Info(clusterNodeInfoDef, nodeID, version, engine)

	gauge := func(def Definition, value func(ClusterSample) float64) {
		GaugeFunc(def, func() float64 { return value(sample()) }, nodeID)
	}

	// The two command counts only ever increase, so they are announced as
	// counters even though they are read through a callback like the rest.
	counter := func(def Definition, value func(ClusterSample) float64) {
		CounterFunc(def, func() float64 { return value(sample()) }, nodeID)
	}

	gauge(clusterLeaderDef, func(s ClusterSample) float64 { return boolValue(s.Leader) })
	gauge(clusterHealthyDef, func(s ClusterSample) float64 { return boolValue(s.Healthy) })
	gauge(clusterTermDef, func(s ClusterSample) float64 { return float64(s.Term) })
	gauge(clusterCommitIndexDef, func(s ClusterSample) float64 { return float64(s.CommitIndex) })
	gauge(clusterAppliedIndexDef, func(s ClusterSample) float64 { return float64(s.AppliedIndex) })
	gauge(clusterLastIndexDef, func(s ClusterSample) float64 { return float64(s.LastIndex) })
	gauge(clusterVotersDef, func(s ClusterSample) float64 { return float64(s.Voters) })
	gauge(clusterMembersDef, func(s ClusterSample) float64 { return float64(s.Members) })
	gauge(clusterReachableDef, func(s ClusterSample) float64 { return float64(s.Reachable) })
	gauge(clusterQuorumDef, func(s ClusterSample) float64 { return float64(s.Quorum) })
	counter(clusterAppliedCommandsDef, func(s ClusterSample) float64 { return float64(s.AppliedCommands) })
	counter(clusterFailedCommandsDef, func(s ClusterSample) float64 { return float64(s.FailedCommands) })
	gauge(clusterLastContactDef, func(s ClusterSample) float64 { return s.LastContact.Seconds() })
}

func boolValue(value bool) float64 {
	if value {
		return 1
	}

	return 0
}

// RecordClusterApply records a write proposed through consensus.
func RecordClusterApply(operation string, start time.Time, err error) {
	clusterApplies.With(operation, resultOf(err)).Inc()
	clusterApplyDuration.ObserveSince(start, operation)
}

// RecordClusterForward records a write a follower handed to the leader.
func RecordClusterForward(operation string, start time.Time, err error) {
	clusterForwards.With(operation, resultOf(err)).Inc()
	clusterForwardDuration.ObserveSince(start, operation)
}

// RecordNotLeader records a write rejected for want of a leader.
func RecordNotLeader() { clusterNotLeader.With().Inc() }

// RecordLeadershipChange records this node gaining or losing leadership.
func RecordLeadershipChange(state string) { clusterLeadershipChanges.With(state).Inc() }

// RecordFSMApply records one log entry applied to the state machine.
func RecordFSMApply(operation string, start time.Time, err error) {
	clusterFSMApplies.With(operation, resultOf(err)).Inc()
	clusterFSMApplyDuration.ObserveSince(start, operation)
}

// RecordDeterminismOverflow records a command that outran its assigned
// identifiers.
func RecordDeterminismOverflow(operation string, count int) {
	if count <= 0 {
		return
	}

	clusterDeterminismOverflows.Add(uint64(count), operation)
}

// RecordSnapshot records a snapshot this node produced.
func RecordSnapshot(start time.Time, bytes int64, err error) {
	clusterSnapshots.With(resultOf(err)).Inc()
	clusterSnapshotDuration.ObserveSince(start)

	if bytes >= 0 {
		clusterSnapshotBytes.Observe(float64(bytes))
	}
}

// RecordSnapshotRecords records what a snapshot contained.
func RecordSnapshotRecords(queues, messages, topics, subscriptions uint64) {
	clusterSnapshotRecords.Add(queues, RecordQueue)
	clusterSnapshotRecords.Add(messages, RecordMessage)
	clusterSnapshotRecords.Add(topics, RecordTopic)
	clusterSnapshotRecords.Add(subscriptions, RecordSubscription)
}

// RecordRestore records a restore from a snapshot.
func RecordRestore(start time.Time, err error) {
	clusterRestores.With(resultOf(err)).Inc()
	clusterRestoreDuration.ObserveSince(start)
}

// RecordRestoreRecords records what a restore read back.
func RecordRestoreRecords(queues, messages, topics, subscriptions uint64) {
	clusterRestoreRecords.Add(queues, RecordQueue)
	clusterRestoreRecords.Add(messages, RecordMessage)
	clusterRestoreRecords.Add(topics, RecordTopic)
	clusterRestoreRecords.Add(subscriptions, RecordSubscription)
}

// RecordMembershipChange records a membership change the leader made.
func RecordMembershipChange(action string, err error) {
	clusterMembershipChanges.With(action, resultOf(err)).Inc()
}

// RecordClusterSweep records a retention sweep the leader proposed.
func RecordClusterSweep(err error) { clusterSweeps.With(resultOf(err)).Inc() }

// RecordGossipEvent records one membership event.
func RecordGossipEvent(eventType string) { gossipEvents.With(eventType).Inc() }

// GossipView is the gossip membership tally a node publishes.
type GossipView struct {
	Alive   int
	Suspect int
	Left    int
	Failed  int
}

// SetGossipMembers records the gossip view, by member state.
func SetGossipMembers(view GossipView) {
	gossipMembers.Set(float64(view.Alive), GossipStateAlive)
	gossipMembers.Set(float64(view.Suspect), GossipStateSuspect)
	gossipMembers.Set(float64(view.Left), GossipStateLeft)
	gossipMembers.Set(float64(view.Failed), GossipStateFailed)
}

// RecordGossipJoin records an attempt to join the gossip pool and how many
// peers it reached.
func RecordGossipJoin(peers int, err error) {
	gossipJoins.With(resultOf(err)).Inc()

	if peers >= 0 {
		gossipJoinPeers.Observe(float64(peers))
	}
}

// RecordDiscovery records one query to a discovery provider.
func RecordDiscovery(provider string, start time.Time, peers int, err error) {
	discoveryRuns.With(provider, resultOf(err)).Inc()
	discoveryDuration.ObserveSince(start, provider)

	if err == nil {
		discoveryPeers.Set(float64(peers), provider)
	}
}

// RecordPeerRequest records an internal peer RPC, server side.
func RecordPeerRequest(path string, start time.Time, err error) {
	peerRequests.With(path, resultOf(err)).Inc()
	peerRequestDuration.ObserveSince(start, path)
}

// RecordPeerAuthFailure records a peer RPC rejected for a bad shared secret.
func RecordPeerAuthFailure() { peerAuthFailures.With().Inc() }

// RecordTransportConnection records a connection on the multiplexed cluster
// port.
func RecordTransportConnection(protocol, direction string) {
	transportConnections.With(protocol, direction).Inc()
}

// RecordTransportHandshakeFailure records an inbound connection dropped
// before its protocol could be identified.
func RecordTransportHandshakeFailure() { transportHandshakeFailures.With().Inc() }
