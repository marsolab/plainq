package main

import (
	"time"

	"github.com/heartwilltell/scotty"
	"github.com/marsolab/plainq/internal/cluster"
)

// setClusterFlags registers the -cluster.* flags on the serve command.
//
// Every one of them is inert unless -cluster.enable is set: a PlainQ that was
// never asked to be a cluster must behave exactly as it did before this
// existed, and the flags are here so that turning it on is a decision rather
// than a discovery.
//
//nolint:funlen // Flag registration is a flat list, and splitting it hides the surface.
func setClusterFlags(f *scotty.FlagSet, cfg *cluster.Config, discovery *string) {
	f.BoolVar(&cfg.Enabled, "cluster.enable", false,
		"run this server as a member of a cluster",
	)

	f.StringVar(&cfg.NodeID, "cluster.node-id", "",
		"stable cluster identity for this node (default: hostname); it must be unique and survive restarts",
	)

	f.StringVar(&cfg.BindAddr, "cluster.bind.addr", cluster.DefaultBindAddr,
		"address for consensus and internal peer RPC",
	)

	f.StringVar(&cfg.AdvertiseAddr, "cluster.advertise.addr", "",
		"cluster address peers should dial (required when cluster.bind.addr is 0.0.0.0)",
	)

	f.StringVar(&cfg.GossipAddr, "cluster.gossip.addr", cluster.DefaultGossipAddr,
		"address for membership gossip (TCP and UDP)",
	)

	f.StringVar(&cfg.GossipAdvertiseAddr, "cluster.gossip.advertise.addr", "",
		"gossip address peers should dial (default: the host of cluster.advertise.addr)",
	)

	f.StringVar(&cfg.GossipSecret, "cluster.gossip.secret", "",
		"base64 16/24/32-byte key that encrypts and authenticates gossip",
	)

	f.StringVar(&cfg.GossipProfile, "cluster.gossip.profile", "lan",
		"gossip failure-detector timing: 'lan', 'wan' or 'local'",
	)

	f.StringVar(&cfg.Secret, "cluster.secret", "",
		"shared secret that authenticates internal peer RPC",
	)

	f.StringVar(&cfg.DataDir, "cluster.data.dir", "",
		"directory for the consensus log and snapshots (default: alongside the storage database)",
	)

	f.StringVar(discovery, "cluster.discovery", "",
		"how to find peers by their gossip address, e.g. 'static://a:8083,b:8083', "+
			"'dns://plainq.internal?port=8083', "+
			"'kubernetes://?namespace=default&selector=app%3Dplainq&port=8083', "+
			"'docker://?label=plainq.cluster%3Dprod&port=8083', "+
			"'aws://?region=eu-west-1&tag=Cluster%3Dplainq&port=8083', "+
			"'gcp://?project=p&label=cluster%3Dplainq&port=8083', "+
			"'azure://?subscription=…&tag=cluster%3Dplainq&port=8083', "+
			"'consul://?service=plainq'. Several may be given, comma-separated",
	)

	f.DurationVar(&cfg.DiscoveryInterval, "cluster.discovery.interval", cluster.DefaultDiscoveryInterval,
		"how often to re-run peer discovery",
	)

	f.BoolVar(&cfg.Bootstrap, "cluster.bootstrap", false,
		"form a new single-node cluster; set this on exactly one node, once",
	)

	f.IntVar(&cfg.BootstrapExpect, "cluster.bootstrap-expect", 0,
		"wait for this many nodes and then form a cluster from all of them",
	)

	f.BoolVar(&cfg.NonVoter, "cluster.non-voter", false,
		"join as a replica that does not vote and does not count toward quorum",
	)

	f.StringVar((*string)(&cfg.Consistency), "cluster.consistency", string(cluster.ConsistencyLocal),
		"where reads are served: 'local' (fast, may lag) or 'strong' (leader, linearizable)",
	)

	f.DurationVar(&cfg.ReconcileInterval, "cluster.reconcile.interval", cluster.DefaultReconcileInterval,
		"how often the leader reconciles gossip against the consensus configuration",
	)

	f.BoolVar(&cfg.AutoRemove, "cluster.auto-remove", false,
		"let the leader remove members that stay unreachable past cluster.remove.timeout",
	)

	f.DurationVar(&cfg.RemoveTimeout, "cluster.remove.timeout", cluster.DefaultRemoveTimeout,
		"how long a member must be unreachable before cluster.auto-remove drops it",
	)

	f.DurationVar(&cfg.SweepInterval, "cluster.sweep.interval", cluster.DefaultSweepInterval,
		"how often the leader proposes queue eviction",
	)

	f.DurationVar(&cfg.ApplyTimeout, "cluster.apply.timeout", 15*time.Second,
		"how long a replicated write may take before it is reported as failed",
	)

	// Consensus tuning. The defaults come from the engine and suit a LAN.

	f.DurationVar(&cfg.HeartbeatTimeout, "cluster.raft.heartbeat.timeout", 0,
		"how long a follower waits for the leader before standing for election",
	)

	f.DurationVar(&cfg.ElectionTimeout, "cluster.raft.election.timeout", 0,
		"how long a candidate waits for votes",
	)

	f.DurationVar(&cfg.LeaderLeaseTimeout, "cluster.raft.leader-lease.timeout", 0,
		"how long a leader may go without contacting a quorum before stepping down",
	)

	f.DurationVar(&cfg.CommitTimeout, "cluster.raft.commit.timeout", 0,
		"how long the leader batches entries before sending them",
	)

	f.DurationVar(&cfg.SnapshotInterval, "cluster.raft.snapshot.interval", 0,
		"how often the consensus log is compacted into a snapshot",
	)

	f.Uint64Var(&cfg.SnapshotThreshold, "cluster.raft.snapshot.threshold", 0,
		"how many log entries trigger a snapshot",
	)

	f.Uint64Var(&cfg.TrailingLogs, "cluster.raft.trailing-logs", 0,
		"how many entries to keep after a snapshot so a lagging follower can catch up",
	)

	// TLS.

	f.StringVar(&cfg.TLSCertFile, "cluster.tls.cert", "",
		"certificate for mutually authenticated cluster traffic",
	)

	f.StringVar(&cfg.TLSKeyFile, "cluster.tls.key", "",
		"private key for cluster.tls.cert",
	)

	f.StringVar(&cfg.TLSCAFile, "cluster.tls.ca", "",
		"certificate authority that issued the cluster's certificates",
	)
}
