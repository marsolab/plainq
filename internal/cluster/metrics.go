package cluster

import (
	"sync"

	"github.com/marsolab/plainq/internal/cluster/consensus"
	"github.com/marsolab/plainq/internal/metrics"
)

// registerMetrics exposes the cluster's state on the server's /metrics
// endpoint.
//
// The two that matter most for alerting are plainq_cluster_healthy — zero
// means the cluster cannot commit a write — and the gap between
// plainq_cluster_commit_index and plainq_cluster_applied_index, which is this
// replica's lag.
//
// Registration happens once per process. A server is one cluster node, and the
// metric registry is process-global: registering twice would leave the second
// node's series pointing at the first node's callbacks.
func (n *Node) registerMetrics() {
	metricsOnce.Do(n.registerMetricsOnce)
}

// metricsOnce guards the process-global metric registration.
var metricsOnce sync.Once

func (n *Node) registerMetricsOnce() {
	metrics.RegisterClusterNode(n.cfg.NodeID, n.cfg.Version, n.consensus.Status().Engine, n.sample)
}

// sample renders this node's state in the shape the metrics package reads.
//
// It is one pass over the same Status the API and the CLI answer from, so a
// scrape, a dashboard and `plainq cluster status` cannot disagree about what
// the cluster looked like at a given moment.
func (n *Node) sample() metrics.ClusterSample {
	status := n.Status()

	sample := metrics.ClusterSample{
		Leader:          status.State == consensus.StateLeader,
		Healthy:         status.Healthy,
		Term:            status.Term,
		CommitIndex:     status.CommitIndex,
		AppliedIndex:    status.AppliedIndex,
		LastIndex:       status.LastIndex,
		Voters:          status.Voters,
		Members:         len(status.Members),
		Quorum:          status.Quorum,
		AppliedCommands: status.AppliedCommands,
		FailedCommands:  status.FailedCommands,
		LastContact:     n.consensus.LastContact(),
	}

	for _, member := range status.Members {
		if member.Reachable {
			sample.Reachable++
		}
	}

	return sample
}
