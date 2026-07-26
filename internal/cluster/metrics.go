package cluster

import (
	"strconv"
	"sync"

	"github.com/VictoriaMetrics/metrics"
	"github.com/marsolab/plainq/internal/cluster/consensus"
)

// Cluster metric names. They are registered as gauge callbacks rather than
// values pushed on a timer: a scrape then reports the cluster as it is at that
// instant, not as it was when some background loop last looked.
const (
	metricIsLeader        = `plainq_cluster_leader`
	metricTerm            = `plainq_cluster_term`
	metricCommitIndex     = `plainq_cluster_commit_index`
	metricAppliedIndex    = `plainq_cluster_applied_index`
	metricLastIndex       = `plainq_cluster_last_index`
	metricVoters          = `plainq_cluster_voters`
	metricReachable       = `plainq_cluster_members_reachable`
	metricMembers         = `plainq_cluster_members`
	metricHealthy         = `plainq_cluster_healthy`
	metricAppliedCommands = `plainq_cluster_commands_applied_total`
	metricFailedCommands  = `plainq_cluster_commands_failed_total`
	metricLastContact     = `plainq_cluster_leader_last_contact_seconds`
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
	set := metrics.GetDefaultSet()

	gauge := func(name string, value func(Status) float64) {
		set.GetOrCreateGauge(name+`{node_id="`+quote(n.cfg.NodeID)+`"}`, func() float64 {
			return value(n.Status())
		})
	}

	gauge(metricIsLeader, func(s Status) float64 { return boolToFloat(s.State == consensus.StateLeader) })
	gauge(metricTerm, func(s Status) float64 { return float64(s.Term) })
	gauge(metricCommitIndex, func(s Status) float64 { return float64(s.CommitIndex) })
	gauge(metricAppliedIndex, func(s Status) float64 { return float64(s.AppliedIndex) })
	gauge(metricLastIndex, func(s Status) float64 { return float64(s.LastIndex) })
	gauge(metricVoters, func(s Status) float64 { return float64(s.Voters) })
	gauge(metricMembers, func(s Status) float64 { return float64(len(s.Members)) })
	gauge(metricHealthy, func(s Status) float64 { return boolToFloat(s.Healthy) })
	gauge(metricAppliedCommands, func(s Status) float64 { return float64(s.AppliedCommands) })
	gauge(metricFailedCommands, func(s Status) float64 { return float64(s.FailedCommands) })

	gauge(metricReachable, func(s Status) float64 {
		var reachable int

		for _, member := range s.Members {
			if member.Reachable {
				reachable++
			}
		}

		return float64(reachable)
	})

	set.GetOrCreateGauge(metricLastContact+`{node_id="`+quote(n.cfg.NodeID)+`"}`, func() float64 {
		return n.consensus.LastContact().Seconds()
	})
}

func boolToFloat(value bool) float64 {
	if value {
		return 1
	}

	return 0
}

// quote escapes a label value. Node ids are hostnames or pod names, so this is
// belt and braces — but a metric name that does not parse takes the whole
// scrape down with it, not just this one series.
func quote(value string) string {
	quoted := strconv.Quote(value)

	return quoted[1 : len(quoted)-1]
}
