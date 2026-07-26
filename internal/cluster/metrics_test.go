package cluster

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	vm "github.com/VictoriaMetrics/metrics"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/maxatome/go-testdeep/td"
)

// scrape renders the registry the way the /metrics endpoint does.
func scrape() string {
	var buf bytes.Buffer

	vm.WritePrometheus(&buf, false)

	return buf.String()
}

// seriesValue returns the value of one series from a scrape, and whether it
// was present at all.
//
//nolint:nonamedreturns // a bare (float64, bool) pair reads as nothing in particular.
func seriesValue(out, series string) (value string, found bool) {
	for line := range strings.SplitSeq(out, "\n") {
		name, rest, ok := strings.Cut(line, " ")
		if ok && name == series {
			return rest, true
		}
	}

	return "", false
}

// TestClusterMetricsDescribeARealCluster runs a real three-node cluster and
// checks that the Prometheus endpoint describes it — not that the recording
// functions can be called, which a unit test already covers, but that a scrape
// of a cluster that actually formed says the right things about it.
//
// Registration is process-global and guarded by a sync.Once, so in a test
// binary that starts several clusters the node-labelled gauges belong to
// whichever node came first. In production that is exactly right — a server is
// one cluster node — so rather than fight it the test checks the two halves
// separately: the callback that feeds those gauges is read from this
// cluster's leader, and the registry is checked for the series and the
// counters, which are process-wide either way.
func TestClusterMetricsDescribeARealCluster(t *testing.T) {
	if testing.Short() {
		t.Skip("starts three raft nodes")
	}

	ctx := context.Background()

	cluster := newTestCluster(t, 3)

	leader := cluster.leader(30 * time.Second)

	cluster.waitFor(30*time.Second, func() bool {
		return len(leader.node.Status().Members) == 3
	}, "all three nodes are in the configuration")

	// The registry is process-global and other tests in this package have
	// already written to it, so the write below is measured as a delta rather
	// than an absolute — which is also how anyone reads a counter.
	const (
		applied = `plainq_cluster_applies_total{operation="send",result="ok"}`
		fsm     = `plainq_cluster_fsm_applies_total{operation="send",result="ok"}`
	)

	before := scrape()
	appliesBefore := counterValue(before, applied)
	fsmBefore := counterValue(before, fsm)

	// A write, so the apply and FSM families have something to report.
	created, err := leader.node.Store().CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "metrics"})
	td.Require(t).CmpNoError(err)

	_, sendErr := leader.node.Store().Send(ctx, &v1.SendRequest{
		QueueId:  created.GetQueueId(),
		Messages: []*v1.SendMessage{{Body: []byte("one")}},
	})
	td.Require(t).CmpNoError(sendErr)

	out := scrape()

	// Every node-labelled gauge must be present. Which node they describe
	// depends on test ordering, so their values are checked below through the
	// callback that produces them.
	for _, series := range []string{
		"plainq_cluster_healthy",
		"plainq_cluster_leader",
		"plainq_cluster_term",
		"plainq_cluster_commit_index",
		"plainq_cluster_applied_index",
		"plainq_cluster_voters",
		"plainq_cluster_members",
		"plainq_cluster_members_reachable",
		"plainq_cluster_quorum",
		"plainq_cluster_commands_applied_total",
		"plainq_cluster_node_info",
	} {
		td.Cmp(t, strings.Contains(out, series+`{node_id="`), true, series+" should be exported")
	}

	// This is what a scrape of the leader would report: the same function the
	// gauges read, on this cluster's leader.
	sample := leader.node.sample()

	td.Cmp(t, sample.Healthy, true, "a formed three-node cluster reports itself healthy")
	td.Cmp(t, sample.Leader, true, "the leader reports itself as the leader")
	td.Cmp(t, sample.Voters, 3)
	td.Cmp(t, sample.Quorum, 2, "three voters need two to commit, which is what survives one failure")
	td.Cmp(t, sample.Reachable, 3, "gossip can see every member")
	td.Cmp(t, sample.CommitIndex > 0, true, "the log has been committed to")

	// The write path: proposed once on the leader, applied on every replica.
	td.Cmp(t, counterValue(out, applied)-appliesBefore, 1,
		"the leader's Send was proposed through consensus exactly once",
	)

	cluster.waitFor(20*time.Second, func() bool {
		return counterValue(scrape(), fsm)-fsmBefore == 3
	}, "all three state machines applied the Send")

	// Gossip and transport are exercised by the cluster simply existing.
	td.Cmp(t, strings.Contains(out, `plainq_cluster_gossip_members{state="alive"}`), true)
	td.Cmp(t, strings.Contains(out, `plainq_cluster_transport_connections_total{protocol="raft"`), true)
}

// counterValue reads a counter out of a scrape, treating a missing series as
// zero — which is what a counter that has never been incremented means.
func counterValue(out, series string) int {
	raw, found := seriesValue(out, series)
	if !found {
		return 0
	}

	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}

	return value
}
