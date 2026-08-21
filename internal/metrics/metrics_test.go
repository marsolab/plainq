package metrics

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	vm "github.com/VictoriaMetrics/metrics"
	"github.com/maxatome/go-testdeep/td"
)

// scrape renders the process-wide registry the way the /metrics endpoint
// does, minus the Go and process collectors.
func scrape() string {
	var buf bytes.Buffer

	vm.WritePrometheus(&buf, false)

	return buf.String()
}

// hasSeries reports whether the scrape contains a series whose name and
// labels start with the given prefix.
func hasSeries(t *testing.T, series string) bool {
	t.Helper()

	for line := range strings.SplitSeq(scrape(), "\n") {
		if strings.HasPrefix(line, series) {
			return true
		}
	}

	return false
}

func Test_render_buildsPrometheusNames(t *testing.T) {
	td.Cmp(t, render("plainq_x", nil, nil), "plainq_x", "a family with no labels is just its name")

	td.Cmp(t,
		render("plainq_x", []string{"queue"}, []string{"Q1"}),
		`plainq_x{queue="Q1"}`,
	)

	td.Cmp(t,
		render("plainq_x", []string{"queue", "op"}, []string{"Q1", "send"}),
		`plainq_x{queue="Q1",op="send"}`,
	)
}

// Test_render_escapesLabelValues guards the one failure mode that takes the
// process down rather than producing a wrong number: the metrics library
// panics on a name it cannot parse, and queue identifiers reach these labels
// from user input.
func Test_render_escapesLabelValues(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"quote":            {`a"b`, `a\"b`},
		"backslash":        {`a\b`, `a\\b`},
		"newline":          {"a\nb", `a\nb`},
		"control dropped":  {"a\x00b", "ab"},
		"unicode kept":     {"héllo", "héllo"},
		"nothing to do":    {"plain", "plain"},
		"quote and escape": {`a"\b`, `a\"\\b`},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := render("plainq_x", []string{"queue"}, []string{tc.in})

			td.Cmp(t, got, `plainq_x{queue="`+tc.want+`"}`)

			// The real assertion: whatever came out, the library accepts it.
			td.CmpNoError(t, vm.ValidateMetric(got), "the rendered name must parse")
		})
	}
}

// Test_vec_capsSeriesPerFamily proves the guard that stops a client creating
// queues in a loop from turning the registry into an unbounded memory leak.
func Test_vec_capsSeriesPerFamily(t *testing.T) {
	family := NewCounterVec(Definition{
		Name:   "plainq_test_capped_total",
		Help:   "Test family for the series cap.",
		Labels: []string{"id"},
	})

	before := droppedSeries.with("plainq_test_capped_total").Get()

	for i := range maxSeriesPerFamily + 100 {
		family.With(strconv.Itoa(i)).Inc()
	}

	family.vec.mu.RLock()
	distinct := len(family.vec.cache)
	family.vec.mu.RUnlock()

	td.Cmp(t, distinct, maxSeriesPerFamily+1,
		"the cap holds, plus the one overflow series everything past it folds into",
	)

	td.Cmp(t, droppedSeries.with("plainq_test_capped_total").Get()-before, uint64(100),
		"every attempt past the cap is counted, not just the first",
	)

	td.Cmp(t, hasSeries(t, `plainq_test_capped_total{id="`+overflowLabelValue+`"}`), true,
		"the overflow series is exported so the loss is visible in the data itself",
	)
}

// Test_Catalog_isCompleteAndConsistent checks the property the documentation
// depends on: every family is declared exactly once, with a name a scraper
// will accept and a sentence saying what it is.
func Test_Catalog_isCompleteAndConsistent(t *testing.T) {
	catalogued := Catalog()

	td.Require(t).Cmp(len(catalogued) > 50, true, "the catalogue should hold every family PlainQ declares")

	seen := make(map[string]bool, len(catalogued))

	for _, def := range catalogued {
		t.Run(def.Name, func(t *testing.T) {
			td.Cmp(t, seen[def.Name], false, "each family is catalogued once")
			seen[def.Name] = true

			td.Cmp(t, strings.HasPrefix(def.Name, Namespace+"_"), true,
				"every metric carries the namespace, so it cannot collide with another exporter",
			)

			td.Cmp(t, def.Help != "", true, "every metric says what it is for")
			td.Cmp(t, strings.HasSuffix(def.Help, "."), true, "help text is a sentence")
			td.Cmp(t, def.Kind != "", true, "every metric declares its type")

			// The exposition layer types a metric by its suffix, so the
			// catalog and the scrape have to agree about what `_total` means
			// or the documentation contradicts the data.
			td.Cmp(t, def.Kind == KindCounter, strings.HasSuffix(def.Name, "_total"),
				"a name ends in _total exactly when the family is a counter",
			)

			td.CmpNoError(t, vm.ValidateMetric(def.Name), "the metric name must parse")
		})
	}
}

// Test_Catalog_sortedByName pins the order the documentation is generated in.
func Test_Catalog_sortedByName(t *testing.T) {
	catalogued := Catalog()

	for i := 1; i < len(catalogued); i++ {
		td.Cmp(t, catalogued[i-1].Name < catalogued[i].Name, true, "the catalogue is sorted")
	}
}

func TestSecurityAuditPersistenceFailuresAreCounted(t *testing.T) {
	before := securityAuditFailures.With().Get()

	RecordSecurityAuditFailure()

	td.Cmp(t, securityAuditFailures.With().Get()-before, uint64(1))
	td.Cmp(t, hasSeries(t, "plainq_security_audit_failures_total"), true)
}

func Test_queueMetrics_recordTheQueueLifecycle(t *testing.T) {
	const queueID = "QTESTLIFECYCLE"

	RecordSend(queueID, 3, 300)
	RecordReceive(queueID, 2, 200)
	RecordDelete(queueID, 2)
	RecordDrop(queueID, "EVICTION_POLICY_DROP", 1)

	td.Cmp(t, messagesSent.With(queueID).Get(), uint64(3))
	td.Cmp(t, messagesReceived.With(queueID).Get(), uint64(2))
	td.Cmp(t, messagesDeleted.With(queueID).Get(), uint64(2))
	td.Cmp(t, messagesSentBytes.With(queueID).Get(), uint64(300))
	td.Cmp(t, messagesDropped.With(queueID, "EVICTION_POLICY_DROP").Get(), uint64(1))

	td.Cmp(t, messagesInFlight.With(queueID).Get(), float64(0),
		"two received and two acknowledged leaves nothing in flight",
	)

	td.Cmp(t, queueDepth.With(queueID).Get(), float64(0),
		"three sent, two deleted and one evicted leaves the queue empty",
	)
}

// Test_RecordReceive_countsEmptyReceivesSeparately pins the distinction that
// tells an idle-polling consumer apart from a busy one.
func Test_RecordReceive_countsEmptyReceivesSeparately(t *testing.T) {
	const queueID = "QTESTEMPTY"

	RecordReceive(queueID, 0, 0)
	RecordReceive(queueID, 0, 0)
	RecordReceive(queueID, 1, 10)

	td.Cmp(t, emptyReceives.With(queueID).Get(), uint64(2))
	td.Cmp(t, messagesReceived.With(queueID).Get(), uint64(1))
}

// Test_ResetQueue_clearsGauges proves a deleted queue does not leave a
// permanent non-zero depth behind on the dashboard.
func Test_ResetQueue_clearsGauges(t *testing.T) {
	const queueID = "QTESTRESET"

	RecordSend(queueID, 5, 500)
	RecordReceive(queueID, 5, 500)

	td.Require(t).Cmp(queueDepth.With(queueID).Get(), float64(5))

	ResetQueue(queueID)

	td.Cmp(t, queueDepth.With(queueID).Get(), float64(0))
	td.Cmp(t, messagesInFlight.With(queueID).Get(), float64(0))
}

func Test_RecordOperation_labelsTheOutcome(t *testing.T) {
	start := time.Now()

	RecordOperation(BackendSQLite, OpSend, start, nil)
	RecordOperation(BackendSQLite, OpSend, start, errTest)

	td.Cmp(t, queueOperations.With(BackendSQLite, OpSend, ResultOK).Get(), uint64(1))
	td.Cmp(t, queueOperations.With(BackendSQLite, OpSend, ResultError).Get(), uint64(1))

	td.Cmp(t, hasSeries(t, `plainq_queue_operation_duration_seconds_bucket{backend="sqlite",operation="send",le=`), true,
		"latency is a real Prometheus histogram with le buckets, so histogram_quantile works on it",
	)
}

// Test_exposition_carriesTypeMetadata checks that a human pointing a browser
// at /metrics can tell a counter from a gauge.
func Test_exposition_carriesTypeMetadata(t *testing.T) {
	ExposeMetadata(true)
	defer ExposeMetadata(false)

	RecordSend("QTESTMETADATA", 1, 1)

	td.Cmp(t, strings.Contains(scrape(), "# TYPE plainq_messages_sent_total counter"), true)
}

func Test_RegisterClusterNode_exportsTheClusterView(t *testing.T) {
	RegisterClusterNode("node-a", "v1.2.3", "raft", func() ClusterSample {
		return ClusterSample{
			Leader:      true,
			Healthy:     true,
			Term:        7,
			CommitIndex: 42,
			Voters:      3,
			Quorum:      2,
			Reachable:   3,
			LastContact: 250 * time.Millisecond,
		}
	})

	out := scrape()

	for _, want := range []string{
		`plainq_cluster_node_info{node_id="node-a",version="v1.2.3",engine="raft"} 1`,
		`plainq_cluster_leader{node_id="node-a"} 1`,
		`plainq_cluster_healthy{node_id="node-a"} 1`,
		`plainq_cluster_term{node_id="node-a"} 7`,
		`plainq_cluster_commit_index{node_id="node-a"} 42`,
		`plainq_cluster_quorum{node_id="node-a"} 2`,
		`plainq_cluster_leader_last_contact_seconds{node_id="node-a"} 0.25`,
	} {
		td.Cmp(t, strings.Contains(out, want), true, "scrape should contain "+want)
	}
}

// Test_RegisterPoolCollector_readsThroughAtScrapeTime proves the pool gauges
// report the pool as it is when Prometheus asks, not as it was at some
// sampler's last tick.
func Test_RegisterPoolCollector_readsThroughAtScrapeTime(t *testing.T) {
	stats := PoolStats{Open: 1, InUse: 1, Idle: 0}

	RegisterPoolCollector("testpool", func() PoolStats { return stats })

	td.Require(t).Cmp(strings.Contains(scrape(), `plainq_storage_db_connections{backend="testpool",state="in_use"} 1`), true)

	stats.InUse = 4

	td.Cmp(t, strings.Contains(scrape(), `plainq_storage_db_connections{backend="testpool",state="in_use"} 4`), true,
		"the next scrape sees the new value without anything having pushed it",
	)
}

// Test_define_rejectsConflictingRedeclaration guards the invariant that keeps
// two subsystems from quietly fighting over one series.
func Test_define_rejectsConflictingRedeclaration(t *testing.T) {
	def := Definition{
		Name:   "plainq_test_conflict",
		Kind:   KindGauge,
		Help:   "Test family.",
		Labels: []string{"a"},
	}

	define(def)

	td.Cmp(t, define(def), def, "an identical redeclaration is fine — one family, several fixed label sets")

	defer func() {
		td.Cmp(t, recover() != nil, true, "a conflicting redeclaration panics at startup")
	}()

	conflicting := def
	conflicting.Help = "Something else."

	define(conflicting)
}

// errTest stands in for a failed operation.
var errTest = errTestType{}

type errTestType struct{}

func (errTestType) Error() string { return "test error" }

// Test_Catalog_isFullyDocumented keeps the reference table honest.
//
// The package doc claims a metric cannot quietly exist without being
// documented. This is what makes that true: add a family and forget the guide,
// and the build stops.
func Test_Catalog_isFullyDocumented(t *testing.T) {
	const guide = "../../docs/guides/observability.md"

	content, err := os.ReadFile(guide)
	td.Require(t).CmpNoError(err, "read the observability guide")

	documented := string(content)

	for _, def := range Catalog() {
		// The test families this file declares are not product metrics.
		if strings.Contains(def.Name, "_test_") {
			continue
		}

		td.Cmp(t, strings.Contains(documented, "`"+def.Name+"`"), true,
			def.Name+" is exposed but missing from "+guide,
		)
	}
}

// Test_inFlight_doesNotDriftOnRedelivery pins the arithmetic that decides
// whether the in-flight gauge is usable on a queue whose consumers are
// failing — which is the only queue anyone looks at it for.
//
// A redelivered message was already counted as in flight on its first
// delivery, and nothing takes it back out when its visibility lapses. Counting
// the receive again without compensating is how that gauge climbs forever.
func Test_inFlight_doesNotDriftOnRedelivery(t *testing.T) {
	const queueID = "QTESTREDRIFT"

	RecordSend(queueID, 1, 10)

	// First delivery: one message claimed.
	RecordReceive(queueID, 1, 10)
	RecordRedelivery(queueID, 0)

	td.Require(t).Cmp(messagesInFlight.With(queueID).Get(), float64(1))

	// Three redeliveries of that same message. Each is a receive carrying one
	// message that was already counted.
	for range 3 {
		RecordReceive(queueID, 1, 10)
		RecordRedelivery(queueID, 1)

		td.Cmp(t, messagesInFlight.With(queueID).Get(), float64(1),
			"a retry re-claims the same message, it does not add a second one",
		)
	}

	// Acknowledged: nothing left in flight, and nothing left behind.
	RecordDelete(queueID, 1)

	td.Cmp(t, messagesInFlight.With(queueID).Get(), float64(0))
	td.Cmp(t, queueDepth.With(queueID).Get(), float64(0))
	td.Cmp(t, messagesRedelivered.With(queueID).Get(), uint64(3))
}

// Test_SetQueueStats_rebasesBothGauges proves the correction path exists and
// overrides whatever the deltas had accumulated — the mechanism that makes a
// process restarting onto a database full of messages report the truth rather
// than starting from zero.
func Test_SetQueueStats_rebasesBothGauges(t *testing.T) {
	const queueID = "QTESTREBASE"

	// Deltas from an incomplete view: a delete with no matching send, which is
	// exactly what a restart looks like.
	RecordDelete(queueID, 5)

	td.Require(t).Cmp(queueDepth.With(queueID).Get(), float64(-5),
		"deltas alone can go negative, which is the problem being corrected",
	)

	SetQueueStats(queueID, 100, 7)

	td.Cmp(t, queueDepth.With(queueID).Get(), float64(100))
	td.Cmp(t, messagesInFlight.With(queueID).Get(), float64(7))

	// And the deltas carry on from the corrected value.
	RecordSend(queueID, 2, 20)

	td.Cmp(t, queueDepth.With(queueID).Get(), float64(102))
}
