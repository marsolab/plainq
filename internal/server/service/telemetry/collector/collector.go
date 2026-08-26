// Package collector provides a comprehensive metrics collection system
// for tracking queue operations with rate calculations, in-flight tracking,
// and time-series storage.
package collector

import (
	"container/list"
	"context"
	"errors"
	"log/slog"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/btree"
	"github.com/marsolab/servekit/logkit"
)

const (
	// Default collection interval for rate calculations.
	defaultCollectionInterval = 1 * time.Second

	defaultCleanupInterval = 10 * time.Minute
	defaultRetentionPeriod = 14 * 24 * time.Hour

	// Default aggregation intervals.
	aggregationInterval1m = 1 * time.Minute
	aggregationInterval1h = 1 * time.Hour
	aggregationInterval1d = 24 * time.Hour

	// Retention periods (like Grafana defaults).
	retentionRaw = 1 * time.Hour
	retention1m  = 24 * time.Hour
	retention5m  = 7 * 24 * time.Hour
	retention1h  = 30 * 24 * time.Hour

	// rateWindowMS is the exact compatibility collection window in milliseconds.
	rateWindowMS int64 = 1000

	defaultTopicLimit         = 65_536
	defaultEventBufferLimit   = 65_536
	defaultTerminalStateLimit = 65_536
	terminalOrderDegree       = 32

	// Bucket sizes in milliseconds for time-series aggregation.
	bucketSize1m = 60000    // 1 minute in ms.
	bucketSize1h = 3600000  // 1 hour in ms.
	bucketSize1d = 86400000 // 1 day in ms.
)

var terminalGenerationSequence = newTerminalGenerationSequence()

func newTerminalGenerationSequence() *atomic.Int64 {
	sequence := &atomic.Int64{}

	seed := time.Now().UnixNano()
	if seed < 0 {
		seed = 0
	}

	sequence.Store(seed)

	return sequence
}

// MetricType represents the type of metric.
type MetricType string

const (
	MetricTypeCounter   MetricType = "counter"
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeHistogram MetricType = "histogram"
)

// Metric names for rate metrics (calculated per second).
const (
	MetricSendRate    = "plainq_send_rate"
	MetricReceiveRate = "plainq_receive_rate"
	MetricDeleteRate  = "plainq_delete_rate"
)

// Metric names for counter metrics (cumulative).
const (
	MetricMessagesSentTotal     = "plainq_messages_sent_total"
	MetricMessagesReceivedTotal = "plainq_messages_received_total"
	MetricMessagesDeletedTotal  = "plainq_messages_deleted_total"
	MetricMessagesDroppedTotal  = "plainq_messages_dropped_total"
	MetricEmptyReceivesTotal    = "plainq_empty_receives_total"
	MetricMessagesRedelivered   = "plainq_messages_redelivered_total"
	MetricMessagesToDLQ         = "plainq_messages_to_dlq_total"
	MetricBytesSentTotal        = "plainq_bytes_sent_total"
	MetricBytesReceivedTotal    = "plainq_bytes_received_total"
)

// Metric names for topic rate metrics (calculated per second).
const (
	MetricTopicPublishRate              = "plainq_topic_publish_rate"
	MetricTopicDeliveryRate             = "plainq_topic_delivery_rate"
	MetricTopicDeliveryFailureRate      = "plainq_topic_delivery_failure_rate"
	MetricTopicPublishedBytesRate       = "plainq_topic_published_bytes_rate"
	MetricTopicSubscriptionsCreatedRate = "plainq_topic_subscriptions_created_rate"
	MetricTopicSubscriptionsDeletedRate = "plainq_topic_subscriptions_deleted_rate"
)

// Metric names for topic counter metrics (cumulative).
const (
	MetricTopicRequestsTotal             = "plainq_topic_requests_total"
	MetricTopicOperationsTotal           = "plainq_topic_operations_total"
	MetricTopicMessagesPublishedTotal    = "plainq_topic_messages_published_total"
	MetricTopicPublishedBytesTotal       = "plainq_topic_published_bytes_total"
	MetricTopicDeliveriesTotal           = "plainq_topic_deliveries_total"
	MetricTopicDeliveryFailuresTotal     = "plainq_topic_delivery_failures_total"
	MetricTopicSubscriptionsCreatedTotal = "plainq_topic_subscriptions_created_total"
	MetricTopicSubscriptionsDeletedTotal = "plainq_topic_subscriptions_deleted_total"
)

// Metric names for topic event metrics.
const (
	MetricTopicRequestDuration          = "plainq_topic_request_duration_seconds"
	MetricTopicOperationDuration        = "plainq_topic_operation_duration_seconds"
	MetricTopicFanout                   = "plainq_topic_fanout"
	MetricTelemetryEventBufferDropped   = "plainq_telemetry_event_buffer_dropped_total"
	MetricTelemetryTerminalStateDropped = "plainq_telemetry_terminal_state_dropped_total"
)

// Metric names for topic gauge metrics (current value).
const (
	MetricTopicSubscriptionsCurrent = "plainq_topic_subscriptions_current"
	MetricTopicsExist               = "plainq_topics_exist"
)

// Metric names for gauge metrics (current value).
const (
	MetricMessagesInFlight      = "plainq_messages_in_flight"
	MetricQueueDepth            = "plainq_queue_depth"
	MetricMessagesVisible       = "plainq_messages_visible"
	MetricMessagesInvisible     = "plainq_messages_invisible"
	MetricOldestMessageAge      = "plainq_oldest_message_age_seconds"
	MetricQueuesExist           = "plainq_queues_exist"
	MetricThroughputBytesPerSec = "plainq_throughput_bytes_per_second"
)

// Metric names for histogram metrics (distribution).
const (
	MetricMessageProcessingDuration = "plainq_message_processing_duration_seconds"
	MetricMessageDwellTime          = "plainq_message_dwell_time_seconds"
	MetricMessageInQueueDuration    = "plainq_message_in_queue_duration_seconds"
	MetricBatchSize                 = "plainq_batch_size"
	MetricMessageSizeBytes          = "plainq_message_size_bytes"
)

// QueueMetrics holds metrics for a specific queue.
type QueueMetrics struct {
	// Counters (atomic for thread safety).
	messagesSent        atomic.Uint64
	messagesReceived    atomic.Uint64
	messagesDeleted     atomic.Uint64
	messagesDropped     atomic.Uint64
	emptyReceives       atomic.Uint64
	messagesRedelivered atomic.Uint64
	messagesToDLQ       atomic.Uint64
	bytesSent           atomic.Uint64

	// In-flight tracking.
	messagesInFlight atomic.Int64

	// Baselines advance only after the complete boundary transaction commits.
	baselines queueRateBaselines

	// Calculated rates.
	sendRate    atomic.Uint64 // Stored as float64 bits.
	receiveRate atomic.Uint64
	deleteRate  atomic.Uint64
}

type counterRateBaseline struct {
	known      bool
	value      uint64
	observedAt int64
}

type queueRateBaselines struct {
	sent     counterRateBaseline
	received counterRateBaseline
	deleted  counterRateBaseline
}

type TopicRates struct {
	PublishRate              float64
	DeliveryRate             float64
	DeliveryFailureRate      float64
	PublishedBytesRate       float64
	SubscriptionsCreatedRate float64
	SubscriptionsDeletedRate float64
}

type TopicCounters struct {
	Requests             uint64
	Operations           uint64
	MessagesPublished    uint64
	PublishedBytes       uint64
	Deliveries           uint64
	DeliveryFailures     uint64
	SubscriptionsCreated uint64
	SubscriptionsDeleted uint64
}

type TopicSystemCounters struct {
	Requests                  uint64
	Operations                uint64
	MessagesPublished         uint64
	PublishedBytes            uint64
	Deliveries                uint64
	DeliveryFailures          uint64
	SubscriptionsCurrent      int64
	SubscriptionsCurrentKnown bool
	TopicsExist               int64
	TopicsExistKnown          bool
	SubscriptionsCreated      uint64
	SubscriptionsDeleted      uint64
}

// SystemMetrics holds system-wide metrics.
type SystemMetrics struct {
	queuesExist atomic.Int64

	// Aggregate counters.
	totalSent     atomic.Uint64
	totalReceived atomic.Uint64
	totalDeleted  atomic.Uint64

	// Baselines advance only after the complete boundary transaction commits.
	baselines queueRateBaselines

	// System-wide rates.
	systemSendRate    atomic.Uint64
	systemReceiveRate atomic.Uint64
	systemDeleteRate  atomic.Uint64
}

// Collector manages metrics collection, rate calculations, and storage.
type Collector struct {
	logger *slog.Logger
	store  Store

	// Per-queue metrics.
	queueMetrics map[string]*QueueMetrics
	queueMu      sync.RWMutex

	// Per-topic metrics.
	topicMetrics map[string]*TopicMetrics
	topicMu      sync.RWMutex
	topicCache   *topicCache
	topicLimit   int

	// System-wide metrics.
	system      SystemMetrics
	topicSystem TopicSystemMetrics

	// cutoverMu orders every topic callback with closed-boundary snapshots.
	// Nested locks follow terminalMu, cutoverMu, then topicMu; ordinary callbacks
	// acquire only the latter two.
	cutoverMu sync.Mutex
	now       func() time.Time

	eventWatermark     int64
	eventQueue         []MetricSample
	eventBufferLimit   int
	eventDirty         map[string]dirtyInterval
	topicDirty         map[string]map[string]dirtyInterval
	topicDirtyOverflow map[string]dirtyInterval
	frozenBoundary     *frozenTopicBoundary
	lastTopicBoundary  int64

	terminalLimit          int
	terminalMu             sync.Mutex
	terminalReservations   map[string]*terminalReservation
	terminalEntries        map[terminalKey]*terminalReservation
	terminalQueue          *list.List
	terminalOrder          *btree.BTreeG[*terminalReservation]
	terminalNextGeneration int64
	terminalLoadFailed     bool
	terminalLoaded         bool
	terminalPromoteMu      sync.Mutex
	terminalVisit          func()

	// Configuration.
	collectionInterval time.Duration
	cleanupInterval    time.Duration
	retentionPeriod    time.Duration

	// Control.
	stop         chan struct{}
	stopOnce     sync.Once
	controlMu    sync.Mutex
	workerCancel context.CancelFunc
	workerWG     sync.WaitGroup
	started      bool
	stopped      bool

	coordinatorMu          sync.Mutex
	coordinatorInitialized bool
	lastRollup1m           int64
	lastRollup1h           int64
	lastRollup1d           int64
	nextCleanup            time.Time
}

// Store interface for persisting metrics.
//
//nolint:interfacebloat // domain interface for metrics persistence; methods cohere around the same data store.
type Store interface {
	// SaveRawMetric saves a raw metric data point.
	SaveRawMetric(ctx context.Context, timestamp int64, queueID, metricName string, value float64, labels string) error

	// SaveRateSnapshot saves rate calculation results.
	SaveRateSnapshot(ctx context.Context, timestamp int64, queueID, metricName string, ratePerSecond float64, windowMS int64) error

	SaveMetric(ctx context.Context, sample MetricSample) error
	SaveCoverage(ctx context.Context, coverage CoverageBucket) error
	SaveMetricAndCoverage(ctx context.Context, sample MetricSample, coverage CoverageBucket) error
	QuerySeries(ctx context.Context, query SeriesQuery) (SeriesResult, error)
	QuerySubjectCoverage(ctx context.Context, query SubjectCoverageQuery) ([]CoverageBucket, error)
	SaveRateSnapshotAndMetric(
		ctx context.Context,
		timestamp int64,
		subjectID, metricName string,
		rate float64,
		windowMS int64,
		sample MetricSample,
	) error
	SaveCollectionBoundary(ctx context.Context, batch CollectionBatch) error
	LatestCollectionBoundary(ctx context.Context, sampleIntervalMS int64) (int64, bool, error)
	Rollup(ctx context.Context, resolution Resolution, closedThrough int64) error
	ResetRawInterval(ctx context.Context, sampleIntervalMS int64) (bool, error)
	EnqueueTerminalState(ctx context.Context, state TerminalState, limit int) (bool, error)
	CancelTerminalState(ctx context.Context, subjectID string, generation int64) error
	ListTerminalStates(ctx context.Context) ([]TerminalState, error)
	AssignTerminalBucket(
		ctx context.Context, subjectID string, generation, targetBucket, sampleIntervalMS int64,
	) error
	CompleteTerminalState(
		ctx context.Context, subjectID string, generation int64, sample MetricSample, coverage CoverageBucket,
	) error

	// SaveQueueStats saves queue statistics snapshot.
	SaveQueueStats(ctx context.Context, timestamp int64, queueID string, depth, visible, invisible int64, oldestAge, avgAge float64) error

	// UpdateInFlightCount updates the in-flight message count for a queue.
	UpdateInFlightCount(ctx context.Context, queueID string, count int64) error

	// Aggregate1m aggregates raw metrics into 1-minute buckets.
	Aggregate1m(ctx context.Context, fromTimestamp, toTimestamp int64) error

	// Aggregate1h aggregates 1-minute metrics into 1-hour buckets.
	Aggregate1h(ctx context.Context, fromTimestamp, toTimestamp int64) error

	// Aggregate1d aggregates 1-hour metrics into 1-day buckets.
	Aggregate1d(ctx context.Context, fromTimestamp, toTimestamp int64) error

	// CleanupOldMetrics removes metrics older than retention period.
	CleanupOldMetrics(ctx context.Context, rawBefore, m1Before, m5Before, h1Before, d1Before int64) error

	// GetMetrics retrieves metrics for a time range.
	GetMetrics(ctx context.Context, metricName, queueID string, from, to int64, resolution string) ([]DataPoint, error)

	// GetLatestRates retrieves the latest rate values.
	GetLatestRates(ctx context.Context, queueID string) (map[string]float64, error)

	// GetQueueStats retrieves queue statistics.
	GetQueueStats(ctx context.Context, queueID string, from, to int64) ([]QueueStatsPoint, error)
}

// QueueStatsPoint represents queue statistics at a point in time.
type QueueStatsPoint struct {
	Timestamp         int64   `json:"timestamp"`
	QueueDepth        int64   `json:"queueDepth"`
	MessagesVisible   int64   `json:"messagesVisible"`
	MessagesInvisible int64   `json:"messagesInvisible"`
	OldestMessageAge  float64 `json:"oldestMessageAge"`
	AvgMessageAge     float64 `json:"avgMessageAge"`
}

// Option configures the Collector.
type Option func(*Collector)

// WithLogger sets the logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Collector) { c.logger = logger }
}

// WithCollectionInterval sets the collection interval.
func WithCollectionInterval(d time.Duration) Option {
	return func(c *Collector) { c.collectionInterval = d }
}

// WithCleanupInterval sets the ordered retention worker interval.
func WithCleanupInterval(d time.Duration) Option {
	return func(c *Collector) { c.cleanupInterval = d }
}

// WithRetentionPeriod sets the maximum telemetry history retained on disk.
func WithRetentionPeriod(d time.Duration) Option {
	return func(c *Collector) { c.retentionPeriod = d }
}

// WithClock replaces the collector clock for deterministic cutover tests.
func WithClock(now func() time.Time) Option {
	return func(c *Collector) {
		if now != nil {
			c.now = now
		}
	}
}

// New creates a new Collector.
func New(store Store, opts ...Option) *Collector {
	c := &Collector{
		logger:               logkit.NewNop(),
		store:                store,
		queueMetrics:         make(map[string]*QueueMetrics),
		topicMetrics:         make(map[string]*TopicMetrics),
		topicCache:           newTopicCache(),
		topicLimit:           defaultTopicLimit,
		collectionInterval:   defaultCollectionInterval,
		cleanupInterval:      defaultCleanupInterval,
		retentionPeriod:      defaultRetentionPeriod,
		now:                  time.Now,
		eventBufferLimit:     defaultEventBufferLimit,
		eventDirty:           make(map[string]dirtyInterval, 3),
		topicDirty:           make(map[string]map[string]dirtyInterval),
		topicDirtyOverflow:   make(map[string]dirtyInterval),
		terminalLimit:        defaultTerminalStateLimit,
		terminalReservations: make(map[string]*terminalReservation),
		terminalEntries:      make(map[terminalKey]*terminalReservation),
		terminalQueue:        list.New(),
		stop:                 make(chan struct{}),
	}
	c.terminalOrder = btree.NewG(terminalOrderDegree, func(left, right *terminalReservation) bool {
		return c.terminalStateBefore(left.state, right.state)
	})

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// CollectionInterval returns the configured raw wall-clock grid interval.
func (c *Collector) CollectionInterval() time.Duration { return c.collectionInterval }

// RetentionPeriod returns the configured maximum telemetry history.
func (c *Collector) RetentionPeriod() time.Duration { return c.retentionPeriod }

// Start begins the metrics collection background workers.
func (c *Collector) Start(ctx context.Context) {
	c.controlMu.Lock()
	if c.started || c.stopped {
		c.controlMu.Unlock()

		return
	}

	workerCtx, cancel := context.WithCancel(ctx)
	c.workerCancel = cancel
	c.started = true
	c.workerWG.Add(1)
	c.controlMu.Unlock()

	go func() {
		defer c.workerWG.Done()

		c.coordinatorWorker(workerCtx)
	}()

	c.logger.Info("Metrics collector started")
}

// Stop stops the collector.
func (c *Collector) Stop() {
	c.stopOnce.Do(func() {
		c.controlMu.Lock()
		c.stopped = true
		cancel := c.workerCancel
		c.controlMu.Unlock()

		if cancel != nil {
			cancel()
		}

		close(c.stop)
	})
	c.workerWG.Wait()
	c.logger.Info("Metrics collector stopped")
}

// getOrCreateQueueMetrics gets or creates metrics for a queue.
func (c *Collector) getOrCreateQueueMetrics(queueID string) *QueueMetrics {
	c.queueMu.RLock()
	m, ok := c.queueMetrics[queueID]
	c.queueMu.RUnlock()

	if ok {
		return m
	}

	c.queueMu.Lock()
	defer c.queueMu.Unlock()

	// Double-check after acquiring write lock.
	if m, ok = c.queueMetrics[queueID]; ok {
		return m
	}

	m = &QueueMetrics{}
	c.queueMetrics[queueID] = m

	return m
}

// RecordSend records a send operation.
func (c *Collector) RecordSend(queueID string, count, totalBytes uint64) {
	c.cutoverMu.Lock()
	m := c.getOrCreateQueueMetrics(queueID)
	m.messagesSent.Add(count)
	m.bytesSent.Add(totalBytes)
	c.system.totalSent.Add(count)
	c.cutoverMu.Unlock()
}

// RecordReceive records a receive operation.
//
//nolint:revive // isEmpty is a reasonable flag parameter for this API.
func (c *Collector) RecordReceive(queueID string, count uint64, isEmpty bool) {
	c.cutoverMu.Lock()
	m := c.getOrCreateQueueMetrics(queueID)
	m.messagesReceived.Add(count)
	m.messagesInFlight.Add(int64(count)) //nolint:gosec // count is a message count that will never approach int64 max
	c.system.totalReceived.Add(count)

	if isEmpty {
		m.emptyReceives.Add(1)
	}

	inFlight := m.messagesInFlight.Load()
	c.cutoverMu.Unlock()

	// Update in-flight count in store.
	if c.store != nil {
		_ = c.store.UpdateInFlightCount(context.Background(), queueID, inFlight) //nolint:errcheck // best-effort metrics
	}
}

// RecordDelete records a delete operation.
func (c *Collector) RecordDelete(queueID string, count uint64) {
	c.cutoverMu.Lock()
	m := c.getOrCreateQueueMetrics(queueID)
	m.messagesDeleted.Add(count)
	m.messagesInFlight.Add(-int64(count)) //nolint:gosec // count is a message count that will never approach int64 max
	c.system.totalDeleted.Add(count)

	inFlight := m.messagesInFlight.Load()
	c.cutoverMu.Unlock()

	// Update in-flight count in store.
	if c.store != nil {
		_ = c.store.UpdateInFlightCount(context.Background(), queueID, inFlight) //nolint:errcheck // best-effort metrics
	}
}

// RecordRedelivery records a message redelivery.
//
// The redelivered messages come back out of the in-flight count for the same
// reason they do on the Prometheus side: the receive that carried them already
// counted them, and they were counted once already on their first delivery.
func (c *Collector) RecordRedelivery(queueID string, count uint64) {
	c.cutoverMu.Lock()
	m := c.getOrCreateQueueMetrics(queueID)
	m.messagesRedelivered.Add(count)
	m.messagesInFlight.Add(-int64(count)) //nolint:gosec // a redelivery count cannot approach int64 max.
	c.cutoverMu.Unlock()
}

// RecordDrop records dropped messages.
func (c *Collector) RecordDrop(queueID string, count uint64) {
	c.cutoverMu.Lock()
	m := c.getOrCreateQueueMetrics(queueID)
	m.messagesDropped.Add(count)
	c.cutoverMu.Unlock()
}

// RecordDLQ records messages moved to DLQ.
func (c *Collector) RecordDLQ(queueID string, count uint64) {
	c.cutoverMu.Lock()
	m := c.getOrCreateQueueMetrics(queueID)
	m.messagesToDLQ.Add(count)
	c.cutoverMu.Unlock()
}

// The collector used to accumulate batch sizes, message sizes, processing
// durations and dwell times into per-queue slices. Nothing ever read them and
// nothing ever truncated them, so they were an append-only allocation for
// every message the server handled — dormant only because the methods that
// appended to them were never called. Those distributions are now real
// Prometheus histograms with bounded memory; the collector keeps the counters
// and rates its own dashboards draw.

// SetQueuesExist sets the current queue count.
func (c *Collector) SetQueuesExist(count int64) {
	c.cutoverMu.Lock()
	c.system.queuesExist.Store(count)
	c.cutoverMu.Unlock()
}

// IncrementQueues increments the queue count.
func (c *Collector) IncrementQueues() {
	c.cutoverMu.Lock()
	c.system.queuesExist.Add(1)
	c.cutoverMu.Unlock()
}

// DecrementQueues decrements the queue count.
func (c *Collector) DecrementQueues() {
	c.cutoverMu.Lock()
	c.system.queuesExist.Add(-1)
	c.cutoverMu.Unlock()
}

// GetInFlightCount returns the current in-flight count for a queue.
func (c *Collector) GetInFlightCount(queueID string) int64 {
	m := c.getOrCreateQueueMetrics(queueID)

	return m.messagesInFlight.Load()
}

// GetSystemInFlightCount returns total in-flight messages across all queues.
func (c *Collector) GetSystemInFlightCount() int64 {
	c.queueMu.RLock()
	defer c.queueMu.RUnlock()

	var total int64
	for _, m := range c.queueMetrics {
		total += m.messagesInFlight.Load()
	}

	return total
}

// Rates holds rate values for send, receive, and delete operations.
type Rates struct {
	SendRate    float64
	ReceiveRate float64
	DeleteRate  float64
}

// GetRates returns current rates for a queue.
func (c *Collector) GetRates(queueID string) Rates {
	m := c.getOrCreateQueueMetrics(queueID)

	return Rates{
		SendRate:    float64FromBits(m.sendRate.Load()),
		ReceiveRate: float64FromBits(m.receiveRate.Load()),
		DeleteRate:  float64FromBits(m.deleteRate.Load()),
	}
}

// GetSystemRates returns system-wide rates.
func (c *Collector) GetSystemRates() Rates {
	return Rates{
		SendRate:    float64FromBits(c.system.systemSendRate.Load()),
		ReceiveRate: float64FromBits(c.system.systemReceiveRate.Load()),
		DeleteRate:  float64FromBits(c.system.systemDeleteRate.Load()),
	}
}

// SystemCounters holds the cluster-wide queue totals.
type SystemCounters struct {
	QueuesExist   int64
	TotalSent     uint64
	TotalReceived uint64
	TotalDeleted  uint64
}

// GetSystemCounters returns the system-wide queue totals.
func (c *Collector) GetSystemCounters() SystemCounters {
	return SystemCounters{
		QueuesExist:   c.system.queuesExist.Load(),
		TotalSent:     c.system.totalSent.Load(),
		TotalReceived: c.system.totalReceived.Load(),
		TotalDeleted:  c.system.totalDeleted.Load(),
	}
}

// GetCounters returns current counter values for a queue.
func (c *Collector) GetCounters(queueID string) map[string]uint64 {
	m := c.getOrCreateQueueMetrics(queueID)

	return map[string]uint64{
		MetricMessagesSentTotal:     m.messagesSent.Load(),
		MetricMessagesReceivedTotal: m.messagesReceived.Load(),
		MetricMessagesDeletedTotal:  m.messagesDeleted.Load(),
		MetricMessagesDroppedTotal:  m.messagesDropped.Load(),
		MetricEmptyReceivesTotal:    m.emptyReceives.Load(),
		MetricMessagesRedelivered:   m.messagesRedelivered.Load(),
		MetricMessagesToDLQ:         m.messagesToDLQ.Load(),
		MetricBytesSentTotal:        m.bytesSent.Load(),
	}
}

// GetAllQueueIDs returns all tracked queue IDs.
func (c *Collector) GetAllQueueIDs() []string {
	c.queueMu.RLock()
	defer c.queueMu.RUnlock()

	ids := make([]string, 0, len(c.queueMetrics))
	for id := range c.queueMetrics {
		ids = append(ids, id)
	}

	return ids
}

// calculateRatesAt atomically persists queue, system, topic, event, and rate
// history at one exact closed boundary.
func (c *Collector) calculateRatesAt(ctx context.Context, boundary time.Time) (collectionErr error) {
	start := time.Now()
	defer func() { c.observeCollection(start, collectionErr) }()

	intervalMS := c.collectionInterval.Milliseconds()
	if intervalMS <= 0 {
		return errors.New("calculate rates: positive collection interval is required")
	}

	boundaryMS := boundary.UTC().UnixMilli()
	if boundaryMS <= 0 || boundaryMS%intervalMS != 0 {
		return errors.New("calculate rates: boundary must align to the collection interval")
	}

	return c.collectTopicBoundary(ctx, boundaryMS)
}

func counterDelta(current, previous uint64) uint64 {
	if current >= previous {
		return current - previous
	}

	return current
}

func rate(delta uint64, elapsed time.Duration) float64 {
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		return 0
	}

	return float64(delta) / seconds
}

type namedCounter struct {
	metricName string
	value      uint64
}

type namedGauge struct {
	metricName string
	value      float64
}

func (c *Collector) appendQueueBoundaryLocked(
	frozen *frozenTopicBoundary,
	boundary, bucketStart, intervalMS int64,
	markSubject func(string, bool),
) {
	queueIDs := make([]string, 0, len(c.queueMetrics))
	systemCounters := map[string]uint64{
		MetricMessagesSentTotal:     c.system.totalSent.Load(),
		MetricMessagesReceivedTotal: c.system.totalReceived.Load(),
		MetricMessagesDeletedTotal:  c.system.totalDeleted.Load(),
	}

	var systemInFlight int64

	for queueID, current := range c.queueMetrics {
		queueIDs = append(queueIDs, queueID)
		systemCounters[MetricMessagesDroppedTotal] += current.messagesDropped.Load()
		systemCounters[MetricEmptyReceivesTotal] += current.emptyReceives.Load()
		systemCounters[MetricMessagesRedelivered] += current.messagesRedelivered.Load()
		systemCounters[MetricMessagesToDLQ] += current.messagesToDLQ.Load()
		systemCounters[MetricBytesSentTotal] += current.bytesSent.Load()
		systemInFlight += current.messagesInFlight.Load()
	}

	systemBaseline, systemRates, systemComplete := appendQueueSubjectBoundary(
		frozen, "", c.system.baselines,
		[]namedCounter{
			{MetricMessagesSentTotal, systemCounters[MetricMessagesSentTotal]},
			{MetricMessagesReceivedTotal, systemCounters[MetricMessagesReceivedTotal]},
			{MetricMessagesDeletedTotal, systemCounters[MetricMessagesDeletedTotal]},
			{MetricMessagesDroppedTotal, systemCounters[MetricMessagesDroppedTotal]},
			{MetricEmptyReceivesTotal, systemCounters[MetricEmptyReceivesTotal]},
			{MetricMessagesRedelivered, systemCounters[MetricMessagesRedelivered]},
			{MetricMessagesToDLQ, systemCounters[MetricMessagesToDLQ]},
			{MetricBytesSentTotal, systemCounters[MetricBytesSentTotal]},
		},
		[]namedGauge{
			{MetricMessagesInFlight, float64(systemInFlight)},
			{MetricQueuesExist, float64(c.system.queuesExist.Load())},
		},
		boundary, bucketStart, intervalMS,
	)
	frozen.systemQueue = systemBaseline
	frozen.systemQueueRates = systemRates

	markSubject("", systemComplete)

	sort.Strings(queueIDs)

	for _, queueID := range queueIDs {
		current := c.queueMetrics[queueID]
		baseline, rates, complete := appendQueueSubjectBoundary(
			frozen, queueID, current.baselines,
			[]namedCounter{
				{MetricMessagesSentTotal, current.messagesSent.Load()},
				{MetricMessagesReceivedTotal, current.messagesReceived.Load()},
				{MetricMessagesDeletedTotal, current.messagesDeleted.Load()},
				{MetricMessagesDroppedTotal, current.messagesDropped.Load()},
				{MetricEmptyReceivesTotal, current.emptyReceives.Load()},
				{MetricMessagesRedelivered, current.messagesRedelivered.Load()},
				{MetricMessagesToDLQ, current.messagesToDLQ.Load()},
				{MetricBytesSentTotal, current.bytesSent.Load()},
			},
			[]namedGauge{{MetricMessagesInFlight, float64(current.messagesInFlight.Load())}},
			boundary, bucketStart, intervalMS,
		)
		frozen.queueBaselines[queueID] = baseline
		frozen.queueRates[queueID] = rates
		frozen.queueMetrics[queueID] = current
		markSubject(queueID, complete)
	}
}

func appendQueueSubjectBoundary(
	frozen *frozenTopicBoundary,
	subjectID string,
	previous queueRateBaselines,
	counters []namedCounter,
	gauges []namedGauge,
	boundary, bucketStart, intervalMS int64,
) (queueRateBaselines, Rates, bool) {
	for _, counter := range counters {
		appendPeriodicSample(&frozen.batch, MetricSample{
			Timestamp: bucketStart, SubjectID: subjectID,
			MetricName: counter.metricName, Kind: MetricKindCounter, Value: float64(counter.value),
		}, intervalMS, true)
	}

	for _, gauge := range gauges {
		appendPeriodicSample(&frozen.batch, MetricSample{
			Timestamp: bucketStart, SubjectID: subjectID,
			MetricName: gauge.metricName, Kind: MetricKindGauge, Value: gauge.value,
		}, intervalMS, true)
	}

	current := queueRateBaselines{
		sent: counterRateBaseline{
			known: true, value: counterValue(counters, MetricMessagesSentTotal), observedAt: boundary,
		},
		received: counterRateBaseline{
			known: true, value: counterValue(counters, MetricMessagesReceivedTotal), observedAt: boundary,
		},
		deleted: counterRateBaseline{
			known: true, value: counterValue(counters, MetricMessagesDeletedTotal), observedAt: boundary,
		},
	}
	rates := Rates{}
	complete := true

	appendRate := func(metricName string, baseline counterRateBaseline, value uint64, assign func(float64)) {
		if !baseline.known || boundary <= baseline.observedAt {
			complete = false

			return
		}

		windowMS := boundary - baseline.observedAt
		valuePerSecond := rate(counterDelta(value, baseline.value), time.Duration(windowMS)*time.Millisecond)
		assign(valuePerSecond)
		sample := MetricSample{
			Timestamp: bucketStart, SubjectID: subjectID, MetricName: metricName,
			Kind: MetricKindRate, Value: valuePerSecond, WindowMS: windowMS,
		}
		appendPeriodicSample(&frozen.batch, sample, intervalMS, windowMS == intervalMS)

		frozen.batch.RateSnapshots = append(frozen.batch.RateSnapshots, RateSnapshot{
			Timestamp: bucketStart, SubjectID: subjectID, MetricName: metricName,
			Rate: valuePerSecond, WindowMS: windowMS,
		})
		if windowMS != intervalMS {
			complete = false
		}
	}

	appendRate(MetricSendRate, previous.sent, current.sent.value,
		func(value float64) { rates.SendRate = value })
	appendRate(MetricReceiveRate, previous.received, current.received.value,
		func(value float64) { rates.ReceiveRate = value })
	appendRate(MetricDeleteRate, previous.deleted, current.deleted.value,
		func(value float64) { rates.DeleteRate = value })

	return current, rates, complete
}

func counterValue(counters []namedCounter, metricName string) uint64 {
	for _, counter := range counters {
		if counter.metricName == metricName {
			return counter.value
		}
	}

	return 0
}

func (c *Collector) finalizeQueueBoundaryLocked(frozen *frozenTopicBoundary) {
	c.system.baselines = frozen.systemQueue
	c.system.systemSendRate.Store(float64ToBits(frozen.systemQueueRates.SendRate))
	c.system.systemReceiveRate.Store(float64ToBits(frozen.systemQueueRates.ReceiveRate))
	c.system.systemDeleteRate.Store(float64ToBits(frozen.systemQueueRates.DeleteRate))

	for queueID, baseline := range frozen.queueBaselines {
		current, exists := c.queueMetrics[queueID]
		if !exists || current != frozen.queueMetrics[queueID] {
			continue
		}

		current.baselines = baseline
		rates := frozen.queueRates[queueID]
		current.sendRate.Store(float64ToBits(rates.SendRate))
		current.receiveRate.Store(float64ToBits(rates.ReceiveRate))
		current.deleteRate.Store(float64ToBits(rates.DeleteRate))
	}
}

// Helper functions for atomic float64 operations.
func float64ToBits(f float64) uint64 {
	return math.Float64bits(f)
}

func float64FromBits(b uint64) float64 {
	return math.Float64frombits(b)
}
