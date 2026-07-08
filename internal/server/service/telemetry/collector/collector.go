// Package collector provides a comprehensive metrics collection system
// for tracking queue operations with rate calculations, in-flight tracking,
// and time-series storage.
package collector

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marsolab/servekit/logkit"
)

const (
	// Default collection interval for rate calculations.
	defaultCollectionInterval = 1 * time.Second

	// Default snapshot interval for queue statistics.
	defaultSnapshotInterval = 5 * time.Second

	// Default aggregation intervals.
	aggregationInterval1m = 1 * time.Minute
	aggregationInterval1h = 1 * time.Hour
	aggregationInterval1d = 24 * time.Hour

	// Retention periods (like Grafana defaults).
	retentionRaw = 1 * time.Hour
	retention1m  = 24 * time.Hour
	retention5m  = 7 * 24 * time.Hour
	retention1h  = 30 * 24 * time.Hour
	retention1d  = 365 * 24 * time.Hour

	// Default slice capacities for histogram accumulators.
	defaultSliceCapLarge = 1000
	defaultSliceCapSmall = 100

	// Bucket sizes in milliseconds for time-series aggregation.
	bucketSize1m = 60000    // 1 minute in ms.
	bucketSize1h = 3600000  // 1 hour in ms.
	bucketSize1d = 86400000 // 1 day in ms.
)

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
	MetricTopicPublishRate  = "plainq_topic_publish_rate"
	MetricTopicDeliveryRate = "plainq_topic_delivery_rate"
)

// Metric names for topic counter metrics (cumulative).
const (
	MetricTopicMessagesPublishedTotal    = "plainq_topic_messages_published_total"
	MetricTopicDeliveriesTotal           = "plainq_topic_deliveries_total"
	MetricTopicSubscriptionsCreatedTotal = "plainq_topic_subscriptions_created_total"
	MetricTopicSubscriptionsDeletedTotal = "plainq_topic_subscriptions_deleted_total"
)

// Metric names for topic gauge metrics (current value).
const (
	MetricTopicSubscriptionsCurrent = "plainq_topic_subscriptions_current"
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

	// Previous values for rate calculation.
	prevSent     uint64
	prevReceived uint64
	prevDeleted  uint64

	// Calculated rates.
	sendRate    atomic.Uint64 // Stored as float64 bits.
	receiveRate atomic.Uint64
	deleteRate  atomic.Uint64

	// Histogram accumulators (simplified - use summary stats).
	processingDurations []float64
	dwellTimes          []float64
	batchSizes          []int
	messageSizes        []int
	histogramMu         sync.Mutex
}

// TopicMetrics holds metrics for a specific topic.
type TopicMetrics struct {
	// Counters (atomic for thread safety).
	messagesPublished    atomic.Uint64
	deliveries           atomic.Uint64
	subscriptionsCreated atomic.Uint64
	subscriptionsDeleted atomic.Uint64
	subscriptionsCurrent atomic.Int64
	subscriptionsKnown   atomic.Bool
	lastUpdated          atomic.Int64

	// Previous values for rate calculation.
	prevMessagesPublished uint64
	prevDeliveries        uint64

	// Calculated rates.
	publishRate  atomic.Uint64 // Stored as float64 bits.
	deliveryRate atomic.Uint64
}

// TopicSystemMetrics holds system-wide topic metrics.
type TopicSystemMetrics struct {
	totalMessagesPublished    atomic.Uint64
	totalDeliveries           atomic.Uint64
	totalSubscriptionsCreated atomic.Uint64
	totalSubscriptionsDeleted atomic.Uint64
	subscriptionsCurrent      atomic.Int64
	subscriptionsKnown        atomic.Bool

	// Previous values for system-wide rates.
	prevTotalMessagesPublished uint64
	prevTotalDeliveries        uint64

	// System-wide rates.
	systemPublishRate  atomic.Uint64
	systemDeliveryRate atomic.Uint64
}

type TopicRates struct {
	PublishRate  float64
	DeliveryRate float64
}

type TopicCounters struct {
	MessagesPublished    uint64
	Deliveries           uint64
	SubscriptionsCreated uint64
	SubscriptionsDeleted uint64
}

type TopicSystemCounters struct {
	MessagesPublished         uint64
	Deliveries                uint64
	SubscriptionsCurrent      int64
	SubscriptionsCurrentKnown bool
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

	// Previous values for system-wide rates.
	prevTotalSent     uint64
	prevTotalReceived uint64
	prevTotalDeleted  uint64

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

	// System-wide metrics.
	system      SystemMetrics
	topicSystem TopicSystemMetrics

	// Configuration.
	collectionInterval time.Duration
	snapshotInterval   time.Duration

	// Control.
	stop     chan struct{}
	stopOnce sync.Once
}

// Store interface for persisting metrics.
//
//nolint:interfacebloat // domain interface for metrics persistence; methods cohere around the same data store.
type Store interface {
	// SaveRawMetric saves a raw metric data point.
	SaveRawMetric(ctx context.Context, timestamp int64, queueID, metricName string, value float64, labels string) error

	// SaveRateSnapshot saves rate calculation results.
	SaveRateSnapshot(ctx context.Context, timestamp int64, queueID, metricName string, ratePerSecond float64, windowSeconds int) error

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

// DataPoint represents a single metric data point.
type DataPoint struct {
	Timestamp int64   `json:"timestamp"`
	Value     float64 `json:"value"`
	Min       float64 `json:"min,omitempty"`
	Max       float64 `json:"max,omitempty"`
	Avg       float64 `json:"avg,omitempty"`
	Sum       float64 `json:"sum,omitempty"`
	Count     int64   `json:"count,omitempty"`
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

// WithSnapshotInterval sets the snapshot interval.
func WithSnapshotInterval(d time.Duration) Option {
	return func(c *Collector) { c.snapshotInterval = d }
}

// New creates a new Collector.
func New(store Store, opts ...Option) *Collector {
	c := &Collector{
		logger:             logkit.NewNop(),
		store:              store,
		queueMetrics:       make(map[string]*QueueMetrics),
		topicMetrics:       make(map[string]*TopicMetrics),
		collectionInterval: defaultCollectionInterval,
		snapshotInterval:   defaultSnapshotInterval,
		stop:               make(chan struct{}),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Start begins the metrics collection background workers.
func (c *Collector) Start(ctx context.Context) {
	// Rate calculation worker.
	go c.rateCalculationWorker(ctx)

	// Aggregation workers.
	go c.aggregationWorker(ctx, aggregationInterval1m, "1m", c.aggregate1m)
	go c.aggregationWorker(ctx, aggregationInterval1h, "1h", c.aggregate1h)
	go c.aggregationWorker(ctx, aggregationInterval1d, "1d", c.aggregate1d)

	// Cleanup worker.
	go c.cleanupWorker(ctx)

	c.logger.Info("Metrics collector started")
}

// Stop stops the collector.
func (c *Collector) Stop() {
	c.stopOnce.Do(func() {
		close(c.stop)
		c.logger.Info("Metrics collector stopped")
	})
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

	m = &QueueMetrics{
		processingDurations: make([]float64, 0, defaultSliceCapLarge),
		dwellTimes:          make([]float64, 0, defaultSliceCapLarge),
		batchSizes:          make([]int, 0, defaultSliceCapSmall),
		messageSizes:        make([]int, 0, defaultSliceCapLarge),
	}
	c.queueMetrics[queueID] = m

	return m
}

// getOrCreateTopicMetrics gets or creates metrics for a topic.
func (c *Collector) getOrCreateTopicMetrics(topicID string) *TopicMetrics {
	c.topicMu.RLock()
	m, ok := c.topicMetrics[topicID]
	c.topicMu.RUnlock()

	if ok {
		return m
	}

	c.topicMu.Lock()
	defer c.topicMu.Unlock()

	if m, ok = c.topicMetrics[topicID]; ok {
		return m
	}

	m = &TopicMetrics{}
	c.topicMetrics[topicID] = m

	return m
}

func (c *Collector) topicMetricsForRead(topicID string) (*TopicMetrics, bool) {
	c.topicMu.RLock()
	defer c.topicMu.RUnlock()

	m, ok := c.topicMetrics[topicID]

	return m, ok
}

// RecordTopicPublish records topic publish and delivery counts.
func (c *Collector) RecordTopicPublish(topicID string, messagesPublished, deliveries uint64) {
	m := c.getOrCreateTopicMetrics(topicID)
	m.messagesPublished.Add(messagesPublished)
	m.deliveries.Add(deliveries)
	m.lastUpdated.Store(time.Now().UnixMilli())
	c.topicSystem.totalMessagesPublished.Add(messagesPublished)
	c.topicSystem.totalDeliveries.Add(deliveries)
}

// RecordTopicSubscriptionCreated records a topic subscription creation.
func (c *Collector) RecordTopicSubscriptionCreated(topicID string, currentCount int64) {
	m := c.getOrCreateTopicMetrics(topicID)
	m.subscriptionsCreated.Add(1)
	m.lastUpdated.Store(time.Now().UnixMilli())
	c.topicSystem.totalSubscriptionsCreated.Add(1)
	c.setTopicSubscriptionsCurrent(m, currentCount)
}

// RecordTopicSubscriptionDeleted records a topic subscription deletion.
func (c *Collector) RecordTopicSubscriptionDeleted(topicID string, currentCount int64) {
	m := c.getOrCreateTopicMetrics(topicID)
	m.subscriptionsDeleted.Add(1)
	m.lastUpdated.Store(time.Now().UnixMilli())
	c.topicSystem.totalSubscriptionsDeleted.Add(1)
	c.setTopicSubscriptionsCurrent(m, currentCount)
}

// ReconcileTopicSubscriptionCounts refreshes topic subscription gauges from an authoritative topic list.
func (c *Collector) ReconcileTopicSubscriptionCounts(countsByTopic map[string]int64) {
	now := time.Now().UnixMilli()

	c.topicMu.Lock()
	defer c.topicMu.Unlock()

	for topicID, currentCount := range countsByTopic {
		if currentCount < 0 {
			continue
		}

		m, ok := c.topicMetrics[topicID]
		if !ok {
			m = &TopicMetrics{}
			c.topicMetrics[topicID] = m
			m.lastUpdated.Store(now)
		}

		if m.subscriptionsCurrent.Load() != currentCount {
			m.subscriptionsCurrent.Store(currentCount)
			m.lastUpdated.Store(now)
		}

		m.subscriptionsKnown.Store(true)
	}

	for topicID := range c.topicMetrics {
		if _, ok := countsByTopic[topicID]; !ok {
			delete(c.topicMetrics, topicID)
		}
	}

	var total int64
	for _, m := range c.topicMetrics {
		total += m.subscriptionsCurrent.Load()
	}

	c.topicSystem.subscriptionsCurrent.Store(total)
	c.topicSystem.subscriptionsKnown.Store(true)
}

func (c *Collector) setTopicSubscriptionsCurrent(m *TopicMetrics, currentCount int64) {
	if currentCount < 0 {
		m.subscriptionsKnown.Store(false)
		c.recalculateTopicSystemSubscriptionsCurrent()

		return
	}

	m.subscriptionsCurrent.Store(currentCount)
	m.subscriptionsKnown.Store(true)
	c.recalculateTopicSystemSubscriptionsCurrent()
}

func (c *Collector) recalculateTopicSystemSubscriptionsCurrent() {
	c.topicMu.RLock()
	defer c.topicMu.RUnlock()

	var total int64

	for _, m := range c.topicMetrics {
		if !m.subscriptionsKnown.Load() {
			c.topicSystem.subscriptionsKnown.Store(false)

			return
		}

		total += m.subscriptionsCurrent.Load()
	}

	c.topicSystem.subscriptionsCurrent.Store(total)
	c.topicSystem.subscriptionsKnown.Store(true)
}

// GetTopicRates returns current topic rates for one topic.
func (c *Collector) GetTopicRates(topicID string) TopicRates {
	m, ok := c.topicMetricsForRead(topicID)
	if !ok {
		return TopicRates{}
	}

	return TopicRates{
		PublishRate:  float64FromBits(m.publishRate.Load()),
		DeliveryRate: float64FromBits(m.deliveryRate.Load()),
	}
}

// GetTopicSystemRates returns current system-wide topic rates.
func (c *Collector) GetTopicSystemRates() TopicRates {
	return TopicRates{
		PublishRate:  float64FromBits(c.topicSystem.systemPublishRate.Load()),
		DeliveryRate: float64FromBits(c.topicSystem.systemDeliveryRate.Load()),
	}
}

// GetTopicCounters returns current counters for one topic.
func (c *Collector) GetTopicCounters(topicID string) TopicCounters {
	m, ok := c.topicMetricsForRead(topicID)
	if !ok {
		return TopicCounters{}
	}

	return TopicCounters{
		MessagesPublished:    m.messagesPublished.Load(),
		Deliveries:           m.deliveries.Load(),
		SubscriptionsCreated: m.subscriptionsCreated.Load(),
		SubscriptionsDeleted: m.subscriptionsDeleted.Load(),
	}
}

// GetTopicSystemCounters returns current system-wide topic counters.
func (c *Collector) GetTopicSystemCounters() TopicSystemCounters {
	return TopicSystemCounters{
		MessagesPublished:         c.topicSystem.totalMessagesPublished.Load(),
		Deliveries:                c.topicSystem.totalDeliveries.Load(),
		SubscriptionsCurrent:      c.topicSystem.subscriptionsCurrent.Load(),
		SubscriptionsCurrentKnown: c.topicSystem.subscriptionsKnown.Load(),
		SubscriptionsCreated:      c.topicSystem.totalSubscriptionsCreated.Load(),
		SubscriptionsDeleted:      c.topicSystem.totalSubscriptionsDeleted.Load(),
	}
}

// GetTopicSubscriptionsCurrent returns current subscription count for one topic.
func (c *Collector) GetTopicSubscriptionsCurrent(topicID string) int64 {
	m, ok := c.topicMetricsForRead(topicID)
	if !ok {
		return 0
	}

	return m.subscriptionsCurrent.Load()
}

// GetTopicSubscriptionsCurrentKnown returns the current subscription count only when it is known.
func (c *Collector) GetTopicSubscriptionsCurrentKnown(topicID string) (int64, bool) {
	m, ok := c.topicMetricsForRead(topicID)
	if !ok || !m.subscriptionsKnown.Load() {
		return 0, false
	}

	return m.subscriptionsCurrent.Load(), true
}

// GetTopicLastUpdated returns the latest metric activity timestamp for one topic.
func (c *Collector) GetTopicLastUpdated(topicID string) int64 {
	m, ok := c.topicMetricsForRead(topicID)
	if !ok {
		return 0
	}

	return m.lastUpdated.Load()
}

// GetAllTopicIDs returns all tracked topic IDs.
func (c *Collector) GetAllTopicIDs() []string {
	c.topicMu.RLock()
	defer c.topicMu.RUnlock()

	ids := make([]string, 0, len(c.topicMetrics))
	for id := range c.topicMetrics {
		ids = append(ids, id)
	}

	sort.Strings(ids)

	return ids
}

// RecordSend records a send operation.
func (c *Collector) RecordSend(queueID string, count, totalBytes uint64) {
	m := c.getOrCreateQueueMetrics(queueID)
	m.messagesSent.Add(count)
	m.bytesSent.Add(totalBytes)
	c.system.totalSent.Add(count)
}

// RecordReceive records a receive operation.
//
//nolint:revive // isEmpty is a reasonable flag parameter for this API.
func (c *Collector) RecordReceive(queueID string, count uint64, isEmpty bool) {
	m := c.getOrCreateQueueMetrics(queueID)
	m.messagesReceived.Add(count)
	m.messagesInFlight.Add(int64(count)) //nolint:gosec // count is a message count that will never approach int64 max
	c.system.totalReceived.Add(count)

	if isEmpty {
		m.emptyReceives.Add(1)
	}

	// Update in-flight count in store.
	if c.store != nil {
		_ = c.store.UpdateInFlightCount(context.Background(), queueID, m.messagesInFlight.Load()) //nolint:errcheck // best-effort metrics
	}
}

// RecordDelete records a delete operation.
func (c *Collector) RecordDelete(queueID string, count uint64, dwellTimeSeconds float64) {
	m := c.getOrCreateQueueMetrics(queueID)
	m.messagesDeleted.Add(count)
	m.messagesInFlight.Add(-int64(count)) //nolint:gosec // count is a message count that will never approach int64 max
	c.system.totalDeleted.Add(count)

	// Record dwell time.
	if dwellTimeSeconds > 0 {
		m.histogramMu.Lock()
		m.dwellTimes = append(m.dwellTimes, dwellTimeSeconds)
		m.histogramMu.Unlock()
	}

	// Update in-flight count in store.
	if c.store != nil {
		_ = c.store.UpdateInFlightCount(context.Background(), queueID, m.messagesInFlight.Load()) //nolint:errcheck // best-effort metrics
	}
}

// RecordRedelivery records a message redelivery.
func (c *Collector) RecordRedelivery(queueID string, count uint64) {
	m := c.getOrCreateQueueMetrics(queueID)
	m.messagesRedelivered.Add(count)
}

// RecordDrop records dropped messages.
func (c *Collector) RecordDrop(queueID string, count uint64) {
	m := c.getOrCreateQueueMetrics(queueID)
	m.messagesDropped.Add(count)
}

// RecordDLQ records messages moved to DLQ.
func (c *Collector) RecordDLQ(queueID string, count uint64) {
	m := c.getOrCreateQueueMetrics(queueID)
	m.messagesToDLQ.Add(count)
}

// RecordBatchSize records a batch operation size.
func (c *Collector) RecordBatchSize(queueID string, size int, _ string) {
	m := c.getOrCreateQueueMetrics(queueID)
	m.histogramMu.Lock()
	m.batchSizes = append(m.batchSizes, size)
	m.histogramMu.Unlock()
}

// RecordMessageSize records message body size.
func (c *Collector) RecordMessageSize(queueID string, sizeBytes int) {
	m := c.getOrCreateQueueMetrics(queueID)
	m.histogramMu.Lock()
	m.messageSizes = append(m.messageSizes, sizeBytes)
	m.histogramMu.Unlock()
}

// RecordProcessingDuration records message processing duration.
func (c *Collector) RecordProcessingDuration(queueID string, durationSeconds float64) {
	m := c.getOrCreateQueueMetrics(queueID)
	m.histogramMu.Lock()
	m.processingDurations = append(m.processingDurations, durationSeconds)
	m.histogramMu.Unlock()
}

// SetQueuesExist sets the current queue count.
func (c *Collector) SetQueuesExist(count int64) {
	c.system.queuesExist.Store(count)
}

// IncrementQueues increments the queue count.
func (c *Collector) IncrementQueues() {
	c.system.queuesExist.Add(1)
}

// DecrementQueues decrements the queue count.
func (c *Collector) DecrementQueues() {
	c.system.queuesExist.Add(-1)
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

// rateCalculationWorker calculates rates periodically.
func (c *Collector) rateCalculationWorker(ctx context.Context) {
	ticker := time.NewTicker(c.collectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-c.stop:
			return

		case <-ticker.C:
			c.calculateRates(ctx)
		}
	}
}

// calculateRates calculates rates for all queues.
func (c *Collector) calculateRates(ctx context.Context) {
	now := time.Now().UnixMilli()

	c.queueMu.RLock()
	defer c.queueMu.RUnlock()

	for queueID, m := range c.queueMetrics {
		currentSent := m.messagesSent.Load()
		currentReceived := m.messagesReceived.Load()
		currentDeleted := m.messagesDeleted.Load()

		// Calculate rates.
		sendRate := float64(currentSent - m.prevSent)
		receiveRate := float64(currentReceived - m.prevReceived)
		deleteRate := float64(currentDeleted - m.prevDeleted)

		// Store rates atomically.
		m.sendRate.Store(float64ToBits(sendRate))
		m.receiveRate.Store(float64ToBits(receiveRate))
		m.deleteRate.Store(float64ToBits(deleteRate))

		// Update previous values.
		m.prevSent = currentSent
		m.prevReceived = currentReceived
		m.prevDeleted = currentDeleted

		// Persist rates to store (best-effort, errors are non-fatal).
		if c.store != nil {
			//nolint:errcheck // best-effort metrics persistence
			_ = c.store.SaveRateSnapshot(ctx, now, queueID, MetricSendRate, sendRate, 1)
			//nolint:errcheck // best-effort metrics persistence
			_ = c.store.SaveRateSnapshot(ctx, now, queueID, MetricReceiveRate, receiveRate, 1)
			//nolint:errcheck // best-effort metrics persistence
			_ = c.store.SaveRateSnapshot(ctx, now, queueID, MetricDeleteRate, deleteRate, 1)
			//nolint:errcheck // best-effort metrics persistence
			_ = c.store.SaveRawMetric(ctx, now, queueID, MetricMessagesSentTotal, float64(currentSent), "")
			//nolint:errcheck // best-effort metrics persistence
			_ = c.store.SaveRawMetric(ctx, now, queueID, MetricMessagesReceivedTotal, float64(currentReceived), "")
			//nolint:errcheck // best-effort metrics persistence
			_ = c.store.SaveRawMetric(ctx, now, queueID, MetricMessagesDeletedTotal, float64(currentDeleted), "")
			//nolint:errcheck // best-effort metrics persistence
			_ = c.store.SaveRawMetric(ctx, now, queueID, MetricMessagesInFlight, float64(m.messagesInFlight.Load()), "")
		}
	}

	c.calculateTopicRates(ctx, now)

	// Calculate system-wide rates.
	currentTotalSent := c.system.totalSent.Load()
	currentTotalReceived := c.system.totalReceived.Load()
	currentTotalDeleted := c.system.totalDeleted.Load()

	systemSendRate := float64(currentTotalSent - c.system.prevTotalSent)
	systemReceiveRate := float64(currentTotalReceived - c.system.prevTotalReceived)
	systemDeleteRate := float64(currentTotalDeleted - c.system.prevTotalDeleted)

	c.system.systemSendRate.Store(float64ToBits(systemSendRate))
	c.system.systemReceiveRate.Store(float64ToBits(systemReceiveRate))
	c.system.systemDeleteRate.Store(float64ToBits(systemDeleteRate))

	c.system.prevTotalSent = currentTotalSent
	c.system.prevTotalReceived = currentTotalReceived
	c.system.prevTotalDeleted = currentTotalDeleted

	// Persist system-wide metrics (best-effort, errors are non-fatal).
	if c.store != nil {
		//nolint:errcheck // best-effort metrics persistence
		_ = c.store.SaveRateSnapshot(ctx, now, "", MetricSendRate, systemSendRate, 1)
		//nolint:errcheck // best-effort metrics persistence
		_ = c.store.SaveRateSnapshot(ctx, now, "", MetricReceiveRate, systemReceiveRate, 1)
		//nolint:errcheck // best-effort metrics persistence
		_ = c.store.SaveRateSnapshot(ctx, now, "", MetricDeleteRate, systemDeleteRate, 1)
		//nolint:errcheck // best-effort metrics persistence
		_ = c.store.SaveRawMetric(ctx, now, "", MetricQueuesExist, float64(c.system.queuesExist.Load()), "")
	}
}

func (c *Collector) calculateTopicRates(ctx context.Context, now int64) {
	c.topicMu.RLock()
	defer c.topicMu.RUnlock()

	for topicID, m := range c.topicMetrics {
		currentPublished := m.messagesPublished.Load()
		currentDeliveries := m.deliveries.Load()

		publishRate := float64(currentPublished - m.prevMessagesPublished)
		deliveryRate := float64(currentDeliveries - m.prevDeliveries)

		m.publishRate.Store(float64ToBits(publishRate))
		m.deliveryRate.Store(float64ToBits(deliveryRate))
		m.prevMessagesPublished = currentPublished
		m.prevDeliveries = currentDeliveries

		if c.store != nil {
			//nolint:errcheck // best-effort metrics persistence
			_ = c.store.SaveRateSnapshot(ctx, now, topicID, MetricTopicPublishRate, publishRate, 1)
			//nolint:errcheck // best-effort metrics persistence
			_ = c.store.SaveRateSnapshot(ctx, now, topicID, MetricTopicDeliveryRate, deliveryRate, 1)
			//nolint:errcheck // best-effort metrics persistence
			_ = c.store.SaveRawMetric(ctx, now, topicID, MetricTopicMessagesPublishedTotal, float64(currentPublished), "")
			//nolint:errcheck // best-effort metrics persistence
			_ = c.store.SaveRawMetric(ctx, now, topicID, MetricTopicDeliveriesTotal, float64(currentDeliveries), "")
			if m.subscriptionsKnown.Load() {
				//nolint:errcheck // best-effort metrics persistence
				_ = c.store.SaveRawMetric(ctx, now, topicID, MetricTopicSubscriptionsCurrent, float64(m.subscriptionsCurrent.Load()), "")
			}
			//nolint:errcheck // best-effort metrics persistence
			_ = c.store.SaveRawMetric(ctx, now, topicID, MetricTopicSubscriptionsCreatedTotal, float64(m.subscriptionsCreated.Load()), "")
			//nolint:errcheck // best-effort metrics persistence
			_ = c.store.SaveRawMetric(ctx, now, topicID, MetricTopicSubscriptionsDeletedTotal, float64(m.subscriptionsDeleted.Load()), "")
		}
	}

	currentSystemPublished := c.topicSystem.totalMessagesPublished.Load()
	currentSystemDeliveries := c.topicSystem.totalDeliveries.Load()

	systemPublishRate := float64(currentSystemPublished - c.topicSystem.prevTotalMessagesPublished)
	systemDeliveryRate := float64(currentSystemDeliveries - c.topicSystem.prevTotalDeliveries)

	c.topicSystem.systemPublishRate.Store(float64ToBits(systemPublishRate))
	c.topicSystem.systemDeliveryRate.Store(float64ToBits(systemDeliveryRate))
	c.topicSystem.prevTotalMessagesPublished = currentSystemPublished
	c.topicSystem.prevTotalDeliveries = currentSystemDeliveries

	if c.store != nil {
		//nolint:errcheck // best-effort metrics persistence
		_ = c.store.SaveRateSnapshot(ctx, now, "", MetricTopicPublishRate, systemPublishRate, 1)
		//nolint:errcheck // best-effort metrics persistence
		_ = c.store.SaveRateSnapshot(ctx, now, "", MetricTopicDeliveryRate, systemDeliveryRate, 1)
		//nolint:errcheck // best-effort metrics persistence
		_ = c.store.SaveRawMetric(ctx, now, "", MetricTopicMessagesPublishedTotal, float64(currentSystemPublished), "")
		//nolint:errcheck // best-effort metrics persistence
		_ = c.store.SaveRawMetric(ctx, now, "", MetricTopicDeliveriesTotal, float64(currentSystemDeliveries), "")
		if c.topicSystem.subscriptionsKnown.Load() {
			//nolint:errcheck // best-effort metrics persistence
			_ = c.store.SaveRawMetric(ctx, now, "", MetricTopicSubscriptionsCurrent, float64(c.topicSystem.subscriptionsCurrent.Load()), "")
		}
		//nolint:errcheck // best-effort metrics persistence
		_ = c.store.SaveRawMetric(
			ctx,
			now,
			"",
			MetricTopicSubscriptionsCreatedTotal,
			float64(c.topicSystem.totalSubscriptionsCreated.Load()),
			"",
		)
		//nolint:errcheck // best-effort metrics persistence
		_ = c.store.SaveRawMetric(
			ctx,
			now,
			"",
			MetricTopicSubscriptionsDeletedTotal,
			float64(c.topicSystem.totalSubscriptionsDeleted.Load()),
			"",
		)
	}
}

// aggregationWorker runs periodic aggregation.
func (c *Collector) aggregationWorker(ctx context.Context, interval time.Duration, name string, aggregateFn func(context.Context) error) {
	// Align to interval boundary.
	now := time.Now()
	nextRun := now.Truncate(interval).Add(interval)
	time.Sleep(nextRun.Sub(now))

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stop:
			return
		case <-ticker.C:
			if err := aggregateFn(ctx); err != nil {
				c.logger.Error("Aggregation failed",
					slog.String("interval", name),
					slog.String("error", err.Error()),
				)
			}
		}
	}
}

func (c *Collector) aggregate1m(ctx context.Context) error {
	if c.store == nil {
		return nil
	}

	now := time.Now().UnixMilli()
	from := now - aggregationInterval1m.Milliseconds() - time.Second.Milliseconds() // 1 extra second buffer.

	if err := c.store.Aggregate1m(ctx, from, now); err != nil {
		return fmt.Errorf("aggregate 1m: %w", err)
	}

	return nil
}

func (c *Collector) aggregate1h(ctx context.Context) error {
	if c.store == nil {
		return nil
	}

	now := time.Now().UnixMilli()
	from := now - aggregationInterval1h.Milliseconds() - bucketSize1m // 1 extra minute buffer.

	if err := c.store.Aggregate1h(ctx, from, now); err != nil {
		return fmt.Errorf("aggregate 1h: %w", err)
	}

	return nil
}

func (c *Collector) aggregate1d(ctx context.Context) error {
	if c.store == nil {
		return nil
	}

	now := time.Now().UnixMilli()
	from := now - aggregationInterval1d.Milliseconds() - bucketSize1h // 1 extra hour buffer.

	if err := c.store.Aggregate1d(ctx, from, now); err != nil {
		return fmt.Errorf("aggregate 1d: %w", err)
	}

	return nil
}

// cleanupWorker runs periodic cleanup of old metrics.
func (c *Collector) cleanupWorker(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stop:
			return
		case <-ticker.C:
			if c.store != nil {
				now := time.Now().UnixMilli()

				err := c.store.CleanupOldMetrics(ctx,
					now-retentionRaw.Milliseconds(),
					now-retention1m.Milliseconds(),
					now-retention5m.Milliseconds(),
					now-retention1h.Milliseconds(),
					now-retention1d.Milliseconds(),
				)
				if err != nil {
					c.logger.Error("Metrics cleanup failed", slog.String("error", err.Error()))
				}
			}
		}
	}
}

// Helper functions for atomic float64 operations.
func float64ToBits(f float64) uint64 {
	return math.Float64bits(f)
}

func float64FromBits(b uint64) float64 {
	return math.Float64frombits(b)
}
