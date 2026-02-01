// Package collector provides a comprehensive metrics collection system
// for tracking queue operations with rate calculations, in-flight tracking,
// and time-series storage.
package collector

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/plainq/servekit/logkit"
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
)

// MetricType represents the type of metric.
type MetricType string

const (
	MetricTypeCounter   MetricType = "counter"
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeHistogram MetricType = "histogram"
)

// Metric names constants.
const (
	// Rate metrics (calculated per second).
	MetricSendRate    = "plainq_send_rate"
	MetricReceiveRate = "plainq_receive_rate"
	MetricDeleteRate  = "plainq_delete_rate"

	// Counter metrics (cumulative).
	MetricMessagesSentTotal     = "plainq_messages_sent_total"
	MetricMessagesReceivedTotal = "plainq_messages_received_total"
	MetricMessagesDeletedTotal  = "plainq_messages_deleted_total"
	MetricMessagesDroppedTotal  = "plainq_messages_dropped_total"
	MetricEmptyReceivesTotal    = "plainq_empty_receives_total"
	MetricMessagesRedelivered   = "plainq_messages_redelivered_total"
	MetricMessagesToDLQ         = "plainq_messages_to_dlq_total"
	MetricBytesSentTotal        = "plainq_bytes_sent_total"
	MetricBytesReceivedTotal    = "plainq_bytes_received_total"

	// Gauge metrics (current value).
	MetricMessagesInFlight      = "plainq_messages_in_flight"
	MetricQueueDepth            = "plainq_queue_depth"
	MetricMessagesVisible       = "plainq_messages_visible"
	MetricMessagesInvisible     = "plainq_messages_invisible"
	MetricOldestMessageAge      = "plainq_oldest_message_age_seconds"
	MetricQueuesExist           = "plainq_queues_exist"
	MetricThroughputBytesPerSec = "plainq_throughput_bytes_per_second"

	// Histogram metrics (distribution).
	MetricMessageProcessingDuration = "plainq_message_processing_duration_seconds"
	MetricMessageDwellTime          = "plainq_message_dwell_time_seconds"
	MetricMessageInQueueDuration    = "plainq_message_in_queue_duration_seconds"
	MetricBatchSize                 = "plainq_batch_size"
	MetricMessageSizeBytes          = "plainq_message_size_bytes"
)

// QueueMetrics holds metrics for a specific queue.
type QueueMetrics struct {
	// Counters (atomic for thread safety).
	messagesSent     atomic.Uint64
	messagesReceived atomic.Uint64
	messagesDeleted  atomic.Uint64
	messagesDropped  atomic.Uint64
	emptyReceives    atomic.Uint64
	messagesRedelivered atomic.Uint64
	messagesToDLQ    atomic.Uint64
	bytesSent        atomic.Uint64
	bytesReceived    atomic.Uint64

	// In-flight tracking.
	messagesInFlight atomic.Int64

	// Previous values for rate calculation.
	prevSent     uint64
	prevReceived uint64
	prevDeleted  uint64
	prevBytes    uint64

	// Calculated rates.
	sendRate    atomic.Uint64 // Stored as float64 bits
	receiveRate atomic.Uint64
	deleteRate  atomic.Uint64

	// Histogram accumulators (simplified - use summary stats).
	processingDurations []float64
	dwellTimes          []float64
	batchSizes          []int
	messageSizes        []int
	histogramMu         sync.Mutex
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

	// System-wide metrics.
	system SystemMetrics

	// Configuration.
	collectionInterval time.Duration
	snapshotInterval   time.Duration

	// Control.
	stop     chan struct{}
	stopOnce sync.Once
}

// Store interface for persisting metrics.
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
	Timestamp        int64   `json:"timestamp"`
	QueueDepth       int64   `json:"queueDepth"`
	MessagesVisible  int64   `json:"messagesVisible"`
	MessagesInvisible int64  `json:"messagesInvisible"`
	OldestMessageAge float64 `json:"oldestMessageAge"`
	AvgMessageAge    float64 `json:"avgMessageAge"`
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
		processingDurations: make([]float64, 0, 1000),
		dwellTimes:          make([]float64, 0, 1000),
		batchSizes:          make([]int, 0, 100),
		messageSizes:        make([]int, 0, 1000),
	}
	c.queueMetrics[queueID] = m
	return m
}

// RecordSend records a send operation.
func (c *Collector) RecordSend(queueID string, count uint64, totalBytes uint64) {
	m := c.getOrCreateQueueMetrics(queueID)
	m.messagesSent.Add(count)
	m.bytesSent.Add(totalBytes)
	c.system.totalSent.Add(count)
}

// RecordReceive records a receive operation.
func (c *Collector) RecordReceive(queueID string, count uint64, isEmpty bool) {
	m := c.getOrCreateQueueMetrics(queueID)
	m.messagesReceived.Add(count)
	m.messagesInFlight.Add(int64(count))
	c.system.totalReceived.Add(count)

	if isEmpty {
		m.emptyReceives.Add(1)
	}

	// Update in-flight count in store.
	if c.store != nil {
		_ = c.store.UpdateInFlightCount(context.Background(), queueID, m.messagesInFlight.Load())
	}
}

// RecordDelete records a delete operation.
func (c *Collector) RecordDelete(queueID string, count uint64, dwellTimeSeconds float64) {
	m := c.getOrCreateQueueMetrics(queueID)
	m.messagesDeleted.Add(count)
	m.messagesInFlight.Add(-int64(count))
	c.system.totalDeleted.Add(count)

	// Record dwell time.
	if dwellTimeSeconds > 0 {
		m.histogramMu.Lock()
		m.dwellTimes = append(m.dwellTimes, dwellTimeSeconds)
		m.histogramMu.Unlock()
	}

	// Update in-flight count in store.
	if c.store != nil {
		_ = c.store.UpdateInFlightCount(context.Background(), queueID, m.messagesInFlight.Load())
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
func (c *Collector) RecordBatchSize(queueID string, size int, operation string) {
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

// GetRates returns current rates for a queue.
func (c *Collector) GetRates(queueID string) (sendRate, receiveRate, deleteRate float64) {
	m := c.getOrCreateQueueMetrics(queueID)
	return float64FromBits(m.sendRate.Load()),
		float64FromBits(m.receiveRate.Load()),
		float64FromBits(m.deleteRate.Load())
}

// GetSystemRates returns system-wide rates.
func (c *Collector) GetSystemRates() (sendRate, receiveRate, deleteRate float64) {
	return float64FromBits(c.system.systemSendRate.Load()),
		float64FromBits(c.system.systemReceiveRate.Load()),
		float64FromBits(c.system.systemDeleteRate.Load())
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
			c.calculateRates()
		}
	}
}

// calculateRates calculates rates for all queues.
func (c *Collector) calculateRates() {
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

		// Persist rates to store.
		if c.store != nil {
			_ = c.store.SaveRateSnapshot(context.Background(), now, queueID, MetricSendRate, sendRate, 1)
			_ = c.store.SaveRateSnapshot(context.Background(), now, queueID, MetricReceiveRate, receiveRate, 1)
			_ = c.store.SaveRateSnapshot(context.Background(), now, queueID, MetricDeleteRate, deleteRate, 1)

			// Also save raw metric values.
			_ = c.store.SaveRawMetric(context.Background(), now, queueID, MetricMessagesSentTotal, float64(currentSent), "")
			_ = c.store.SaveRawMetric(context.Background(), now, queueID, MetricMessagesReceivedTotal, float64(currentReceived), "")
			_ = c.store.SaveRawMetric(context.Background(), now, queueID, MetricMessagesDeletedTotal, float64(currentDeleted), "")
			_ = c.store.SaveRawMetric(context.Background(), now, queueID, MetricMessagesInFlight, float64(m.messagesInFlight.Load()), "")
		}
	}

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

	// Persist system-wide metrics.
	if c.store != nil {
		_ = c.store.SaveRateSnapshot(context.Background(), now, "", MetricSendRate, systemSendRate, 1)
		_ = c.store.SaveRateSnapshot(context.Background(), now, "", MetricReceiveRate, systemReceiveRate, 1)
		_ = c.store.SaveRateSnapshot(context.Background(), now, "", MetricDeleteRate, systemDeleteRate, 1)
		_ = c.store.SaveRawMetric(context.Background(), now, "", MetricQueuesExist, float64(c.system.queuesExist.Load()), "")
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
	from := now - int64(aggregationInterval1m.Milliseconds()) - 1000 // 1 extra second buffer
	return c.store.Aggregate1m(ctx, from, now)
}

func (c *Collector) aggregate1h(ctx context.Context) error {
	if c.store == nil {
		return nil
	}
	now := time.Now().UnixMilli()
	from := now - int64(aggregationInterval1h.Milliseconds()) - 60000 // 1 extra minute buffer
	return c.store.Aggregate1h(ctx, from, now)
}

func (c *Collector) aggregate1d(ctx context.Context) error {
	if c.store == nil {
		return nil
	}
	now := time.Now().UnixMilli()
	from := now - int64(aggregationInterval1d.Milliseconds()) - 3600000 // 1 extra hour buffer
	return c.store.Aggregate1d(ctx, from, now)
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
					now-int64(retentionRaw.Milliseconds()),
					now-int64(retention1m.Milliseconds()),
					now-int64(retention5m.Milliseconds()),
					now-int64(retention1h.Milliseconds()),
					now-int64(retention1d.Milliseconds()),
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
	return *(*uint64)((*[8]byte)((*[8]byte)(&f))[:])
}

func float64FromBits(b uint64) float64 {
	return *(*float64)((*[8]byte)((*[8]byte)(&b))[:])
}
