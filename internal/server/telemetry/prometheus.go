package telemetry

import (
	"math"
	"sync"
	"time"

	"github.com/VictoriaMetrics/metrics"
)

// PrometheusMetrics provides enhanced Prometheus-compatible metrics.
// This extends the existing observer with additional metrics for
// comprehensive queue telemetry.
type PrometheusMetrics struct {
	// Rate gauges (calculated per second).
	sendRates    map[string]*metrics.Gauge
	receiveRates map[string]*metrics.Gauge
	deleteRates  map[string]*metrics.Gauge
	mu           sync.RWMutex

	// System-wide rate gauges.
	systemSendRate    *metrics.Gauge
	systemReceiveRate *metrics.Gauge
	systemDeleteRate  *metrics.Gauge

	// In-flight gauges.
	messagesInFlight       map[string]*metrics.Gauge
	systemMessagesInFlight *metrics.Gauge

	// Queue depth gauges.
	queueDepth         map[string]*metrics.Gauge
	messagesVisible    map[string]*metrics.Gauge
	messagesInvisible  map[string]*metrics.Gauge
	oldestMessageAge   map[string]*metrics.Gauge

	// Throughput gauges.
	throughputIn  map[string]*metrics.Gauge
	throughputOut map[string]*metrics.Gauge

	// Histogram metrics.
	processingDuration map[string]*metrics.Histogram
	dwellTime          map[string]*metrics.Histogram
	batchSize          map[string]*metrics.Histogram
	messageSize        map[string]*metrics.Histogram

	// Additional counters.
	messagesRedelivered map[string]*metrics.Counter
	messagesToDLQ       map[string]*metrics.Counter
}

// NewPrometheusMetrics creates a new PrometheusMetrics instance.
func NewPrometheusMetrics() *PrometheusMetrics {
	pm := &PrometheusMetrics{
		sendRates:           make(map[string]*metrics.Gauge),
		receiveRates:        make(map[string]*metrics.Gauge),
		deleteRates:         make(map[string]*metrics.Gauge),
		messagesInFlight:    make(map[string]*metrics.Gauge),
		queueDepth:          make(map[string]*metrics.Gauge),
		messagesVisible:     make(map[string]*metrics.Gauge),
		messagesInvisible:   make(map[string]*metrics.Gauge),
		oldestMessageAge:    make(map[string]*metrics.Gauge),
		throughputIn:        make(map[string]*metrics.Gauge),
		throughputOut:       make(map[string]*metrics.Gauge),
		processingDuration:  make(map[string]*metrics.Histogram),
		dwellTime:           make(map[string]*metrics.Histogram),
		batchSize:           make(map[string]*metrics.Histogram),
		messageSize:         make(map[string]*metrics.Histogram),
		messagesRedelivered: make(map[string]*metrics.Counter),
		messagesToDLQ:       make(map[string]*metrics.Counter),
	}

	// Initialize system-wide gauges.
	pm.systemSendRate = metrics.GetOrCreateGauge(`plainq_system_send_rate`, nil)
	pm.systemReceiveRate = metrics.GetOrCreateGauge(`plainq_system_receive_rate`, nil)
	pm.systemDeleteRate = metrics.GetOrCreateGauge(`plainq_system_delete_rate`, nil)
	pm.systemMessagesInFlight = metrics.GetOrCreateGauge(`plainq_system_messages_in_flight`, nil)

	return pm
}

// SetSendRate sets the send rate for a queue.
func (pm *PrometheusMetrics) SetSendRate(queueID string, rate float64) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	gauge, ok := pm.sendRates[queueID]
	if !ok {
		gauge = metrics.GetOrCreateGauge(`plainq_send_rate{queue="`+queueID+`"}`, nil)
		pm.sendRates[queueID] = gauge
	}
	gauge.Set(rate)
}

// SetReceiveRate sets the receive rate for a queue.
func (pm *PrometheusMetrics) SetReceiveRate(queueID string, rate float64) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	gauge, ok := pm.receiveRates[queueID]
	if !ok {
		gauge = metrics.GetOrCreateGauge(`plainq_receive_rate{queue="`+queueID+`"}`, nil)
		pm.receiveRates[queueID] = gauge
	}
	gauge.Set(rate)
}

// SetDeleteRate sets the delete rate for a queue.
func (pm *PrometheusMetrics) SetDeleteRate(queueID string, rate float64) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	gauge, ok := pm.deleteRates[queueID]
	if !ok {
		gauge = metrics.GetOrCreateGauge(`plainq_delete_rate{queue="`+queueID+`"}`, nil)
		pm.deleteRates[queueID] = gauge
	}
	gauge.Set(rate)
}

// SetSystemRates sets the system-wide rates.
func (pm *PrometheusMetrics) SetSystemRates(sendRate, receiveRate, deleteRate float64) {
	pm.systemSendRate.Set(sendRate)
	pm.systemReceiveRate.Set(receiveRate)
	pm.systemDeleteRate.Set(deleteRate)
}

// SetMessagesInFlight sets the in-flight message count for a queue.
func (pm *PrometheusMetrics) SetMessagesInFlight(queueID string, count int64) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	gauge, ok := pm.messagesInFlight[queueID]
	if !ok {
		gauge = metrics.GetOrCreateGauge(`plainq_messages_in_flight{queue="`+queueID+`"}`, nil)
		pm.messagesInFlight[queueID] = gauge
	}
	gauge.Set(float64(count))
}

// SetSystemMessagesInFlight sets the system-wide in-flight count.
func (pm *PrometheusMetrics) SetSystemMessagesInFlight(count int64) {
	pm.systemMessagesInFlight.Set(float64(count))
}

// SetQueueDepth sets the queue depth for a queue.
func (pm *PrometheusMetrics) SetQueueDepth(queueID string, depth int64) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	gauge, ok := pm.queueDepth[queueID]
	if !ok {
		gauge = metrics.GetOrCreateGauge(`plainq_queue_depth{queue="`+queueID+`"}`, nil)
		pm.queueDepth[queueID] = gauge
	}
	gauge.Set(float64(depth))
}

// SetMessagesVisible sets the visible message count for a queue.
func (pm *PrometheusMetrics) SetMessagesVisible(queueID string, count int64) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	gauge, ok := pm.messagesVisible[queueID]
	if !ok {
		gauge = metrics.GetOrCreateGauge(`plainq_messages_visible{queue="`+queueID+`"}`, nil)
		pm.messagesVisible[queueID] = gauge
	}
	gauge.Set(float64(count))
}

// SetMessagesInvisible sets the invisible message count for a queue.
func (pm *PrometheusMetrics) SetMessagesInvisible(queueID string, count int64) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	gauge, ok := pm.messagesInvisible[queueID]
	if !ok {
		gauge = metrics.GetOrCreateGauge(`plainq_messages_invisible{queue="`+queueID+`"}`, nil)
		pm.messagesInvisible[queueID] = gauge
	}
	gauge.Set(float64(count))
}

// SetOldestMessageAge sets the oldest message age for a queue.
func (pm *PrometheusMetrics) SetOldestMessageAge(queueID string, ageSeconds float64) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	gauge, ok := pm.oldestMessageAge[queueID]
	if !ok {
		gauge = metrics.GetOrCreateGauge(`plainq_oldest_message_age_seconds{queue="`+queueID+`"}`, nil)
		pm.oldestMessageAge[queueID] = gauge
	}
	gauge.Set(ageSeconds)
}

// SetThroughput sets the throughput for a queue.
func (pm *PrometheusMetrics) SetThroughput(queueID string, bytesIn, bytesOut float64) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	gaugeIn, ok := pm.throughputIn[queueID]
	if !ok {
		gaugeIn = metrics.GetOrCreateGauge(`plainq_throughput_bytes_per_second{queue="`+queueID+`",direction="in"}`, nil)
		pm.throughputIn[queueID] = gaugeIn
	}
	gaugeIn.Set(bytesIn)

	gaugeOut, ok := pm.throughputOut[queueID]
	if !ok {
		gaugeOut = metrics.GetOrCreateGauge(`plainq_throughput_bytes_per_second{queue="`+queueID+`",direction="out"}`, nil)
		pm.throughputOut[queueID] = gaugeOut
	}
	gaugeOut.Set(bytesOut)
}

// RecordProcessingDuration records a message processing duration.
func (pm *PrometheusMetrics) RecordProcessingDuration(queueID string, durationSeconds float64) {
	pm.mu.Lock()
	hist, ok := pm.processingDuration[queueID]
	if !ok {
		hist = metrics.GetOrCreateHistogram(`plainq_message_processing_duration_seconds{queue="` + queueID + `"}`)
		pm.processingDuration[queueID] = hist
	}
	pm.mu.Unlock()

	hist.Update(durationSeconds)
}

// RecordDwellTime records message dwell time (time from send to receive).
func (pm *PrometheusMetrics) RecordDwellTime(queueID string, durationSeconds float64) {
	pm.mu.Lock()
	hist, ok := pm.dwellTime[queueID]
	if !ok {
		hist = metrics.GetOrCreateHistogram(`plainq_message_dwell_time_seconds{queue="` + queueID + `"}`)
		pm.dwellTime[queueID] = hist
	}
	pm.mu.Unlock()

	hist.Update(durationSeconds)
}

// RecordBatchSize records a batch operation size.
func (pm *PrometheusMetrics) RecordBatchSize(queueID string, size int, operation string) {
	pm.mu.Lock()
	key := queueID + "_" + operation
	hist, ok := pm.batchSize[key]
	if !ok {
		hist = metrics.GetOrCreateHistogram(`plainq_batch_size{queue="` + queueID + `",operation="` + operation + `"}`)
		pm.batchSize[key] = hist
	}
	pm.mu.Unlock()

	hist.Update(float64(size))
}

// RecordMessageSize records a message body size.
func (pm *PrometheusMetrics) RecordMessageSize(queueID string, sizeBytes int) {
	pm.mu.Lock()
	hist, ok := pm.messageSize[queueID]
	if !ok {
		hist = metrics.GetOrCreateHistogram(`plainq_message_size_bytes{queue="` + queueID + `"}`)
		pm.messageSize[queueID] = hist
	}
	pm.mu.Unlock()

	hist.Update(float64(sizeBytes))
}

// IncrementRedelivered increments the redelivery counter.
func (pm *PrometheusMetrics) IncrementRedelivered(queueID string) {
	pm.mu.Lock()
	counter, ok := pm.messagesRedelivered[queueID]
	if !ok {
		counter = metrics.GetOrCreateCounter(`plainq_messages_redelivered_total{queue="` + queueID + `"}`)
		pm.messagesRedelivered[queueID] = counter
	}
	pm.mu.Unlock()

	counter.Inc()
}

// IncrementDLQ increments the DLQ counter.
func (pm *PrometheusMetrics) IncrementDLQ(queueID string, sourceQueue string) {
	pm.mu.Lock()
	key := queueID + "_" + sourceQueue
	counter, ok := pm.messagesToDLQ[key]
	if !ok {
		counter = metrics.GetOrCreateCounter(`plainq_messages_to_dlq_total{queue="` + queueID + `",source_queue="` + sourceQueue + `"}`)
		pm.messagesToDLQ[key] = counter
	}
	pm.mu.Unlock()

	counter.Inc()
}

// EnhancedObserver extends the base Observer with Prometheus metrics support.
type EnhancedObserver struct {
	*MetricsObserver
	prom *PrometheusMetrics
}

// NewEnhancedObserver creates an EnhancedObserver with Prometheus metrics.
func NewEnhancedObserver() *EnhancedObserver {
	return &EnhancedObserver{
		MetricsObserver: NewObserver(),
		prom:            NewPrometheusMetrics(),
	}
}

// Prometheus returns the Prometheus metrics instance.
func (e *EnhancedObserver) Prometheus() *PrometheusMetrics {
	return e.prom
}

// observedMetricsEnhanced is the full list of observed metrics including new ones.
var observedMetricsEnhanced = map[string]struct{}{
	// Original metrics.
	"queues_exist":              {},
	"message_in_queue_duration": {},
	"messages_sent_total":       {},
	"messages_sent_bytes_total": {},
	"messages_received_total":   {},
	"messages_deleted_total":    {},
	"messages_dropped_total":    {},
	"empty_receives_total":      {},
	"gc_schedules_total":        {},
	"gc_duration":               {},

	// New rate metrics.
	"plainq_send_rate":                       {},
	"plainq_receive_rate":                    {},
	"plainq_delete_rate":                     {},
	"plainq_system_send_rate":                {},
	"plainq_system_receive_rate":             {},
	"plainq_system_delete_rate":              {},

	// New gauge metrics.
	"plainq_messages_in_flight":              {},
	"plainq_system_messages_in_flight":       {},
	"plainq_queue_depth":                     {},
	"plainq_messages_visible":                {},
	"plainq_messages_invisible":              {},
	"plainq_oldest_message_age_seconds":      {},
	"plainq_throughput_bytes_per_second":     {},

	// New histogram metrics.
	"plainq_message_processing_duration_seconds": {},
	"plainq_message_dwell_time_seconds":          {},
	"plainq_batch_size":                          {},
	"plainq_message_size_bytes":                  {},

	// New counter metrics.
	"plainq_messages_redelivered_total":      {},
	"plainq_messages_to_dlq_total":           {},
}

// IsObservableEnhanced checks if a metric is observed (including new metrics).
func IsObservableEnhanced(metric string) bool {
	_, ok := observedMetricsEnhanced[metric]
	return ok
}

// EnhancedCounter wraps Counter with rate tracking capability.
type EnhancedCounter struct {
	Counter
	lastValue    uint64
	lastTime     time.Time
	currentRate  float64
	rateMu       sync.Mutex
}

// NewEnhancedCounter wraps a Counter.
func NewEnhancedCounter(c Counter) *EnhancedCounter {
	return &EnhancedCounter{
		Counter:  c,
		lastTime: time.Now(),
	}
}

// CalculateRate calculates and returns the current rate per second.
func (ec *EnhancedCounter) CalculateRate() float64 {
	ec.rateMu.Lock()
	defer ec.rateMu.Unlock()

	currentValue := ec.Counter.Get()
	currentTime := time.Now()

	elapsed := currentTime.Sub(ec.lastTime).Seconds()
	if elapsed > 0 {
		delta := currentValue - ec.lastValue
		ec.currentRate = float64(delta) / elapsed
	}

	ec.lastValue = currentValue
	ec.lastTime = currentTime

	return ec.currentRate
}

// GetRate returns the last calculated rate.
func (ec *EnhancedCounter) GetRate() float64 {
	ec.rateMu.Lock()
	defer ec.rateMu.Unlock()
	return ec.currentRate
}

// SafeFloat64ToBits converts float64 to uint64 bits safely.
func SafeFloat64ToBits(f float64) uint64 {
	return math.Float64bits(f)
}

// SafeFloat64FromBits converts uint64 bits to float64 safely.
func SafeFloat64FromBits(b uint64) float64 {
	return math.Float64frombits(b)
}
