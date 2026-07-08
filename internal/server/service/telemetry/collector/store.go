package collector

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/marsolab/servekit/dbkit/litekit"
)

// errScanRow is a common error format string for row scanning failures.
const errScanRow = "scan row: %w"

// SQLiteStore implements the Store interface using SQLite.
type SQLiteStore struct {
	db *litekit.Conn
}

// NewSQLiteStore creates a new SQLite-backed metrics store.
func NewSQLiteStore(db *litekit.Conn) *SQLiteStore {
	return &SQLiteStore{db: db}
}

// SaveRawMetric saves a raw metric data point.
//
//nolint:revive // argument-limit: signature matches Store interface
func (s *SQLiteStore) SaveRawMetric(
	ctx context.Context, timestamp int64, queueID, metricName string, value float64, labels string,
) error {
	query := `INSERT INTO metrics_raw (timestamp, queue_id, metric_name, metric_value, labels) VALUES (?, ?, ?, ?, ?)`
	if _, err := s.db.ExecContext(ctx, query, timestamp, queueID, metricName, value, labels); err != nil {
		return fmt.Errorf("save raw metric: %w", err)
	}

	return nil
}

// SaveRateSnapshot saves rate calculation results.
//
//nolint:revive // argument-limit: signature matches Store interface
func (s *SQLiteStore) SaveRateSnapshot(
	ctx context.Context, timestamp int64, queueID, metricName string, ratePerSecond float64, windowSeconds int,
) error {
	query := `INSERT INTO rate_snapshots (timestamp, queue_id, metric_name, rate_per_second, window_seconds) VALUES (?, ?, ?, ?, ?)`
	if _, err := s.db.ExecContext(ctx, query, timestamp, queueID, metricName, ratePerSecond, windowSeconds); err != nil {
		return fmt.Errorf("save rate snapshot: %w", err)
	}

	return nil
}

// SaveQueueStats saves queue statistics snapshot.
func (s *SQLiteStore) SaveQueueStats( //nolint:revive // argument-limit: signature matches Store interface
	ctx context.Context, timestamp int64, queueID string,
	depth, visible, invisible int64, oldestAge, avgAge float64,
) error {
	query := `INSERT INTO queue_stats_snapshot
		(timestamp, queue_id, queue_depth, messages_visible, messages_invisible,
		oldest_message_age_seconds, avg_message_age_seconds)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	if _, err := s.db.ExecContext(ctx, query, timestamp, queueID, depth, visible, invisible, oldestAge, avgAge); err != nil {
		return fmt.Errorf("save queue stats: %w", err)
	}

	return nil
}

// UpdateInFlightCount updates the in-flight message count for a queue.
func (s *SQLiteStore) UpdateInFlightCount(ctx context.Context, queueID string, count int64) error {
	query := `INSERT INTO messages_in_flight (queue_id, count, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(queue_id) DO UPDATE SET count = excluded.count, updated_at = excluded.updated_at`
	if _, err := s.db.ExecContext(ctx, query, queueID, count, time.Now().UnixMilli()); err != nil {
		return fmt.Errorf("update in-flight count: %w", err)
	}

	return nil
}

// Aggregate1m aggregates raw metrics into 1-minute buckets.
func (s *SQLiteStore) Aggregate1m(ctx context.Context, fromTimestamp, toTimestamp int64) error {
	// Calculate bucket boundaries (1-minute = 60000ms).
	bucketSize := int64(bucketSize1m)

	query := `
		INSERT OR REPLACE INTO metrics_1m (bucket_start, queue_id, metric_name, min_value, max_value, avg_value, sum_value, count, labels)
		SELECT
			(timestamp / ?) * ? as bucket_start,
			queue_id,
			metric_name,
			MIN(metric_value) as min_value,
			MAX(metric_value) as max_value,
			AVG(metric_value) as avg_value,
			SUM(metric_value) as sum_value,
			COUNT(*) as count,
			labels
		FROM metrics_raw
		WHERE timestamp >= ? AND timestamp < ?
		GROUP BY bucket_start, queue_id, metric_name, labels
	`
	if _, err := s.db.ExecContext(ctx, query, bucketSize, bucketSize, fromTimestamp, toTimestamp); err != nil {
		return fmt.Errorf("aggregate 1m: %w", err)
	}

	return nil
}

// Aggregate1h aggregates 1-minute metrics into 1-hour buckets.
func (s *SQLiteStore) Aggregate1h(ctx context.Context, fromTimestamp, toTimestamp int64) error {
	bucketSize := int64(bucketSize1h)
	minuteBucketSize := int64(bucketSize1m)

	query := `
		INSERT OR REPLACE INTO metrics_1h (bucket_start, queue_id, metric_name, min_value, max_value, avg_value, sum_value, count, labels)
		SELECT
			(bucket_start / ?) * ? as hour_bucket,
			queue_id,
			metric_name,
			MIN(min_value) as min_value,
			MAX(max_value) as max_value,
			SUM(avg_value * count) / SUM(count) as avg_value,
			SUM(sum_value) as sum_value,
			SUM(count) as count,
			labels
		FROM metrics_1m
		WHERE bucket_start >= (? / ?) * ? AND bucket_start < (? / ?) * ?
		GROUP BY hour_bucket, queue_id, metric_name, labels
	`
	if _, err := s.db.ExecContext(ctx, query,
		bucketSize, bucketSize,
		fromTimestamp, minuteBucketSize, minuteBucketSize,
		toTimestamp, minuteBucketSize, minuteBucketSize); err != nil {
		return fmt.Errorf("aggregate 1h: %w", err)
	}

	return nil
}

// Aggregate1d aggregates 1-hour metrics into 1-day buckets.
func (s *SQLiteStore) Aggregate1d(ctx context.Context, fromTimestamp, toTimestamp int64) error {
	bucketSize := int64(bucketSize1d)
	hourBucketSize := int64(bucketSize1h)

	query := `
		INSERT OR REPLACE INTO metrics_1d (bucket_start, queue_id, metric_name, min_value, max_value, avg_value, sum_value, count, labels)
		SELECT
			(bucket_start / ?) * ? as day_bucket,
			queue_id,
			metric_name,
			MIN(min_value) as min_value,
			MAX(max_value) as max_value,
			SUM(avg_value * count) / SUM(count) as avg_value,
			SUM(sum_value) as sum_value,
			SUM(count) as count,
			labels
		FROM metrics_1h
		WHERE bucket_start >= (? / ?) * ? AND bucket_start < (? / ?) * ?
		GROUP BY day_bucket, queue_id, metric_name, labels
	`
	if _, err := s.db.ExecContext(ctx, query,
		bucketSize, bucketSize,
		fromTimestamp, hourBucketSize, hourBucketSize,
		toTimestamp, hourBucketSize, hourBucketSize); err != nil {
		return fmt.Errorf("aggregate 1d: %w", err)
	}

	return nil
}

// CleanupOldMetrics removes metrics older than retention period.
//
//nolint:revive // argument-limit: signature matches Store interface
func (s *SQLiteStore) CleanupOldMetrics(ctx context.Context, rawBefore, m1Before, m5Before, h1Before, d1Before int64) error {
	queries := []string{
		`DELETE FROM metrics_raw WHERE timestamp < ?`,
		`DELETE FROM metrics_1m WHERE bucket_start < ?`,
		`DELETE FROM metrics_5m WHERE timestamp < ?`,
		`DELETE FROM metrics_1h WHERE bucket_start < ?`,
		`DELETE FROM metrics_1d WHERE bucket_start < ?`,
		`DELETE FROM rate_snapshots WHERE timestamp < ?`,
		`DELETE FROM queue_stats_snapshot WHERE timestamp < ?`,
	}

	thresholds := []int64{rawBefore, m1Before, m5Before, h1Before, d1Before, rawBefore, rawBefore}

	for i, query := range queries {
		if _, err := s.db.ExecContext(ctx, query, thresholds[i]); err != nil {
			return fmt.Errorf("cleanup query %d: %w", i, err)
		}
	}

	return nil
}

// GetMetrics retrieves metrics for a time range.
// resolution: "raw", "1m", "5m", "1h", "1d".
// When queueID is empty, returns system-wide metrics (queue_id = ”).
//
//nolint:revive,cyclop // argument-limit and cyclomatic complexity stem from the per-resolution query lookup.
func (s *SQLiteStore) GetMetrics(ctx context.Context, metricName, queueID string, from, to int64, resolution string) ([]DataPoint, error) {
	var (
		query string
		args  []any
	)

	// Always filter by queue_id - empty string means system-wide metrics.
	switch resolution {
	case "raw":
		//nolint:dupword // intentional column reuse to fill the unified DataPoint shape.
		query = `SELECT timestamp, metric_value, metric_value, metric_value, metric_value, metric_value, 1
			FROM metrics_raw WHERE metric_name = ? AND queue_id = ? AND timestamp >= ? AND timestamp <= ?
			ORDER BY timestamp ASC`
		args = []any{metricName, queueID, from, to}

	case "1m":
		query = `SELECT bucket_start, avg_value, min_value, max_value, avg_value, sum_value, count
			FROM metrics_1m WHERE metric_name = ? AND queue_id = ? AND bucket_start >= ? AND bucket_start <= ?
			ORDER BY bucket_start ASC`
		args = []any{metricName, queueID, from, to}

	case "5m":
		//nolint:dupword // intentional column reuse to fill the unified DataPoint shape.
		query = `SELECT timestamp, metric_value_avg, metric_value_min, metric_value_max, metric_value_avg, metric_value_avg, 1
			FROM metrics_5m WHERE metric_name = ? AND queue_id = ? AND timestamp >= ? AND timestamp <= ?
			ORDER BY timestamp ASC`
		args = []any{metricName, queueID, from, to}

	case "1h":
		query = `SELECT bucket_start, avg_value, min_value, max_value, avg_value, sum_value, count
			FROM metrics_1h WHERE metric_name = ? AND queue_id = ? AND bucket_start >= ? AND bucket_start <= ?
			ORDER BY bucket_start ASC`
		args = []any{metricName, queueID, from, to}

	case "1d":
		query = `SELECT bucket_start, avg_value, min_value, max_value, avg_value, sum_value, count
			FROM metrics_1d WHERE metric_name = ? AND queue_id = ? AND bucket_start >= ? AND bucket_start <= ?
			ORDER BY bucket_start ASC`
		args = []any{metricName, queueID, from, to}

	default:
		return nil, fmt.Errorf("unknown resolution: %s", resolution)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query metrics: %w", err)
	}
	defer rows.Close()

	var points []DataPoint

	for rows.Next() {
		var p DataPoint
		if err := rows.Scan(&p.Timestamp, &p.Value, &p.Min, &p.Max, &p.Avg, &p.Sum, &p.Count); err != nil {
			return nil, fmt.Errorf(errScanRow, err)
		}

		points = append(points, p)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate metrics: %w", err)
	}

	return points, nil
}

// GetLatestRates retrieves the latest rate values.
func (s *SQLiteStore) GetLatestRates(ctx context.Context, queueID string) (map[string]float64, error) {
	query := `
		SELECT metric_name, rate_per_second
		FROM rate_snapshots
		WHERE queue_id = ? AND timestamp = (
			SELECT MAX(timestamp) FROM rate_snapshots WHERE queue_id = ?
		)
	`

	rows, err := s.db.QueryContext(ctx, query, queueID, queueID)
	if err != nil {
		return nil, fmt.Errorf("query rates: %w", err)
	}
	defer rows.Close()

	rates := make(map[string]float64)

	for rows.Next() {
		var (
			name string
			rate float64
		)

		if err := rows.Scan(&name, &rate); err != nil {
			return nil, fmt.Errorf(errScanRow, err)
		}

		rates[name] = rate
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rates: %w", err)
	}

	return rates, nil
}

// GetQueueStats retrieves queue statistics.
func (s *SQLiteStore) GetQueueStats(ctx context.Context, queueID string, from, to int64) ([]QueueStatsPoint, error) {
	query := `
		SELECT timestamp, queue_depth, messages_visible, messages_invisible,
			oldest_message_age_seconds, avg_message_age_seconds
		FROM queue_stats_snapshot
		WHERE queue_id = ? AND timestamp >= ? AND timestamp <= ?
		ORDER BY timestamp ASC
	`

	rows, err := s.db.QueryContext(ctx, query, queueID, from, to)
	if err != nil {
		return nil, fmt.Errorf("query queue stats: %w", err)
	}
	defer rows.Close()

	var points []QueueStatsPoint

	for rows.Next() {
		var p QueueStatsPoint
		if err := rows.Scan(
			&p.Timestamp, &p.QueueDepth, &p.MessagesVisible, &p.MessagesInvisible,
			&p.OldestMessageAge, &p.AvgMessageAge,
		); err != nil {
			return nil, fmt.Errorf(errScanRow, err)
		}

		points = append(points, p)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate queue stats: %w", err)
	}

	return points, nil
}

// GetInFlightCounts retrieves in-flight counts for all queues.
func (s *SQLiteStore) GetInFlightCounts(ctx context.Context) (map[string]int64, error) {
	query := `SELECT queue_id, count FROM messages_in_flight`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query in-flight: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int64)

	for rows.Next() {
		var (
			queueID string
			count   int64
		)

		if err := rows.Scan(&queueID, &count); err != nil {
			return nil, fmt.Errorf(errScanRow, err)
		}

		counts[queueID] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate in-flight counts: %w", err)
	}

	return counts, nil
}

// GetRateHistory retrieves rate history for a metric.
// When queueID is empty, returns system-wide metrics (queue_id = ”).
//
//nolint:revive // argument-limit: all params are needed for query filtering
func (s *SQLiteStore) GetRateHistory(ctx context.Context, metricName, queueID string, from, to int64) ([]DataPoint, error) {
	// Always filter by queue_id - empty string means system-wide metrics.
	//nolint:dupword // intentional column reuse to fill the unified DataPoint shape.
	query := `
		SELECT timestamp, rate_per_second, rate_per_second, rate_per_second, rate_per_second, rate_per_second, 1
		FROM rate_snapshots
		WHERE metric_name = ? AND queue_id = ? AND timestamp >= ? AND timestamp <= ?
		ORDER BY timestamp ASC
	`
	args := []any{metricName, queueID, from, to}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query rate history: %w", err)
	}
	defer rows.Close()

	var points []DataPoint

	for rows.Next() {
		var p DataPoint
		if err := rows.Scan(&p.Timestamp, &p.Value, &p.Min, &p.Max, &p.Avg, &p.Sum, &p.Count); err != nil {
			return nil, fmt.Errorf(errScanRow, err)
		}

		points = append(points, p)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rate history: %w", err)
	}

	return points, nil
}

// GetSystemMetrics retrieves system-wide metrics (queue_id = ”).
//
//nolint:revive // argument-limit: all params are needed for query filtering
func (s *SQLiteStore) GetSystemMetrics(ctx context.Context, metricName string, from, to int64, resolution string) ([]DataPoint, error) {
	return s.GetMetrics(ctx, metricName, "", from, to, resolution)
}

// GetAllQueuesMetrics retrieves metrics aggregated across all queues.
func (s *SQLiteStore) GetAllQueuesMetrics(ctx context.Context, metricName string, from, to int64) ([]DataPoint, error) {
	query := `
		SELECT timestamp, SUM(metric_value) as value
		FROM metrics_raw
		WHERE metric_name = ? AND timestamp >= ? AND timestamp <= ? AND queue_id != ''
		GROUP BY timestamp
		ORDER BY timestamp ASC
	`

	rows, err := s.db.QueryContext(ctx, query, metricName, from, to)
	if err != nil {
		return nil, fmt.Errorf("query all queues metrics: %w", err)
	}
	defer rows.Close()

	var points []DataPoint

	for rows.Next() {
		var p DataPoint
		if err := rows.Scan(&p.Timestamp, &p.Value); err != nil {
			return nil, fmt.Errorf(errScanRow, err)
		}

		points = append(points, p)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate all queues metrics: %w", err)
	}

	return points, nil
}

// LatestMetric holds the most recent value and timestamp for a metric.
type LatestMetric struct {
	Value     float64
	Timestamp int64
}

// GetLatestMetricValue retrieves the most recent value for a metric.
func (s *SQLiteStore) GetLatestMetricValue(ctx context.Context, metricName, queueID string) (LatestMetric, error) {
	query := `
		SELECT metric_value, timestamp
		FROM metrics_raw
		WHERE metric_name = ? AND queue_id = ?
		ORDER BY timestamp DESC
		LIMIT 1
	`

	var m LatestMetric

	err := s.db.QueryRowContext(ctx, query, metricName, queueID).Scan(&m.Value, &m.Timestamp)
	if err == sql.ErrNoRows {
		return LatestMetric{}, nil
	}

	if err != nil {
		return LatestMetric{}, fmt.Errorf("query latest metric: %w", err)
	}

	return m, nil
}

// GetMetricsSummary retrieves a summary of metrics for a time range.
func (s *SQLiteStore) GetMetricsSummary(ctx context.Context, queueID string, from, to int64) (*MetricsSummary, error) {
	summary := &MetricsSummary{
		QueueID: queueID,
		From:    from,
		To:      to,
	}

	// Get total sent.
	query := `SELECT COALESCE(MAX(metric_value) - MIN(metric_value), 0)
		FROM metrics_raw
		WHERE metric_name = ? AND queue_id = ? AND timestamp >= ? AND timestamp <= ?`
	//nolint:errcheck // best-effort metrics summary
	_ = s.db.QueryRowContext(ctx, query, MetricMessagesSentTotal, queueID, from, to).Scan(&summary.TotalSent)
	//nolint:errcheck // best-effort metrics summary
	_ = s.db.QueryRowContext(ctx, query, MetricMessagesReceivedTotal, queueID, from, to).Scan(&summary.TotalReceived)
	//nolint:errcheck // best-effort metrics summary
	_ = s.db.QueryRowContext(ctx, query, MetricMessagesDeletedTotal, queueID, from, to).Scan(&summary.TotalDeleted)

	// Get average rates.
	rateQuery := `SELECT COALESCE(AVG(rate_per_second), 0)
		FROM rate_snapshots
		WHERE metric_name = ? AND queue_id = ? AND timestamp >= ? AND timestamp <= ?`
	//nolint:errcheck // best-effort metrics summary
	_ = s.db.QueryRowContext(ctx, rateQuery, MetricSendRate, queueID, from, to).Scan(&summary.AvgSendRate)
	//nolint:errcheck // best-effort metrics summary
	_ = s.db.QueryRowContext(ctx, rateQuery, MetricReceiveRate, queueID, from, to).Scan(&summary.AvgReceiveRate)
	//nolint:errcheck // best-effort metrics summary
	_ = s.db.QueryRowContext(ctx, rateQuery, MetricDeleteRate, queueID, from, to).Scan(&summary.AvgDeleteRate)

	// Get max rates.
	maxRateQuery := `SELECT COALESCE(MAX(rate_per_second), 0)
		FROM rate_snapshots
		WHERE metric_name = ? AND queue_id = ? AND timestamp >= ? AND timestamp <= ?`
	//nolint:errcheck // best-effort metrics summary
	_ = s.db.QueryRowContext(ctx, maxRateQuery, MetricSendRate, queueID, from, to).Scan(&summary.MaxSendRate)
	//nolint:errcheck // best-effort metrics summary
	_ = s.db.QueryRowContext(ctx, maxRateQuery, MetricReceiveRate, queueID, from, to).Scan(&summary.MaxReceiveRate)
	//nolint:errcheck // best-effort metrics summary
	_ = s.db.QueryRowContext(ctx, maxRateQuery, MetricDeleteRate, queueID, from, to).Scan(&summary.MaxDeleteRate)

	// Get current in-flight.
	inFlightQuery := `SELECT COALESCE(count, 0) FROM messages_in_flight WHERE queue_id = ?`
	_ = s.db.QueryRowContext(ctx, inFlightQuery, queueID).Scan(&summary.CurrentInFlight) //nolint:errcheck // best-effort metrics summary

	return summary, nil
}

// MetricsSummary contains aggregated metrics summary.
type MetricsSummary struct {
	QueueID         string  `json:"queueId"`
	From            int64   `json:"from"`
	To              int64   `json:"to"`
	TotalSent       int64   `json:"totalSent"`
	TotalReceived   int64   `json:"totalReceived"`
	TotalDeleted    int64   `json:"totalDeleted"`
	AvgSendRate     float64 `json:"avgSendRate"`
	AvgReceiveRate  float64 `json:"avgReceiveRate"`
	AvgDeleteRate   float64 `json:"avgDeleteRate"`
	MaxSendRate     float64 `json:"maxSendRate"`
	MaxReceiveRate  float64 `json:"maxReceiveRate"`
	MaxDeleteRate   float64 `json:"maxDeleteRate"`
	CurrentInFlight int64   `json:"currentInFlight"`
}

// TopicMetricsSummary contains aggregated topic metrics summary.
type TopicMetricsSummary struct {
	TopicID         string  `json:"topicId"`
	From            int64   `json:"from"`
	To              int64   `json:"to"`
	TotalPublished  int64   `json:"totalPublished"`
	TotalDeliveries int64   `json:"totalDeliveries"`
	AvgPublishRate  float64 `json:"avgPublishRate"`
	AvgDeliveryRate float64 `json:"avgDeliveryRate"`
	MaxPublishRate  float64 `json:"maxPublishRate"`
	MaxDeliveryRate float64 `json:"maxDeliveryRate"`
	Subscriptions   *int64  `json:"subscriptions"`
}

// GetTopicMetricsSummary retrieves a summary of topic metrics for a time range.
func (s *SQLiteStore) GetTopicMetricsSummary(ctx context.Context, topicID string, from, to int64) (*TopicMetricsSummary, error) {
	summary := &TopicMetricsSummary{TopicID: topicID, From: from, To: to}

	totalPublished, err := s.getTopicCounterTotal(ctx, MetricTopicMessagesPublishedTotal, topicID, from, to)
	if err != nil {
		return nil, fmt.Errorf("get topic published total: %w", err)
	}

	totalDeliveries, err := s.getTopicCounterTotal(ctx, MetricTopicDeliveriesTotal, topicID, from, to)
	if err != nil {
		return nil, fmt.Errorf("get topic deliveries total: %w", err)
	}

	summary.TotalPublished = totalPublished
	summary.TotalDeliveries = totalDeliveries

	avgRateQuery := `SELECT COALESCE(AVG(rate_per_second), 0)
		FROM rate_snapshots
		WHERE metric_name = ? AND queue_id = ? AND timestamp >= ? AND timestamp <= ?`
	if err := s.db.QueryRowContext(ctx, avgRateQuery, MetricTopicPublishRate, topicID, from, to).
		Scan(&summary.AvgPublishRate); err != nil {
		return nil, fmt.Errorf("query topic avg publish rate: %w", err)
	}

	if err := s.db.QueryRowContext(ctx, avgRateQuery, MetricTopicDeliveryRate, topicID, from, to).
		Scan(&summary.AvgDeliveryRate); err != nil {
		return nil, fmt.Errorf("query topic avg delivery rate: %w", err)
	}

	maxRateQuery := `SELECT COALESCE(MAX(rate_per_second), 0)
		FROM rate_snapshots
		WHERE metric_name = ? AND queue_id = ? AND timestamp >= ? AND timestamp <= ?`
	if err := s.db.QueryRowContext(ctx, maxRateQuery, MetricTopicPublishRate, topicID, from, to).
		Scan(&summary.MaxPublishRate); err != nil {
		return nil, fmt.Errorf("query topic max publish rate: %w", err)
	}

	if err := s.db.QueryRowContext(ctx, maxRateQuery, MetricTopicDeliveryRate, topicID, from, to).
		Scan(&summary.MaxDeliveryRate); err != nil {
		return nil, fmt.Errorf("query topic max delivery rate: %w", err)
	}

	latestSubscriptions, known, err := s.getLatestMetricValueKnown(ctx, MetricTopicSubscriptionsCurrent, topicID)
	if err != nil {
		return nil, fmt.Errorf("query topic subscriptions current: %w", err)
	}

	if known {
		subscriptions := int64(latestSubscriptions.Value)
		summary.Subscriptions = &subscriptions
	}

	return summary, nil
}

func (s *SQLiteStore) getLatestMetricValueKnown(ctx context.Context, metricName, queueID string) (LatestMetric, bool, error) {
	query := `
		SELECT metric_value, timestamp
		FROM metrics_raw
		WHERE metric_name = ? AND queue_id = ?
		ORDER BY timestamp DESC
		LIMIT 1
	`

	var m LatestMetric

	err := s.db.QueryRowContext(ctx, query, metricName, queueID).Scan(&m.Value, &m.Timestamp)
	if err == sql.ErrNoRows {
		return LatestMetric{}, false, nil
	}

	if err != nil {
		return LatestMetric{}, false, fmt.Errorf("query latest metric: %w", err)
	}

	return m, true, nil
}

func (s *SQLiteStore) getTopicCounterTotal(ctx context.Context, metricName, topicID string, from, to int64) (int64, error) {
	const totalQuery = `
		WITH last_before_range AS (
			SELECT timestamp, id, metric_value, 1 AS is_prior
			FROM metrics_raw
			WHERE metric_name = ? AND queue_id = ? AND timestamp < ?
			ORDER BY timestamp DESC, id DESC
			LIMIT 1
		),
		counter_points AS (
			SELECT timestamp, id, metric_value, is_prior FROM last_before_range
			UNION ALL
			SELECT timestamp, id, metric_value, 0 AS is_prior FROM metrics_raw
			WHERE metric_name = ? AND queue_id = ? AND timestamp >= ? AND timestamp <= ?
		)
		SELECT metric_value, is_prior
		FROM counter_points
		ORDER BY timestamp ASC, id ASC
	`

	rows, err := s.db.QueryContext(
		ctx,
		totalQuery,
		metricName, topicID, from,
		metricName, topicID, from, to,
	)
	if err != nil {
		return 0, fmt.Errorf("query topic counter total: %w", err)
	}
	defer rows.Close()

	var (
		total       float64
		previous    float64
		havePrev    bool
		haveInRange bool
	)

	for rows.Next() {
		var (
			value   float64
			isPrior int
		)

		if err := rows.Scan(&value, &isPrior); err != nil {
			return 0, fmt.Errorf(errScanRow, err)
		}

		if isPrior == 1 && !haveInRange {
			previous = value
			havePrev = true

			continue
		}

		switch {
		case !havePrev:
			total += value
		case value >= previous:
			total += value - previous
		default:
			total += value
		}

		previous = value
		havePrev = true
		haveInRange = true
	}

	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate topic counter total: %w", err)
	}

	return int64(total), nil
}
