package collector

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/plainq/servekit/dbkit/litekit"
)

// SQLiteStore implements the Store interface using SQLite.
type SQLiteStore struct {
	db *litekit.Conn
}

// NewSQLiteStore creates a new SQLite-backed metrics store.
func NewSQLiteStore(db *litekit.Conn) *SQLiteStore {
	return &SQLiteStore{db: db}
}

// SaveRawMetric saves a raw metric data point.
func (s *SQLiteStore) SaveRawMetric(ctx context.Context, timestamp int64, queueID, metricName string, value float64, labels string) error {
	query := `INSERT INTO metrics_raw (timestamp, queue_id, metric_name, metric_value, labels) VALUES (?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, timestamp, queueID, metricName, value, labels)
	return err
}

// SaveRateSnapshot saves rate calculation results.
func (s *SQLiteStore) SaveRateSnapshot(ctx context.Context, timestamp int64, queueID, metricName string, ratePerSecond float64, windowSeconds int) error {
	query := `INSERT INTO rate_snapshots (timestamp, queue_id, metric_name, rate_per_second, window_seconds) VALUES (?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, timestamp, queueID, metricName, ratePerSecond, windowSeconds)
	return err
}

// SaveQueueStats saves queue statistics snapshot.
func (s *SQLiteStore) SaveQueueStats(ctx context.Context, timestamp int64, queueID string, depth, visible, invisible int64, oldestAge, avgAge float64) error {
	query := `INSERT INTO queue_stats_snapshot (timestamp, queue_id, queue_depth, messages_visible, messages_invisible, oldest_message_age_seconds, avg_message_age_seconds) VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, timestamp, queueID, depth, visible, invisible, oldestAge, avgAge)
	return err
}

// UpdateInFlightCount updates the in-flight message count for a queue.
func (s *SQLiteStore) UpdateInFlightCount(ctx context.Context, queueID string, count int64) error {
	query := `INSERT INTO messages_in_flight (queue_id, count, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(queue_id) DO UPDATE SET count = excluded.count, updated_at = excluded.updated_at`
	_, err := s.db.ExecContext(ctx, query, queueID, count, time.Now().UnixMilli())
	return err
}

// Aggregate1m aggregates raw metrics into 1-minute buckets.
func (s *SQLiteStore) Aggregate1m(ctx context.Context, fromTimestamp, toTimestamp int64) error {
	// Calculate bucket boundaries (1-minute = 60000ms).
	bucketSize := int64(60000)

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
	_, err := s.db.ExecContext(ctx, query, bucketSize, bucketSize, fromTimestamp, toTimestamp)
	return err
}

// Aggregate1h aggregates 1-minute metrics into 1-hour buckets.
func (s *SQLiteStore) Aggregate1h(ctx context.Context, fromTimestamp, toTimestamp int64) error {
	bucketSize := int64(3600000) // 1 hour in ms
	minuteBucketSize := int64(60000)

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
	_, err := s.db.ExecContext(ctx, query,
		bucketSize, bucketSize,
		fromTimestamp, minuteBucketSize, minuteBucketSize,
		toTimestamp, minuteBucketSize, minuteBucketSize)
	return err
}

// Aggregate1d aggregates 1-hour metrics into 1-day buckets.
func (s *SQLiteStore) Aggregate1d(ctx context.Context, fromTimestamp, toTimestamp int64) error {
	bucketSize := int64(86400000) // 1 day in ms
	hourBucketSize := int64(3600000)

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
	_, err := s.db.ExecContext(ctx, query,
		bucketSize, bucketSize,
		fromTimestamp, hourBucketSize, hourBucketSize,
		toTimestamp, hourBucketSize, hourBucketSize)
	return err
}

// CleanupOldMetrics removes metrics older than retention period.
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
func (s *SQLiteStore) GetMetrics(ctx context.Context, metricName, queueID string, from, to int64, resolution string) ([]DataPoint, error) {
	var query string
	var args []interface{}

	switch resolution {
	case "raw":
		query = `SELECT timestamp, metric_value, metric_value, metric_value, metric_value, metric_value, 1
			FROM metrics_raw WHERE metric_name = ? AND timestamp >= ? AND timestamp <= ?`
		args = []interface{}{metricName, from, to}
		if queueID != "" {
			query = `SELECT timestamp, metric_value, metric_value, metric_value, metric_value, metric_value, 1
				FROM metrics_raw WHERE metric_name = ? AND queue_id = ? AND timestamp >= ? AND timestamp <= ?`
			args = []interface{}{metricName, queueID, from, to}
		}
		query += " ORDER BY timestamp ASC"

	case "1m":
		query = `SELECT bucket_start, avg_value, min_value, max_value, avg_value, sum_value, count
			FROM metrics_1m WHERE metric_name = ? AND bucket_start >= ? AND bucket_start <= ?`
		args = []interface{}{metricName, from, to}
		if queueID != "" {
			query = `SELECT bucket_start, avg_value, min_value, max_value, avg_value, sum_value, count
				FROM metrics_1m WHERE metric_name = ? AND queue_id = ? AND bucket_start >= ? AND bucket_start <= ?`
			args = []interface{}{metricName, queueID, from, to}
		}
		query += " ORDER BY bucket_start ASC"

	case "5m":
		query = `SELECT timestamp, metric_value_avg, metric_value_min, metric_value_max, metric_value_avg, metric_value_avg, 1
			FROM metrics_5m WHERE metric_name = ? AND timestamp >= ? AND timestamp <= ?`
		args = []interface{}{metricName, from, to}
		if queueID != "" {
			query = `SELECT timestamp, metric_value_avg, metric_value_min, metric_value_max, metric_value_avg, metric_value_avg, 1
				FROM metrics_5m WHERE metric_name = ? AND queue_id = ? AND timestamp >= ? AND timestamp <= ?`
			args = []interface{}{metricName, queueID, from, to}
		}
		query += " ORDER BY timestamp ASC"

	case "1h":
		query = `SELECT bucket_start, avg_value, min_value, max_value, avg_value, sum_value, count
			FROM metrics_1h WHERE metric_name = ? AND bucket_start >= ? AND bucket_start <= ?`
		args = []interface{}{metricName, from, to}
		if queueID != "" {
			query = `SELECT bucket_start, avg_value, min_value, max_value, avg_value, sum_value, count
				FROM metrics_1h WHERE metric_name = ? AND queue_id = ? AND bucket_start >= ? AND bucket_start <= ?`
			args = []interface{}{metricName, queueID, from, to}
		}
		query += " ORDER BY bucket_start ASC"

	case "1d":
		query = `SELECT bucket_start, avg_value, min_value, max_value, avg_value, sum_value, count
			FROM metrics_1d WHERE metric_name = ? AND bucket_start >= ? AND bucket_start <= ?`
		args = []interface{}{metricName, from, to}
		if queueID != "" {
			query = `SELECT bucket_start, avg_value, min_value, max_value, avg_value, sum_value, count
				FROM metrics_1d WHERE metric_name = ? AND queue_id = ? AND bucket_start >= ? AND bucket_start <= ?`
			args = []interface{}{metricName, queueID, from, to}
		}
		query += " ORDER BY bucket_start ASC"

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
			return nil, fmt.Errorf("scan row: %w", err)
		}
		points = append(points, p)
	}

	return points, rows.Err()
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
		var name string
		var rate float64
		if err := rows.Scan(&name, &rate); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		rates[name] = rate
	}

	return rates, rows.Err()
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
		if err := rows.Scan(&p.Timestamp, &p.QueueDepth, &p.MessagesVisible, &p.MessagesInvisible, &p.OldestMessageAge, &p.AvgMessageAge); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		points = append(points, p)
	}

	return points, rows.Err()
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
		var queueID string
		var count int64
		if err := rows.Scan(&queueID, &count); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		counts[queueID] = count
	}

	return counts, rows.Err()
}

// GetRateHistory retrieves rate history for a metric.
func (s *SQLiteStore) GetRateHistory(ctx context.Context, metricName, queueID string, from, to int64) ([]DataPoint, error) {
	query := `
		SELECT timestamp, rate_per_second, rate_per_second, rate_per_second, rate_per_second, rate_per_second, 1
		FROM rate_snapshots
		WHERE metric_name = ? AND timestamp >= ? AND timestamp <= ?
	`
	args := []interface{}{metricName, from, to}

	if queueID != "" {
		query = `
			SELECT timestamp, rate_per_second, rate_per_second, rate_per_second, rate_per_second, rate_per_second, 1
			FROM rate_snapshots
			WHERE metric_name = ? AND queue_id = ? AND timestamp >= ? AND timestamp <= ?
		`
		args = []interface{}{metricName, queueID, from, to}
	}
	query += " ORDER BY timestamp ASC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query rate history: %w", err)
	}
	defer rows.Close()

	var points []DataPoint
	for rows.Next() {
		var p DataPoint
		if err := rows.Scan(&p.Timestamp, &p.Value, &p.Min, &p.Max, &p.Avg, &p.Sum, &p.Count); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		points = append(points, p)
	}

	return points, rows.Err()
}

// GetSystemMetrics retrieves system-wide metrics (queue_id = '').
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
			return nil, fmt.Errorf("scan row: %w", err)
		}
		points = append(points, p)
	}

	return points, rows.Err()
}

// GetLatestMetricValue retrieves the most recent value for a metric.
func (s *SQLiteStore) GetLatestMetricValue(ctx context.Context, metricName, queueID string) (float64, int64, error) {
	query := `
		SELECT metric_value, timestamp
		FROM metrics_raw
		WHERE metric_name = ? AND queue_id = ?
		ORDER BY timestamp DESC
		LIMIT 1
	`

	var value float64
	var timestamp int64
	err := s.db.QueryRowContext(ctx, query, metricName, queueID).Scan(&value, &timestamp)
	if err == sql.ErrNoRows {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, fmt.Errorf("query latest metric: %w", err)
	}

	return value, timestamp, nil
}

// GetMetricsSummary retrieves a summary of metrics for a time range.
func (s *SQLiteStore) GetMetricsSummary(ctx context.Context, queueID string, from, to int64) (*MetricsSummary, error) {
	summary := &MetricsSummary{
		QueueID: queueID,
		From:    from,
		To:      to,
	}

	// Get total sent.
	query := `SELECT COALESCE(MAX(metric_value) - MIN(metric_value), 0) FROM metrics_raw WHERE metric_name = ? AND queue_id = ? AND timestamp >= ? AND timestamp <= ?`
	_ = s.db.QueryRowContext(ctx, query, MetricMessagesSentTotal, queueID, from, to).Scan(&summary.TotalSent)

	// Get total received.
	_ = s.db.QueryRowContext(ctx, query, MetricMessagesReceivedTotal, queueID, from, to).Scan(&summary.TotalReceived)

	// Get total deleted.
	_ = s.db.QueryRowContext(ctx, query, MetricMessagesDeletedTotal, queueID, from, to).Scan(&summary.TotalDeleted)

	// Get average rates.
	rateQuery := `SELECT COALESCE(AVG(rate_per_second), 0) FROM rate_snapshots WHERE metric_name = ? AND queue_id = ? AND timestamp >= ? AND timestamp <= ?`
	_ = s.db.QueryRowContext(ctx, rateQuery, MetricSendRate, queueID, from, to).Scan(&summary.AvgSendRate)
	_ = s.db.QueryRowContext(ctx, rateQuery, MetricReceiveRate, queueID, from, to).Scan(&summary.AvgReceiveRate)
	_ = s.db.QueryRowContext(ctx, rateQuery, MetricDeleteRate, queueID, from, to).Scan(&summary.AvgDeleteRate)

	// Get max rates.
	maxRateQuery := `SELECT COALESCE(MAX(rate_per_second), 0) FROM rate_snapshots WHERE metric_name = ? AND queue_id = ? AND timestamp >= ? AND timestamp <= ?`
	_ = s.db.QueryRowContext(ctx, maxRateQuery, MetricSendRate, queueID, from, to).Scan(&summary.MaxSendRate)
	_ = s.db.QueryRowContext(ctx, maxRateQuery, MetricReceiveRate, queueID, from, to).Scan(&summary.MaxReceiveRate)
	_ = s.db.QueryRowContext(ctx, maxRateQuery, MetricDeleteRate, queueID, from, to).Scan(&summary.MaxDeleteRate)

	// Get current in-flight.
	_ = s.db.QueryRowContext(ctx, `SELECT COALESCE(count, 0) FROM messages_in_flight WHERE queue_id = ?`, queueID).Scan(&summary.CurrentInFlight)

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
