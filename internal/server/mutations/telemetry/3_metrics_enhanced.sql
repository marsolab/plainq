-- Enhanced metrics schema with multiple retention tiers (like Grafana/Prometheus)
-- Retention tiers:
--   metrics_raw:  1-second resolution, 1-hour retention
--   metrics_1m:   1-minute aggregates, 24-hour retention
--   metrics_5m:   5-minute aggregates, 7-day retention (already exists, enhanced)
--   metrics_1h:   1-hour aggregates, 30-day retention
--   metrics_1d:   1-day aggregates, 1-year retention

-- Raw metrics table (1-second resolution, 1-hour retention)
CREATE TABLE IF NOT EXISTS "metrics_raw" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,  -- Unix timestamp in milliseconds
    queue_id TEXT NOT NULL DEFAULT '',  -- Empty for system-wide metrics
    metric_name TEXT NOT NULL,
    metric_value REAL NOT NULL,
    labels TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_metrics_raw_timestamp ON metrics_raw(timestamp);
CREATE INDEX IF NOT EXISTS idx_metrics_raw_queue ON metrics_raw(queue_id);
CREATE INDEX IF NOT EXISTS idx_metrics_raw_metric ON metrics_raw(metric_name);
CREATE INDEX IF NOT EXISTS idx_metrics_raw_composite ON metrics_raw(metric_name, queue_id, timestamp);

-- 1-minute aggregates (24-hour retention)
CREATE TABLE IF NOT EXISTS "metrics_1m" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket_start INTEGER NOT NULL,  -- Unix timestamp (start of minute)
    queue_id TEXT NOT NULL DEFAULT '',
    metric_name TEXT NOT NULL,
    min_value REAL NOT NULL,
    max_value REAL NOT NULL,
    avg_value REAL NOT NULL,
    sum_value REAL NOT NULL,
    count INTEGER NOT NULL,
    labels TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_metrics_1m_bucket ON metrics_1m(bucket_start);
CREATE INDEX IF NOT EXISTS idx_metrics_1m_queue ON metrics_1m(queue_id);
CREATE INDEX IF NOT EXISTS idx_metrics_1m_metric ON metrics_1m(metric_name);
CREATE INDEX IF NOT EXISTS idx_metrics_1m_composite ON metrics_1m(metric_name, queue_id, bucket_start);
CREATE UNIQUE INDEX IF NOT EXISTS idx_metrics_1m_unique ON metrics_1m(bucket_start, queue_id, metric_name, labels);

-- 1-hour aggregates (30-day retention)
CREATE TABLE IF NOT EXISTS "metrics_1h" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket_start INTEGER NOT NULL,  -- Unix timestamp (start of hour)
    queue_id TEXT NOT NULL DEFAULT '',
    metric_name TEXT NOT NULL,
    min_value REAL NOT NULL,
    max_value REAL NOT NULL,
    avg_value REAL NOT NULL,
    sum_value REAL NOT NULL,
    count INTEGER NOT NULL,
    labels TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_metrics_1h_bucket ON metrics_1h(bucket_start);
CREATE INDEX IF NOT EXISTS idx_metrics_1h_queue ON metrics_1h(queue_id);
CREATE INDEX IF NOT EXISTS idx_metrics_1h_metric ON metrics_1h(metric_name);
CREATE INDEX IF NOT EXISTS idx_metrics_1h_composite ON metrics_1h(metric_name, queue_id, bucket_start);
CREATE UNIQUE INDEX IF NOT EXISTS idx_metrics_1h_unique ON metrics_1h(bucket_start, queue_id, metric_name, labels);

-- 1-day aggregates (1-year retention)
CREATE TABLE IF NOT EXISTS "metrics_1d" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket_start INTEGER NOT NULL,  -- Unix timestamp (start of day, UTC)
    queue_id TEXT NOT NULL DEFAULT '',
    metric_name TEXT NOT NULL,
    min_value REAL NOT NULL,
    max_value REAL NOT NULL,
    avg_value REAL NOT NULL,
    sum_value REAL NOT NULL,
    count INTEGER NOT NULL,
    labels TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_metrics_1d_bucket ON metrics_1d(bucket_start);
CREATE INDEX IF NOT EXISTS idx_metrics_1d_queue ON metrics_1d(queue_id);
CREATE INDEX IF NOT EXISTS idx_metrics_1d_metric ON metrics_1d(metric_name);
CREATE INDEX IF NOT EXISTS idx_metrics_1d_composite ON metrics_1d(metric_name, queue_id, bucket_start);
CREATE UNIQUE INDEX IF NOT EXISTS idx_metrics_1d_unique ON metrics_1d(bucket_start, queue_id, metric_name, labels);

-- In-flight messages tracking table (real-time gauge data)
CREATE TABLE IF NOT EXISTS "messages_in_flight" (
    queue_id TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL  -- Unix timestamp in milliseconds
);

-- Queue statistics snapshot table (for queue depth, oldest message, etc.)
CREATE TABLE IF NOT EXISTS "queue_stats_snapshot" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    queue_id TEXT NOT NULL,
    queue_depth INTEGER NOT NULL DEFAULT 0,
    messages_visible INTEGER NOT NULL DEFAULT 0,
    messages_invisible INTEGER NOT NULL DEFAULT 0,
    oldest_message_age_seconds REAL NOT NULL DEFAULT 0,
    avg_message_age_seconds REAL NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_queue_stats_timestamp ON queue_stats_snapshot(timestamp);
CREATE INDEX IF NOT EXISTS idx_queue_stats_queue ON queue_stats_snapshot(queue_id);
CREATE INDEX IF NOT EXISTS idx_queue_stats_composite ON queue_stats_snapshot(queue_id, timestamp);

-- Rate tracking table (for real-time rate calculations)
CREATE TABLE IF NOT EXISTS "rate_snapshots" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,  -- Unix timestamp in milliseconds
    queue_id TEXT NOT NULL DEFAULT '',  -- Empty for system-wide
    metric_name TEXT NOT NULL,  -- e.g., 'send_rate', 'receive_rate', 'delete_rate'
    rate_per_second REAL NOT NULL,
    window_seconds INTEGER NOT NULL DEFAULT 1  -- The window over which rate was calculated
);

CREATE INDEX IF NOT EXISTS idx_rate_timestamp ON rate_snapshots(timestamp);
CREATE INDEX IF NOT EXISTS idx_rate_queue ON rate_snapshots(queue_id);
CREATE INDEX IF NOT EXISTS idx_rate_metric ON rate_snapshots(metric_name);
CREATE INDEX IF NOT EXISTS idx_rate_composite ON rate_snapshots(metric_name, queue_id, timestamp);
