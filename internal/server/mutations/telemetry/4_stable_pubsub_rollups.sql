ALTER TABLE metrics_raw ADD COLUMN metric_kind TEXT NOT NULL DEFAULT 'gauge';
ALTER TABLE metrics_raw ADD COLUMN window_ms INTEGER NOT NULL DEFAULT 0;

ALTER TABLE metrics_1m ADD COLUMN metric_kind TEXT NOT NULL DEFAULT 'gauge';
ALTER TABLE metrics_1m ADD COLUMN first_value REAL;
ALTER TABLE metrics_1m ADD COLUMN last_value REAL;
ALTER TABLE metrics_1m ADD COLUMN increase_value REAL;
ALTER TABLE metrics_1m ADD COLUMN window_ms INTEGER NOT NULL DEFAULT 0;

ALTER TABLE metrics_1h ADD COLUMN metric_kind TEXT NOT NULL DEFAULT 'gauge';
ALTER TABLE metrics_1h ADD COLUMN first_value REAL;
ALTER TABLE metrics_1h ADD COLUMN last_value REAL;
ALTER TABLE metrics_1h ADD COLUMN increase_value REAL;
ALTER TABLE metrics_1h ADD COLUMN window_ms INTEGER NOT NULL DEFAULT 0;

ALTER TABLE metrics_1d ADD COLUMN metric_kind TEXT NOT NULL DEFAULT 'gauge';
ALTER TABLE metrics_1d ADD COLUMN first_value REAL;
ALTER TABLE metrics_1d ADD COLUMN last_value REAL;
ALTER TABLE metrics_1d ADD COLUMN increase_value REAL;
ALTER TABLE metrics_1d ADD COLUMN window_ms INTEGER NOT NULL DEFAULT 0;

ALTER TABLE rate_snapshots ADD COLUMN window_ms INTEGER NOT NULL DEFAULT 1000;
UPDATE rate_snapshots SET window_ms = window_seconds * 1000;

DROP INDEX IF EXISTS idx_metrics_1m_unique;
CREATE UNIQUE INDEX idx_metrics_1m_unique
    ON metrics_1m (bucket_start, queue_id, metric_name, labels, metric_kind);
DROP INDEX IF EXISTS idx_metrics_1m_composite;
CREATE INDEX idx_metrics_1m_composite
    ON metrics_1m (metric_name, queue_id, labels, metric_kind, bucket_start);
DROP INDEX IF EXISTS idx_metrics_1h_unique;
CREATE UNIQUE INDEX idx_metrics_1h_unique
    ON metrics_1h (bucket_start, queue_id, metric_name, labels, metric_kind);
DROP INDEX IF EXISTS idx_metrics_1h_composite;
CREATE INDEX idx_metrics_1h_composite
    ON metrics_1h (metric_name, queue_id, labels, metric_kind, bucket_start);
DROP INDEX IF EXISTS idx_metrics_1d_unique;
CREATE UNIQUE INDEX idx_metrics_1d_unique
    ON metrics_1d (bucket_start, queue_id, metric_name, labels, metric_kind);
DROP INDEX IF EXISTS idx_metrics_1d_composite;
CREATE INDEX idx_metrics_1d_composite
    ON metrics_1d (metric_name, queue_id, labels, metric_kind, bucket_start);
DROP INDEX IF EXISTS idx_metrics_raw_composite;
CREATE INDEX idx_metrics_raw_composite
    ON metrics_raw (metric_name, queue_id, labels, metric_kind, timestamp);

CREATE TABLE IF NOT EXISTS telemetry_rollup_state (
    resolution TEXT PRIMARY KEY,
    last_completed_bucket INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS telemetry_collection_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    raw_sample_interval_ms INTEGER NOT NULL CHECK (raw_sample_interval_ms > 0)
);

CREATE TABLE IF NOT EXISTS telemetry_coverage (
    resolution TEXT NOT NULL,
    bucket_start INTEGER NOT NULL,
    subject_id TEXT NOT NULL DEFAULT '',
    metric_name TEXT NOT NULL DEFAULT '',
    labels TEXT NOT NULL DEFAULT '',
    metric_kind TEXT NOT NULL DEFAULT '',
    sample_interval_ms INTEGER NOT NULL,
    PRIMARY KEY (resolution, bucket_start, subject_id, metric_name, labels, metric_kind)
);

CREATE INDEX IF NOT EXISTS idx_telemetry_coverage_subject
    ON telemetry_coverage (subject_id, metric_name, labels, metric_kind, resolution, bucket_start);

CREATE TABLE IF NOT EXISTS telemetry_terminal_state (
    subject_id TEXT PRIMARY KEY,
    observed_at INTEGER NOT NULL,
    target_bucket INTEGER,
    sample_interval_ms INTEGER
);

CREATE TABLE IF NOT EXISTS telemetry_collection_commits (
    boundary INTEGER NOT NULL,
    sample_interval_ms INTEGER NOT NULL,
    PRIMARY KEY (boundary, sample_interval_ms)
);
