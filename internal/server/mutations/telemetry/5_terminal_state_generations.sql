CREATE TABLE telemetry_terminal_state_v5 (
    subject_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    observed_at INTEGER NOT NULL,
    target_bucket INTEGER,
    sample_interval_ms INTEGER,
    PRIMARY KEY (subject_id, generation)
);

INSERT INTO telemetry_terminal_state_v5
    (subject_id, generation, observed_at, target_bucket, sample_interval_ms)
SELECT subject_id, 1, observed_at, target_bucket, sample_interval_ms
FROM telemetry_terminal_state;

DROP TABLE telemetry_terminal_state;
ALTER TABLE telemetry_terminal_state_v5 RENAME TO telemetry_terminal_state;

CREATE INDEX idx_telemetry_terminal_state_order
    ON telemetry_terminal_state (observed_at, subject_id, generation);
