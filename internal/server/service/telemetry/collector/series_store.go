package collector

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

	"github.com/marsolab/plainq/internal/shared/pqlite"
)

const (
	tableMetricsRaw   = "metrics_raw"
	tableMetrics1m    = "metrics_1m"
	tableMetrics1h    = "metrics_1h"
	tableMetrics1d    = "metrics_1d"
	columnTimestamp   = "timestamp"
	columnBucketStart = "bucket_start"
)

type transaction interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	Commit() error
	Rollback() error
}

type sqlWriter interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func defaultCommit(tx transaction) error { return tx.Commit() } //nolint:wrapcheck // callers add operation context.

func rollback(tx transaction) {
	_ = tx.Rollback() //nolint:errcheck // best-effort cleanup; commit makes rollback return sql.ErrTxDone.
}

func (s *SQLiteStore) commitTx(tx transaction) error {
	commit := s.commit
	if commit == nil {
		commit = defaultCommit
	}

	return commit(tx)
}

// SaveMetric saves one typed raw metric.
func (s *SQLiteStore) SaveMetric(ctx context.Context, sample MetricSample) error {
	if err := validateMetricSample(sample); err != nil {
		return err
	}

	if err := insertMetric(ctx, s.db, sample); err != nil {
		return fmt.Errorf("save metric: %w", err)
	}

	return nil
}

// SaveCoverage records one exact series or subject-wide coverage bucket.
func (s *SQLiteStore) SaveCoverage(ctx context.Context, coverage CoverageBucket) error {
	if err := validateCoverage(coverage); err != nil {
		return err
	}

	if err := upsertCoverage(ctx, s.db, coverage); err != nil {
		return fmt.Errorf("save coverage: %w", err)
	}

	return nil
}

// SaveMetricAndCoverage atomically persists one raw sample and its exact coverage.
func (s *SQLiteStore) SaveMetricAndCoverage(
	ctx context.Context, sample MetricSample, coverage CoverageBucket,
) error {
	if err := validateMetricCoveragePair(sample, coverage); err != nil {
		return err
	}

	tx, err := pqlite.BeginTx(ctx, s.db)
	if err != nil {
		return fmt.Errorf("save metric and coverage: begin transaction: %w", err)
	}
	defer rollback(tx)

	if err := insertMetric(ctx, tx, sample); err != nil {
		return fmt.Errorf("save metric and coverage: insert metric: %w", err)
	}

	if err := upsertCoverage(ctx, tx, coverage); err != nil {
		return fmt.Errorf("save metric and coverage: insert coverage: %w", err)
	}

	if err := s.commitTx(tx); err != nil {
		return fmt.Errorf("save metric and coverage: commit: %w", err)
	}

	return nil
}

// QuerySeries reads points, exact coverage, prior point, and prior coverage from one snapshot.
func (s *SQLiteStore) QuerySeries(ctx context.Context, query SeriesQuery) (SeriesResult, error) {
	result := SeriesResult{
		DataPoints:    make([]DataPoint, 0),
		Coverage:      make([]CoverageBucket, 0),
		PriorCoverage: make([]CoverageBucket, 0),
	}
	if err := validateSeriesQuery(query); err != nil {
		return result, err
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return result, fmt.Errorf("query series: begin snapshot: %w", err)
	}
	defer rollback(tx)

	result.DataPoints, err = queryDataPoints(ctx, tx, query, query.From, query.To)
	if err != nil {
		return result, fmt.Errorf("query series: points: %w", err)
	}

	result.Coverage, err = queryExactCoverage(
		ctx,
		tx,
		query.Resolution,
		query.SubjectID,
		query.MetricName,
		query.Labels,
		query.Kind,
		query.From,
		query.To,
	)
	if err != nil {
		return result, fmt.Errorf("query series: coverage: %w", err)
	}

	if query.CarryForward {
		result.Prior, err = queryCoveredPrior(ctx, tx, query)
		if err != nil {
			return result, fmt.Errorf("query series: prior: %w", err)
		}

		if result.Prior != nil {
			result.PriorCoverage, err = queryExactCoverage(
				ctx, tx, query.Resolution, query.SubjectID, query.MetricName, query.Labels, query.Kind,
				result.Prior.Timestamp, query.From,
			)
			if err != nil {
				return result, fmt.Errorf("query series: prior coverage: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return result, fmt.Errorf("query series: close snapshot: %w", err)
	}

	return result, nil
}

// QuerySubjectCoverage returns subject-wide collector coverage only.
func (s *SQLiteStore) QuerySubjectCoverage(
	ctx context.Context, query SubjectCoverageQuery,
) ([]CoverageBucket, error) {
	result := make([]CoverageBucket, 0)
	if !validResolution(query.Resolution) {
		return result, fmt.Errorf("query subject coverage: invalid resolution %q", query.Resolution)
	}

	if query.From >= query.To {
		return result, errors.New("query subject coverage: from must be before to")
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT resolution, bucket_start, subject_id, metric_name, labels, metric_kind, sample_interval_ms
FROM telemetry_coverage
WHERE resolution = ? AND subject_id = ? AND metric_name = '' AND labels = '' AND metric_kind = ''
  AND bucket_start >= ? AND bucket_start < ?
ORDER BY bucket_start`, string(query.Resolution), query.SubjectID, query.From, query.To)
	if err != nil {
		return result, fmt.Errorf("query subject coverage: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		coverage, scanErr := scanCoverage(rows)
		if scanErr != nil {
			return result, fmt.Errorf("query subject coverage: %w", scanErr)
		}

		result = append(result, coverage)
	}

	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("query subject coverage: rows: %w", err)
	}

	return result, nil
}

// SaveRateSnapshotAndMetric stores the compatibility and typed rate histories atomically.
func (s *SQLiteStore) SaveRateSnapshotAndMetric(
	ctx context.Context,
	timestamp int64,
	subjectID, metricName string,
	rate float64,
	windowMS int64,
	sample MetricSample,
) error {
	if err := validateRatePair(timestamp, subjectID, metricName, rate, windowMS, sample); err != nil {
		return err
	}

	tx, err := pqlite.BeginTx(ctx, s.db)
	if err != nil {
		return fmt.Errorf("save rate snapshot and metric: begin transaction: %w", err)
	}
	defer rollback(tx)

	if err := insertRateSnapshot(ctx, tx, RateSnapshot{
		Timestamp: timestamp, SubjectID: subjectID, MetricName: metricName, Rate: rate, WindowMS: windowMS,
	}); err != nil {
		return fmt.Errorf("save rate snapshot and metric: snapshot: %w", err)
	}

	if err := insertMetric(ctx, tx, sample); err != nil {
		return fmt.Errorf("save rate pair: typed metric: %w", err)
	}

	if err := s.commitTx(tx); err != nil {
		return fmt.Errorf("save rate snapshot and metric: commit: %w", err)
	}

	return nil
}

// SaveCollectionBoundary atomically commits one closed collection boundary.
//
//nolint:cyclop // Atomic boundary persistence intentionally keeps every ordered failure point explicit.
func (s *SQLiteStore) SaveCollectionBoundary(ctx context.Context, batch CollectionBatch) error {
	if err := validateCollectionBatch(batch); err != nil {
		return err
	}

	tx, err := pqlite.BeginTx(ctx, s.db)
	if err != nil {
		return fmt.Errorf("save collection boundary: begin transaction: %w", err)
	}
	defer rollback(tx)

	var exists int

	err = tx.QueryRowContext(ctx, `SELECT 1 FROM telemetry_collection_commits WHERE boundary = ? AND sample_interval_ms = ?`,
		batch.Boundary, batch.SampleIntervalMS).Scan(&exists)
	if err == nil {
		return nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("save collection boundary: check completion: %w", err)
	}

	for _, sample := range batch.Samples {
		if sample.Kind != MetricKindEvent {
			if _, err := tx.ExecContext(ctx, `DELETE FROM metrics_raw
WHERE timestamp = ? AND queue_id = ? AND metric_name = ? AND labels = ? AND metric_kind = ?`,
				sample.Timestamp, sample.SubjectID, sample.MetricName, sample.Labels, string(sample.Kind)); err != nil {
				return fmt.Errorf("save collection boundary: replace periodic metric: %w", err)
			}
		}

		if err := insertMetric(ctx, tx, sample); err != nil {
			return fmt.Errorf("save collection boundary: insert metric: %w", err)
		}
	}

	for _, snapshot := range batch.RateSnapshots {
		if err := insertRateSnapshot(ctx, tx, snapshot); err != nil {
			return fmt.Errorf("save collection boundary: rate snapshot: %w", err)
		}
	}

	for _, coverage := range batch.Coverage {
		if err := upsertCoverage(ctx, tx, coverage); err != nil {
			return fmt.Errorf("save collection boundary: coverage: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO telemetry_collection_commits (boundary, sample_interval_ms) VALUES (?, ?)`,
		batch.Boundary, batch.SampleIntervalMS); err != nil {
		return fmt.Errorf("save collection boundary: completion ledger: %w", err)
	}

	if err := s.commitTx(tx); err != nil {
		return fmt.Errorf("save collection boundary: commit: %w", err)
	}

	return nil
}

// LatestCollectionBoundary returns the newest durable completion-ledger entry
// for one raw grid. A restarted collector uses it before freezing any new
// in-memory state, so an idempotent row from the prior process cannot be
// mistaken for acknowledgement of the new process's first observation.
func (s *SQLiteStore) LatestCollectionBoundary(
	ctx context.Context, sampleIntervalMS int64,
) (int64, bool, error) {
	if sampleIntervalMS <= 0 {
		return 0, false, errors.New("latest collection boundary: positive sample interval is required")
	}

	var boundary sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(boundary)
FROM telemetry_collection_commits WHERE sample_interval_ms = ?`, sampleIntervalMS).Scan(&boundary); err != nil {
		return 0, false, fmt.Errorf("latest collection boundary: query: %w", err)
	}
	if !boundary.Valid {
		return 0, false, nil
	}

	return boundary.Int64, true, nil
}

// ResetRawInterval clears the entire raw grid when its interval identity changes.
//
//nolint:cyclop // One transaction must explicitly guard state inspection, purge, and replacement.
func (s *SQLiteStore) ResetRawInterval(ctx context.Context, sampleIntervalMS int64) (bool, error) {
	if sampleIntervalMS <= 0 {
		return false, errors.New("reset raw interval: sample interval must be positive")
	}

	tx, err := pqlite.BeginTx(ctx, s.db)
	if err != nil {
		return false, fmt.Errorf("reset raw interval: begin transaction: %w", err)
	}
	defer rollback(tx)

	var stored int64

	err = tx.QueryRowContext(ctx, `SELECT raw_sample_interval_ms FROM telemetry_collection_state WHERE singleton = 1`).Scan(&stored)

	missing := errors.Is(err, sql.ErrNoRows)
	if err != nil && !missing {
		return false, fmt.Errorf("reset raw interval: read state: %w", err)
	}

	var disagreement int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(
SELECT 1 FROM telemetry_coverage WHERE resolution = 'raw' AND sample_interval_ms <> ?
)`, sampleIntervalMS).Scan(&disagreement); err != nil {
		return false, fmt.Errorf("reset raw interval: inspect coverage: %w", err)
	}

	if !missing && stored == sampleIntervalMS && disagreement == 0 {
		return false, nil
	}

	for _, statement := range []string{
		`DELETE FROM metrics_raw`,
		`DELETE FROM telemetry_coverage WHERE resolution = 'raw'`,
		`DELETE FROM telemetry_collection_commits`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return false, fmt.Errorf("reset raw interval: purge grid: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO telemetry_collection_state (singleton, raw_sample_interval_ms)
VALUES (1, ?) ON CONFLICT(singleton) DO UPDATE SET raw_sample_interval_ms = excluded.raw_sample_interval_ms`, sampleIntervalMS); err != nil {
		return false, fmt.Errorf("reset raw interval: save state: %w", err)
	}

	if err := s.commitTx(tx); err != nil {
		return false, fmt.Errorf("reset raw interval: commit: %w", err)
	}

	return true, nil
}

// EnqueueTerminalState durably deduplicates and caps terminal work.
func (s *SQLiteStore) EnqueueTerminalState(
	ctx context.Context, state TerminalState, limit int,
) (bool, error) {
	if state.SubjectID == "" || state.Generation <= 0 || limit <= 0 {
		return false, errors.New("enqueue terminal state: subject, positive generation, and positive cap are required")
	}

	tx, err := pqlite.BeginTx(ctx, s.db)
	if err != nil {
		return false, fmt.Errorf("enqueue terminal state: begin transaction: %w", err)
	}
	defer rollback(tx)
	// This conditional INSERT is deliberately the first statement: the write
	// lock makes the count check and insert atomic without a nested BEGIN.
	if _, err := tx.ExecContext(ctx, `
INSERT INTO telemetry_terminal_state (subject_id, generation, observed_at)
SELECT ?, ?, ?
WHERE (SELECT COUNT(*) FROM telemetry_terminal_state) < ?
ON CONFLICT(subject_id, generation) DO NOTHING`, state.SubjectID, state.Generation, state.ObservedAt, limit); err != nil {
		return false, fmt.Errorf("enqueue terminal state: insert: %w", err)
	}

	var exists int

	err = tx.QueryRowContext(ctx, `SELECT 1 FROM telemetry_terminal_state
WHERE subject_id = ? AND generation = ?`, state.SubjectID, state.Generation).Scan(&exists)

	accepted := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("enqueue terminal state: verify: %w", err)
	}

	if err := s.commitTx(tx); err != nil {
		return false, fmt.Errorf("enqueue terminal state: commit: %w", err)
	}

	return accepted, nil
}

// CancelTerminalState removes only the deletion generation made stale by re-admission.
func (s *SQLiteStore) CancelTerminalState(ctx context.Context, subjectID string, generation int64) error {
	if subjectID == "" || generation <= 0 {
		return errors.New("cancel terminal state: subject and positive generation are required")
	}

	if _, err := s.db.ExecContext(ctx, `DELETE FROM telemetry_terminal_state
WHERE subject_id = ? AND generation = ?`, subjectID, generation); err != nil {
		return fmt.Errorf("cancel terminal state: delete: %w", err)
	}

	return nil
}

// ListTerminalStates returns durable terminal work in stable order.
func (s *SQLiteStore) ListTerminalStates(ctx context.Context) ([]TerminalState, error) {
	result := make([]TerminalState, 0)

	rows, err := s.db.QueryContext(ctx, `
SELECT subject_id, generation, observed_at, target_bucket, sample_interval_ms
FROM telemetry_terminal_state ORDER BY observed_at, subject_id, generation`)
	if err != nil {
		return result, fmt.Errorf("list terminal states: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			state            TerminalState
			target, interval sql.NullInt64
		)
		if err := rows.Scan(&state.SubjectID, &state.Generation, &state.ObservedAt, &target, &interval); err != nil {
			return result, fmt.Errorf("list terminal states: scan: %w", err)
		}

		if target.Valid {
			value := target.Int64
			state.TargetBucket = &value
		}

		if interval.Valid {
			value := interval.Int64
			state.SampleIntervalMS = &value
		}

		result = append(result, state)
	}

	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("list terminal states: rows: %w", err)
	}

	return result, nil
}

// AssignTerminalBucket freezes the terminal bucket for stable retries.
//
//nolint:cyclop // Stable retry handling explicitly distinguishes absent, identical, and conflicting assignments.
func (s *SQLiteStore) AssignTerminalBucket(
	ctx context.Context, subjectID string, generation, targetBucket, sampleIntervalMS int64,
) error {
	if subjectID == "" || generation <= 0 || sampleIntervalMS <= 0 {
		return errors.New("assign terminal bucket: subject, positive generation, and positive interval are required")
	}

	if targetBucket%sampleIntervalMS != 0 {
		return errors.New("assign terminal bucket: target bucket must align to the interval")
	}

	tx, err := pqlite.BeginTx(ctx, s.db)
	if err != nil {
		return fmt.Errorf("assign terminal bucket: begin transaction: %w", err)
	}
	defer rollback(tx)

	result, err := tx.ExecContext(ctx, `UPDATE telemetry_terminal_state
SET target_bucket = ?, sample_interval_ms = ?
WHERE subject_id = ? AND generation = ? AND target_bucket IS NULL AND sample_interval_ms IS NULL`,
		targetBucket, sampleIntervalMS, subjectID, generation)
	if err != nil {
		return fmt.Errorf("assign terminal bucket: update: %w", err)
	}

	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("assign terminal bucket: rows affected: %w", err)
	}

	if changed == 0 {
		var existingTarget, existingInterval sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT target_bucket, sample_interval_ms
FROM telemetry_terminal_state WHERE subject_id = ? AND generation = ?`, subjectID, generation).
			Scan(&existingTarget, &existingInterval); err != nil {
			return fmt.Errorf("assign terminal bucket: find existing assignment: %w", err)
		}

		if !existingTarget.Valid || !existingInterval.Valid ||
			existingTarget.Int64 != targetBucket || existingInterval.Int64 != sampleIntervalMS {
			return errors.New("assign terminal bucket: conflicting assignment")
		}
	}

	if err := s.commitTx(tx); err != nil {
		return fmt.Errorf("assign terminal bucket: commit: %w", err)
	}

	return nil
}

// CompleteTerminalState atomically writes the terminal zero, coverage, and completion.
//
//nolint:cyclop,gocyclo // The durable completion protocol keeps validation and each rollback boundary explicit.
func (s *SQLiteStore) CompleteTerminalState(
	ctx context.Context, subjectID string, generation int64, sample MetricSample, coverage CoverageBucket,
) error {
	if err := validateMetricCoveragePair(sample, coverage); err != nil {
		return fmt.Errorf("complete terminal state: %w", err)
	}

	if subjectID == "" || generation <= 0 || sample.SubjectID != subjectID ||
		sample.Kind != MetricKindGauge || sample.Value != 0 {
		return errors.New("complete terminal state: terminal sample must be the subject's gauge zero")
	}

	tx, err := pqlite.BeginTx(ctx, s.db)
	if err != nil {
		return fmt.Errorf("complete terminal state: begin transaction: %w", err)
	}
	defer rollback(tx)

	var target, interval sql.NullInt64

	err = tx.QueryRowContext(ctx, `SELECT target_bucket, sample_interval_ms
FROM telemetry_terminal_state WHERE subject_id = ? AND generation = ?`, subjectID, generation).
		Scan(&target, &interval)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("complete terminal state: read assignment: %w", err)
	}

	if !target.Valid || !interval.Valid || sample.Timestamp != target.Int64 || coverage.BucketStart != target.Int64 ||
		coverage.SampleIntervalMS != interval.Int64 {
		return errors.New("complete terminal state: sample does not match stable assignment")
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM metrics_raw
WHERE timestamp = ? AND queue_id = ? AND metric_name = ? AND labels = ? AND metric_kind = ?`,
		sample.Timestamp, sample.SubjectID, sample.MetricName, sample.Labels, string(sample.Kind)); err != nil {
		return fmt.Errorf("complete terminal state: replace zero: %w", err)
	}

	if err := insertMetric(ctx, tx, sample); err != nil {
		return fmt.Errorf("complete terminal state: insert zero: %w", err)
	}

	if err := upsertCoverage(ctx, tx, coverage); err != nil {
		return fmt.Errorf("complete terminal state: coverage: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM telemetry_terminal_state
WHERE subject_id = ? AND generation = ? AND target_bucket = ? AND sample_interval_ms = ?`,
		subjectID, generation, target.Int64, interval.Int64); err != nil {
		return fmt.Errorf("complete terminal state: delete pending state: %w", err)
	}

	if err := s.commitTx(tx); err != nil {
		return fmt.Errorf("complete terminal state: commit: %w", err)
	}

	return nil
}

func validateMetricSample(sample MetricSample) error {
	if sample.MetricName == "" || !validMetricKind(sample.Kind) {
		return errors.New("metric sample: metric name and valid kind are required")
	}

	if sample.Kind == MetricKindRate {
		if sample.WindowMS <= 0 {
			return errors.New("metric sample: rate window_ms must be positive")
		}
	} else if sample.WindowMS != 0 {
		return errors.New("metric sample: window_ms is only valid for rates")
	}

	return nil
}

func validateCoverage(coverage CoverageBucket) error {
	if !validResolution(coverage.Resolution) || coverage.SampleIntervalMS <= 0 {
		return errors.New("coverage: valid resolution and positive sample interval are required")
	}

	if coverage.MetricName == "" {
		if coverage.Labels != "" || coverage.Kind != "" {
			return errors.New("coverage: subject-wide coverage must have an empty identity")
		}

		return nil
	}

	if !validMetricKind(coverage.Kind) {
		return errors.New("coverage: series coverage requires a valid kind")
	}

	return nil
}

func validateMetricCoveragePair(sample MetricSample, coverage CoverageBucket) error {
	if err := validateMetricSample(sample); err != nil {
		return err
	}

	if err := validateCoverage(coverage); err != nil {
		return err
	}

	if coverage.Resolution != ResolutionRaw || coverage.BucketStart != sample.Timestamp ||
		coverage.SubjectID != sample.SubjectID || coverage.MetricName != sample.MetricName ||
		coverage.Labels != sample.Labels || coverage.Kind != sample.Kind {
		return errors.New("metric and coverage identities must match at raw resolution")
	}

	return nil
}

func validateSeriesQuery(query SeriesQuery) error {
	if query.MetricName == "" || !validMetricKind(query.Kind) || !validResolution(query.Resolution) {
		return errors.New("query series: metric name, kind, and supported resolution are required")
	}

	if query.From >= query.To {
		return errors.New("query series: from must be before to")
	}

	return nil
}

func validateRatePair(
	timestamp int64, subjectID, metricName string, rate float64, windowMS int64, sample MetricSample,
) error {
	if err := validateMetricSample(sample); err != nil {
		return fmt.Errorf("rate pair: %w", err)
	}

	if windowMS <= 0 || sample.Kind != MetricKindRate || sample.Timestamp != timestamp ||
		sample.SubjectID != subjectID || sample.MetricName != metricName || sample.Value != rate || sample.WindowMS != windowMS {
		return errors.New("rate pair: snapshot and typed rate sample must match exactly")
	}

	return nil
}

//nolint:cyclop,gocognit,gocyclo // Validation mirrors each independently persisted batch component.
func validateCollectionBatch(batch CollectionBatch) error {
	if batch.Boundary <= 0 || batch.SampleIntervalMS <= 0 || batch.Boundary%batch.SampleIntervalMS != 0 {
		return errors.New("collection batch: positive boundary and sample interval are required")
	}

	periodic := make(map[string]struct{})
	rates := make(map[string]RateSnapshot)

	for _, sample := range batch.Samples {
		if err := validateMetricSample(sample); err != nil {
			return fmt.Errorf("collection batch: %w", err)
		}

		if sample.Timestamp >= batch.Boundary {
			return errors.New("collection batch: sample must precede boundary")
		}

		if sample.Kind != MetricKindEvent {
			if sample.Timestamp != batch.Boundary-batch.SampleIntervalMS {
				return errors.New("collection batch: periodic sample must match the closed boundary")
			}

			key := fmt.Sprintf(
				"%d\x00%s\x00%s\x00%s\x00%s",
				sample.Timestamp,
				sample.SubjectID,
				sample.MetricName,
				sample.Labels,
				sample.Kind,
			)
			if _, exists := periodic[key]; exists {
				return errors.New("collection batch: duplicate periodic sample")
			}

			periodic[key] = struct{}{}
		}

		if sample.Kind == MetricKindRate {
			key := rateKey(sample.Timestamp, sample.SubjectID, sample.MetricName)
			rates[key] = RateSnapshot{
				Timestamp: sample.Timestamp, SubjectID: sample.SubjectID, MetricName: sample.MetricName,
				Rate: sample.Value, WindowMS: sample.WindowMS,
			}
		}
	}

	for _, snapshot := range batch.RateSnapshots {
		if snapshot.WindowMS <= 0 || snapshot.MetricName == "" || snapshot.Timestamp >= batch.Boundary {
			return errors.New("collection batch: invalid rate snapshot")
		}

		match, exists := rates[rateKey(snapshot.Timestamp, snapshot.SubjectID, snapshot.MetricName)]
		if !exists || match.Rate != snapshot.Rate || match.WindowMS != snapshot.WindowMS {
			return errors.New("collection batch: rate snapshot has no matching typed sample")
		}
	}

	if len(rates) != len(batch.RateSnapshots) {
		return errors.New("collection batch: every typed rate sample requires one snapshot")
	}

	for _, coverage := range batch.Coverage {
		if err := validateCoverage(coverage); err != nil {
			return fmt.Errorf("collection batch: %w", err)
		}

		if coverage.Resolution != ResolutionRaw || coverage.BucketStart != batch.Boundary-batch.SampleIntervalMS ||
			coverage.SampleIntervalMS != batch.SampleIntervalMS {
			return errors.New("collection batch: coverage must match the closed raw boundary")
		}
	}

	return nil
}

func validMetricKind(kind MetricKind) bool {
	switch kind {
	case MetricKindCounter, MetricKindGauge, MetricKindRate, MetricKindEvent:
		return true
	default:
		return false
	}
}

func validResolution(resolution Resolution) bool {
	switch resolution {
	case ResolutionRaw, Resolution1m, Resolution1h, Resolution1d:
		return true
	default:
		return false
	}
}

func insertMetric(ctx context.Context, writer sqlWriter, sample MetricSample) error {
	_, err := writer.ExecContext(ctx, `INSERT INTO metrics_raw
    (timestamp, queue_id, metric_name, metric_value, labels, metric_kind, window_ms)
VALUES (?, ?, ?, ?, ?, ?, ?)`, sample.Timestamp, sample.SubjectID, sample.MetricName, sample.Value,
		sample.Labels, string(sample.Kind), sample.WindowMS)

	return err //nolint:wrapcheck // caller adds operation context.
}

func upsertCoverage(ctx context.Context, writer sqlWriter, coverage CoverageBucket) error {
	_, err := writer.ExecContext(ctx, `INSERT INTO telemetry_coverage
    (resolution, bucket_start, subject_id, metric_name, labels, metric_kind, sample_interval_ms)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(resolution, bucket_start, subject_id, metric_name, labels, metric_kind)
DO UPDATE SET sample_interval_ms = excluded.sample_interval_ms`,
		string(coverage.Resolution), coverage.BucketStart, coverage.SubjectID, coverage.MetricName,
		coverage.Labels, string(coverage.Kind), coverage.SampleIntervalMS)

	return err //nolint:wrapcheck // caller adds operation context.
}

func insertRateSnapshot(ctx context.Context, writer sqlWriter, snapshot RateSnapshot) error {
	if snapshot.WindowMS <= 0 {
		return errors.New("window_ms must be positive")
	}

	_, err := writer.ExecContext(ctx, `INSERT INTO rate_snapshots
    (timestamp, queue_id, metric_name, rate_per_second, window_seconds, window_ms)
VALUES (?, ?, ?, ?, ?, ?)`, snapshot.Timestamp, snapshot.SubjectID, snapshot.MetricName,
		snapshot.Rate, compatibilityWindowSeconds(snapshot.WindowMS), snapshot.WindowMS)

	return err //nolint:wrapcheck // caller adds operation context.
}

func compatibilityWindowSeconds(windowMS int64) int64 {
	seconds := int64(math.Round(float64(windowMS) / 1000))
	if seconds < 1 {
		return 1
	}

	return seconds
}

func rateKey(timestamp int64, subjectID, metricName string) string {
	return fmt.Sprintf("%d\x00%s\x00%s", timestamp, subjectID, metricName)
}

//nolint:gocritic // Both identifiers and an error keep callers from interpolating unchecked names.
func resolutionTable(resolution Resolution) (string, string, error) {
	switch resolution {
	case ResolutionRaw:
		return tableMetricsRaw, columnTimestamp, nil
	case Resolution1m:
		return tableMetrics1m, columnBucketStart, nil
	case Resolution1h:
		return tableMetrics1h, columnBucketStart, nil
	case Resolution1d:
		return tableMetrics1d, columnBucketStart, nil
	default:
		return "", "", fmt.Errorf("unsupported resolution %q", resolution)
	}
}

//nolint:cyclop // Raw and aggregate tiers have intentionally distinct scan contracts.
func queryDataPoints(
	ctx context.Context, tx *sql.Tx, query SeriesQuery, from, to int64,
) ([]DataPoint, error) {
	result := make([]DataPoint, 0)

	table, timeColumn, err := resolutionTable(query.Resolution)
	if err != nil {
		return result, err
	}

	if query.Resolution == ResolutionRaw {
		rows, err := tx.QueryContext(ctx, `SELECT timestamp, metric_value, window_ms
FROM metrics_raw
WHERE metric_name = ? AND queue_id = ? AND labels = ? AND metric_kind = ?
  AND timestamp >= ? AND timestamp < ?
ORDER BY timestamp`, query.MetricName, query.SubjectID, query.Labels, string(query.Kind), from, to)
		if err != nil {
			return result, fmt.Errorf("query raw data points: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var point DataPoint
			if err := rows.Scan(&point.Timestamp, &point.Value, &point.WindowMS); err != nil {
				return result, fmt.Errorf("scan raw data point: %w", err)
			}

			point.Count = 1
			point.Source = "observed"
			result = append(result, point)
		}

		if err := rows.Err(); err != nil {
			return result, fmt.Errorf("iterate raw data points: %w", err)
		}

		return result, nil
	}

	//nolint:gosec // Table and time-column identifiers come from resolutionTable constants.
	statement := fmt.Sprintf(`SELECT %s, min_value, max_value, avg_value, sum_value, count,
       first_value, last_value, increase_value, window_ms
FROM %s
WHERE metric_name = ? AND queue_id = ? AND labels = ? AND metric_kind = ?
  AND %s >= ? AND %s < ?
ORDER BY %s`, timeColumn, table, timeColumn, timeColumn, timeColumn)

	rows, err := tx.QueryContext(ctx, statement, query.MetricName, query.SubjectID, query.Labels, string(query.Kind), from, to)
	if err != nil {
		return result, fmt.Errorf("query aggregate data points: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		point, include, scanErr := scanAggregatePoint(rows, query.Kind)
		if scanErr != nil {
			return result, scanErr
		}

		if include {
			result = append(result, point)
		}
	}

	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("iterate aggregate data points: %w", err)
	}

	return result, nil
}

//nolint:cyclop // Kind-specific nullable selection is intentionally centralized with SQL scanning.
func scanAggregatePoint(
	scanner interface{ Scan(dest ...any) error }, kind MetricKind,
) (DataPoint, bool, error) {
	var (
		point                 DataPoint
		first, last, increase sql.NullFloat64
	)
	if err := scanner.Scan(&point.Timestamp, &point.Min, &point.Max, &point.Avg, &point.Sum, &point.Count,
		&first, &last, &increase, &point.WindowMS); err != nil {
		return point, false, fmt.Errorf("scan aggregate point: %w", err)
	}

	if first.Valid {
		point.First = first.Float64
	}

	if last.Valid {
		point.Last = last.Float64
	}

	if increase.Valid {
		point.Increase = increase.Float64
	}

	switch kind {
	case MetricKindGauge:
		if !last.Valid {
			return point, false, nil
		}

		point.Value = last.Float64
	case MetricKindCounter:
		if !increase.Valid {
			return point, false, nil
		}

		point.Value = increase.Float64
	case MetricKindRate, MetricKindEvent:
		point.Value = point.Avg
	default:
		return point, false, fmt.Errorf("unknown metric kind %q", kind)
	}

	point.Source = "aggregated"

	return point, true, nil
}

func queryExactCoverage(
	ctx context.Context,
	tx *sql.Tx,
	resolution Resolution,
	subjectID, metricName, labels string,
	kind MetricKind,
	from, to int64,
) ([]CoverageBucket, error) {
	result := make([]CoverageBucket, 0)

	rows, err := tx.QueryContext(ctx, `
SELECT resolution, bucket_start, subject_id, metric_name, labels, metric_kind, sample_interval_ms
FROM telemetry_coverage
WHERE resolution = ? AND subject_id = ? AND metric_name = ? AND labels = ? AND metric_kind = ?
  AND bucket_start >= ? AND bucket_start < ?
ORDER BY bucket_start`, string(resolution), subjectID, metricName, labels, string(kind), from, to)
	if err != nil {
		return result, fmt.Errorf("query exact coverage: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		coverage, scanErr := scanCoverage(rows)
		if scanErr != nil {
			return result, scanErr
		}

		result = append(result, coverage)
	}

	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("iterate exact coverage: %w", err)
	}

	return result, nil
}

func scanCoverage(scanner interface{ Scan(dest ...any) error }) (CoverageBucket, error) {
	var (
		coverage         CoverageBucket
		resolution, kind string
	)
	if err := scanner.Scan(&resolution, &coverage.BucketStart, &coverage.SubjectID, &coverage.MetricName,
		&coverage.Labels, &kind, &coverage.SampleIntervalMS); err != nil {
		return coverage, fmt.Errorf("scan coverage: %w", err)
	}

	coverage.Resolution = Resolution(resolution)
	coverage.Kind = MetricKind(kind)

	return coverage, nil
}

//nolint:cyclop // Raw and aggregate prior selection have distinct nullable-value contracts.
func queryCoveredPrior(ctx context.Context, tx *sql.Tx, query SeriesQuery) (*DataPoint, error) {
	table, timeColumn, err := resolutionTable(query.Resolution)
	if err != nil {
		return nil, err
	}

	coverageJoin := fmt.Sprintf(`JOIN telemetry_coverage c
  ON c.resolution = ? AND c.bucket_start = m.%s AND c.subject_id = m.queue_id
 AND c.metric_name = m.metric_name AND c.labels = m.labels AND c.metric_kind = m.metric_kind`, timeColumn)
	if query.Resolution == ResolutionRaw {
		//nolint:gosec // Table and join identifiers come from resolutionTable constants.
		statement := fmt.Sprintf(`SELECT m.timestamp, m.metric_value, m.window_ms
FROM %s m %s
WHERE m.metric_name = ? AND m.queue_id = ? AND m.labels = ? AND m.metric_kind = ? AND m.timestamp < ?
ORDER BY m.timestamp DESC LIMIT 1`, table, coverageJoin)

		var point DataPoint

		err := tx.QueryRowContext(ctx, statement, string(query.Resolution), query.MetricName, query.SubjectID,
			query.Labels, string(query.Kind), query.From).Scan(&point.Timestamp, &point.Value, &point.WindowMS)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}

		if err != nil {
			return nil, fmt.Errorf("query covered raw prior: %w", err)
		}

		point.Count = 1
		point.Source = "observed"

		return &point, nil
	}

	selectedValuePredicate := "1 = 1"

	switch query.Kind {
	case MetricKindGauge:
		selectedValuePredicate = "m.last_value IS NOT NULL"
	case MetricKindCounter:
		selectedValuePredicate = "m.increase_value IS NOT NULL"
	case MetricKindRate, MetricKindEvent:
		// These kinds select the non-null legacy avg_value column.
	default:
		return nil, fmt.Errorf("query covered prior: invalid kind %q", query.Kind)
	}

	statement := fmt.Sprintf(`SELECT m.%s, m.min_value, m.max_value, m.avg_value, m.sum_value, m.count,
       m.first_value, m.last_value, m.increase_value, m.window_ms
FROM %s m %s
WHERE m.metric_name = ? AND m.queue_id = ? AND m.labels = ? AND m.metric_kind = ?
  AND %s AND m.%s < ?
ORDER BY m.%s DESC LIMIT 1`,
		timeColumn, table, coverageJoin, selectedValuePredicate, timeColumn, timeColumn,
	)

	point, include, err := scanAggregatePoint(tx.QueryRowContext(ctx, statement, string(query.Resolution), query.MetricName,
		query.SubjectID, query.Labels, string(query.Kind), query.From), query.Kind)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	if !include {
		return nil, nil
	}

	return &point, nil
}
