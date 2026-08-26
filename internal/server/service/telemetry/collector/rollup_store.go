package collector

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

	"github.com/marsolab/plainq/internal/shared/pqlite"
)

type rollupSpec struct {
	targetResolution Resolution
	sourceResolution Resolution
	targetTable      string
	sourceTable      string
	sourceTimeColumn string
	targetSizeMS     int64
	sourceSizeMS     int64
}

type seriesIdentity struct {
	subjectID  string
	metricName string
	labels     string
	kind       MetricKind
}

type sourceRow struct {
	timestamp  int64
	value      float64
	min        float64
	max        float64
	avg        float64
	sum        float64
	count      int64
	first      float64
	last       float64
	increase   float64
	windowMS   int64
	firstOK    bool
	lastOK     bool
	increaseOK bool
}

type rolledAggregate struct {
	first           float64
	last            float64
	min             float64
	max             float64
	avg             float64
	sum             float64
	count           int64
	increase        float64
	windowMS        int64
	weightedRateSum float64
	hasRows         bool
	usable          bool
}

// Rollup deterministically aggregates closed source buckets in one transaction.
//
//nolint:cyclop // The ordered checkpoint transaction keeps every rollback boundary explicit.
func (s *SQLiteStore) Rollup(ctx context.Context, resolution Resolution, closedThrough int64) error {
	spec, err := makeRollupSpec(resolution)
	if err != nil {
		return err
	}

	tx, err := pqlite.BeginTx(ctx, s.db)
	if err != nil {
		return fmt.Errorf("rollup %s: begin transaction: %w", resolution, err)
	}
	defer rollback(tx)

	start, ok, err := rollupStart(ctx, tx, spec)
	if err != nil {
		return fmt.Errorf("rollup %s: find start: %w", resolution, err)
	}

	if !ok || start+spec.targetSizeMS > closedThrough {
		return nil
	}

	rawInterval, err := storedRawInterval(ctx, tx)
	if err != nil {
		return fmt.Errorf("rollup %s: raw interval: %w", resolution, err)
	}

	for bucketStart := start; bucketStart+spec.targetSizeMS <= closedThrough; bucketStart += spec.targetSizeMS {
		if err := s.rollupBucket(ctx, tx, spec, bucketStart, rawInterval); err != nil {
			return fmt.Errorf("rollup %s bucket %d: %w", resolution, bucketStart, err)
		}

		if _, err := tx.ExecContext(ctx, `INSERT INTO telemetry_rollup_state (resolution, last_completed_bucket)
VALUES (?, ?) ON CONFLICT(resolution) DO UPDATE SET last_completed_bucket = excluded.last_completed_bucket`,
			string(resolution), bucketStart); err != nil {
			return fmt.Errorf("rollup %s: advance checkpoint: %w", resolution, err)
		}
	}

	if err := s.commitTx(tx); err != nil {
		return fmt.Errorf("rollup %s: commit: %w", resolution, err)
	}

	return nil
}

//nolint:cyclop,funlen,gocognit,gocyclo // Per-identity and subject coverage gates remain in one atomic bucket phase.
func (s *SQLiteStore) rollupBucket(
	ctx context.Context,
	tx *sql.Tx,
	spec rollupSpec,
	bucketStart int64,
	rawInterval int64,
) error {
	bucketEnd := bucketStart + spec.targetSizeMS

	identities, err := loadSeriesIdentities(ctx, tx, spec, bucketStart, bucketEnd)
	if err != nil {
		return err
	}

	subjectComplete := make(map[string]bool)

	identityComplete := make(map[seriesIdentity]bool, len(identities))
	for _, identity := range identities {
		rows, err := loadSourceRows(ctx, tx, spec, identity, bucketStart, bucketEnd)
		if err != nil {
			return err
		}

		coverage, err := loadCoverageStarts(ctx, tx, spec.sourceResolution, identity, bucketStart, bucketEnd)
		if err != nil {
			return err
		}

		interval := spec.sourceSizeMS
		if spec.sourceResolution == ResolutionRaw {
			interval = coverageInterval(coverage, rawInterval)
		}

		complete := coverageIsComplete(coverage, bucketStart, bucketEnd, interval)

		if identity.kind != MetricKindEvent {
			expectedRows := int64(0)
			if interval > 0 && (bucketEnd-bucketStart)%interval == 0 {
				expectedRows = (bucketEnd - bucketStart) / interval
			}

			complete = complete && int64(len(rows)) == expectedRows
		}

		var previous *float64

		if identity.kind == MetricKindCounter && spec.sourceResolution == ResolutionRaw {
			var baselineOK bool

			previous, baselineOK, err = loadAdjacentRawCounterBaseline(ctx, tx, identity, bucketStart, interval)
			if err != nil {
				return err
			}

			complete = complete && baselineOK
		}

		aggregate, err := aggregateSourceRows(identity.kind, spec.sourceResolution, rows, previous)
		if err != nil {
			return err
		}

		complete = complete && aggregate.usable

		identityComplete[identity] = complete
		if aggregate.hasRows {
			if err := upsertAggregate(ctx, tx, spec, bucketStart, identity, aggregate); err != nil {
				return err
			}
		}

		if _, exists := subjectComplete[identity.subjectID]; !exists {
			subjectComplete[identity.subjectID] = true
		}

		if !complete {
			subjectComplete[identity.subjectID] = false

			continue
		}

		if err := upsertCoverage(ctx, tx, CoverageBucket{
			Resolution: spec.targetResolution, BucketStart: bucketStart, SubjectID: identity.subjectID,
			MetricName: identity.metricName, Labels: identity.labels, Kind: identity.kind,
			SampleIntervalMS: spec.targetSizeMS,
		}); err != nil {
			return err
		}
	}

	subjects, err := loadSubjectCoverageIdentities(ctx, tx, spec.sourceResolution, bucketStart, bucketEnd)
	if err != nil {
		return err
	}

	for _, subjectID := range subjects {
		coverage, err := loadCoverageStarts(ctx, tx, spec.sourceResolution, seriesIdentity{subjectID: subjectID}, bucketStart, bucketEnd)
		if err != nil {
			return err
		}

		interval := spec.sourceSizeMS
		if spec.sourceResolution == ResolutionRaw {
			interval = coverageInterval(coverage, rawInterval)
		}

		allSeriesComplete, hasSeries := subjectComplete[subjectID]
		if hasSeries && !allSeriesComplete {
			continue
		}

		expectedIdentities, err := loadExpectedSeriesIdentities(ctx, tx, spec, subjectID, bucketEnd)
		if err != nil {
			return err
		}

		missingExpectedSeries := false

		for _, identity := range expectedIdentities {
			if !identityComplete[identity] {
				missingExpectedSeries = true

				break
			}
		}

		if missingExpectedSeries {
			continue
		}

		if !coverageIsComplete(coverage, bucketStart, bucketEnd, interval) {
			continue
		}

		if err := upsertCoverage(ctx, tx, CoverageBucket{
			Resolution: spec.targetResolution, BucketStart: bucketStart,
			SubjectID: subjectID, SampleIntervalMS: spec.targetSizeMS,
		}); err != nil {
			return err
		}
	}

	return nil
}

func makeRollupSpec(resolution Resolution) (rollupSpec, error) {
	switch resolution {
	case Resolution1m:
		return rollupSpec{
			targetResolution: Resolution1m, sourceResolution: ResolutionRaw,
			targetTable: tableMetrics1m, sourceTable: tableMetricsRaw, sourceTimeColumn: columnTimestamp,
			targetSizeMS: bucketSize1m,
		}, nil
	case Resolution1h:
		return rollupSpec{
			targetResolution: Resolution1h, sourceResolution: Resolution1m,
			targetTable: tableMetrics1h, sourceTable: tableMetrics1m, sourceTimeColumn: columnBucketStart,
			targetSizeMS: bucketSize1h, sourceSizeMS: bucketSize1m,
		}, nil
	case Resolution1d:
		return rollupSpec{
			targetResolution: Resolution1d, sourceResolution: Resolution1h,
			targetTable: tableMetrics1d, sourceTable: tableMetrics1h, sourceTimeColumn: columnBucketStart,
			targetSizeMS: bucketSize1d, sourceSizeMS: bucketSize1h,
		}, nil
	case ResolutionRaw:
		return rollupSpec{}, errors.New("rollup: raw is a source resolution, not a target")
	default:
		return rollupSpec{}, fmt.Errorf("rollup: unsupported target resolution %q", resolution)
	}
}

//nolint:gocritic // The start and presence flag distinguish a real zero bucket from no retained source.
func rollupStart(ctx context.Context, tx *sql.Tx, spec rollupSpec) (int64, bool, error) {
	var checkpoint int64

	err := tx.QueryRowContext(ctx, `SELECT last_completed_bucket FROM telemetry_rollup_state WHERE resolution = ?`,
		string(spec.targetResolution)).Scan(&checkpoint)
	if err == nil {
		return checkpoint + spec.targetSizeMS, true, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return 0, false, fmt.Errorf("read checkpoint: %w", err)
	}
	//nolint:gosec // Table and time-column identifiers come from makeRollupSpec constants.
	statement := fmt.Sprintf(`SELECT MIN(source_time) FROM (
    SELECT MIN(%s) AS source_time FROM %s
    UNION ALL
    SELECT MIN(bucket_start) AS source_time FROM telemetry_coverage WHERE resolution = ?
)`, spec.sourceTimeColumn, spec.sourceTable)

	var earliest sql.NullInt64
	if err := tx.QueryRowContext(ctx, statement, string(spec.sourceResolution)).Scan(&earliest); err != nil {
		return 0, false, fmt.Errorf("read earliest source: %w", err)
	}

	if !earliest.Valid {
		return 0, false, nil
	}

	return floorBucket(earliest.Int64, spec.targetSizeMS), true, nil
}

func floorBucket(timestamp, size int64) int64 {
	quotient := timestamp / size
	if timestamp < 0 && timestamp%size != 0 {
		quotient--
	}

	return quotient * size
}

func storedRawInterval(ctx context.Context, tx *sql.Tx) (int64, error) {
	var interval int64

	err := tx.QueryRowContext(ctx, `SELECT raw_sample_interval_ms FROM telemetry_collection_state WHERE singleton = 1`).Scan(&interval)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}

	if err != nil {
		return 0, fmt.Errorf("read stored raw interval: %w", err)
	}

	return interval, nil
}

func loadSeriesIdentities(
	ctx context.Context, tx *sql.Tx, spec rollupSpec, from, to int64,
) ([]seriesIdentity, error) {
	//nolint:gosec // Table and time-column identifiers come from makeRollupSpec constants.
	statement := fmt.Sprintf(`SELECT queue_id, metric_name, labels, metric_kind FROM %s
WHERE %s >= ? AND %s < ?
UNION
SELECT subject_id, metric_name, labels, metric_kind FROM telemetry_coverage
WHERE resolution = ? AND metric_name <> '' AND bucket_start >= ? AND bucket_start < ?
ORDER BY 1, 2, 3, 4`, spec.sourceTable, spec.sourceTimeColumn, spec.sourceTimeColumn)

	rows, err := tx.QueryContext(ctx, statement, from, to, string(spec.sourceResolution), from, to)
	if err != nil {
		return nil, fmt.Errorf("query series identities: %w", err)
	}
	defer rows.Close()

	result := make([]seriesIdentity, 0)

	for rows.Next() {
		var (
			identity seriesIdentity
			kind     string
		)
		if err := rows.Scan(&identity.subjectID, &identity.metricName, &identity.labels, &kind); err != nil {
			return nil, fmt.Errorf("scan series identity: %w", err)
		}

		identity.kind = MetricKind(kind)
		if !validMetricKind(identity.kind) {
			continue
		}

		result = append(result, identity)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate series identities: %w", err)
	}

	return result, nil
}

func loadSubjectCoverageIdentities(
	ctx context.Context, tx *sql.Tx, resolution Resolution, from, to int64,
) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT subject_id FROM telemetry_coverage
WHERE resolution = ? AND metric_name = '' AND labels = '' AND metric_kind = ''
  AND bucket_start >= ? AND bucket_start < ?
ORDER BY subject_id`, string(resolution), from, to)
	if err != nil {
		return nil, fmt.Errorf("query subject coverage identities: %w", err)
	}
	defer rows.Close()

	result := make([]string, 0)

	for rows.Next() {
		var subjectID string
		if err := rows.Scan(&subjectID); err != nil {
			return nil, fmt.Errorf("scan subject coverage identity: %w", err)
		}

		result = append(result, subjectID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subject coverage identities: %w", err)
	}

	return result, nil
}

func loadExpectedSeriesIdentities(
	ctx context.Context,
	tx *sql.Tx,
	spec rollupSpec,
	subjectID string,
	through int64,
) ([]seriesIdentity, error) {
	//nolint:gosec // Table and time-column identifiers come from makeRollupSpec constants.
	statement := fmt.Sprintf(`SELECT queue_id, metric_name, labels, metric_kind FROM %s
WHERE queue_id = ? AND %s < ?
UNION
SELECT subject_id, metric_name, labels, metric_kind FROM telemetry_coverage
WHERE resolution = ? AND subject_id = ? AND metric_name <> '' AND bucket_start < ?
ORDER BY 2, 3, 4`, spec.sourceTable, spec.sourceTimeColumn)

	rows, err := tx.QueryContext(ctx, statement, subjectID, through, string(spec.sourceResolution), subjectID, through)
	if err != nil {
		return nil, fmt.Errorf("query expected series identities: %w", err)
	}
	defer rows.Close()

	result := make([]seriesIdentity, 0)

	for rows.Next() {
		identity := seriesIdentity{subjectID: subjectID}

		var rowSubject, kind string
		if err := rows.Scan(&rowSubject, &identity.metricName, &identity.labels, &kind); err != nil {
			return nil, fmt.Errorf("scan expected series identity: %w", err)
		}

		identity.subjectID = rowSubject

		identity.kind = MetricKind(kind)
		if validMetricKind(identity.kind) {
			result = append(result, identity)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate expected series identities: %w", err)
	}

	return result, nil
}

func loadSourceRows(
	ctx context.Context,
	tx *sql.Tx,
	spec rollupSpec,
	identity seriesIdentity,
	from, to int64,
) ([]sourceRow, error) {
	if spec.sourceResolution == ResolutionRaw {
		rows, err := tx.QueryContext(ctx, `SELECT timestamp, metric_value, window_ms
FROM metrics_raw
WHERE queue_id = ? AND metric_name = ? AND labels = ? AND metric_kind = ?
  AND timestamp >= ? AND timestamp < ?
ORDER BY timestamp, id`, identity.subjectID, identity.metricName, identity.labels, string(identity.kind), from, to)
		if err != nil {
			return nil, fmt.Errorf("query raw source rows: %w", err)
		}
		defer rows.Close()

		result := make([]sourceRow, 0)

		for rows.Next() {
			var row sourceRow
			if err := rows.Scan(&row.timestamp, &row.value, &row.windowMS); err != nil {
				return nil, fmt.Errorf("scan raw source row: %w", err)
			}

			result = append(result, row)
		}

		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("iterate raw source rows: %w", err)
		}

		return result, nil
	}

	//nolint:gosec // Source table is selected by makeRollupSpec.
	statement := fmt.Sprintf(`SELECT bucket_start, min_value, max_value, avg_value, sum_value, count,
       first_value, last_value, increase_value, window_ms
FROM %s
WHERE queue_id = ? AND metric_name = ? AND labels = ? AND metric_kind = ?
  AND bucket_start >= ? AND bucket_start < ?
ORDER BY bucket_start, id`, spec.sourceTable)

	rows, err := tx.QueryContext(ctx, statement, identity.subjectID, identity.metricName, identity.labels,
		string(identity.kind), from, to)
	if err != nil {
		return nil, fmt.Errorf("query aggregate source rows: %w", err)
	}
	defer rows.Close()

	result := make([]sourceRow, 0)

	for rows.Next() {
		var (
			row                   sourceRow
			first, last, increase sql.NullFloat64
		)
		if err := rows.Scan(&row.timestamp, &row.min, &row.max, &row.avg, &row.sum, &row.count,
			&first, &last, &increase, &row.windowMS); err != nil {
			return nil, fmt.Errorf("scan aggregate source row: %w", err)
		}

		row.first, row.firstOK = first.Float64, first.Valid
		row.last, row.lastOK = last.Float64, last.Valid
		row.increase, row.increaseOK = increase.Float64, increase.Valid
		result = append(result, row)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate aggregate source rows: %w", err)
	}

	return result, nil
}

type coverageStart struct {
	bucketStart int64
	intervalMS  int64
}

func loadCoverageStarts(
	ctx context.Context,
	tx *sql.Tx,
	resolution Resolution,
	identity seriesIdentity,
	from, to int64,
) ([]coverageStart, error) {
	rows, err := tx.QueryContext(ctx, `SELECT bucket_start, sample_interval_ms FROM telemetry_coverage
WHERE resolution = ? AND subject_id = ? AND metric_name = ? AND labels = ? AND metric_kind = ?
  AND bucket_start >= ? AND bucket_start < ?
ORDER BY bucket_start`, string(resolution), identity.subjectID, identity.metricName, identity.labels,
		string(identity.kind), from, to)
	if err != nil {
		return nil, fmt.Errorf("query coverage starts: %w", err)
	}
	defer rows.Close()

	result := make([]coverageStart, 0)

	for rows.Next() {
		var coverage coverageStart
		if err := rows.Scan(&coverage.bucketStart, &coverage.intervalMS); err != nil {
			return nil, fmt.Errorf("scan coverage start: %w", err)
		}

		result = append(result, coverage)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate coverage starts: %w", err)
	}

	return result, nil
}

func coverageInterval(coverage []coverageStart, fallback int64) int64 {
	if fallback > 0 {
		return fallback
	}

	if len(coverage) > 0 {
		return coverage[0].intervalMS
	}

	return fallback
}

func coverageIsComplete(coverage []coverageStart, from, to, interval int64) bool {
	if interval <= 0 || (to-from)%interval != 0 || len(coverage) != int((to-from)/interval) {
		return false
	}

	for index, item := range coverage {
		if item.intervalMS != interval || item.bucketStart != from+int64(index)*interval {
			return false
		}
	}

	return true
}

//nolint:gocritic // The value pointer and completeness flag distinguish zero from an uncovered baseline.
func loadAdjacentRawCounterBaseline(
	ctx context.Context,
	tx *sql.Tx,
	identity seriesIdentity,
	bucketStart, interval int64,
) (*float64, bool, error) {
	if interval <= 0 {
		return nil, false, nil
	}

	priorBucket := bucketStart - interval

	var value float64

	err := tx.QueryRowContext(ctx, `SELECT r.metric_value
FROM metrics_raw r
JOIN telemetry_coverage c
  ON c.resolution = 'raw' AND c.bucket_start = r.timestamp AND c.subject_id = r.queue_id
 AND c.metric_name = r.metric_name AND c.labels = r.labels AND c.metric_kind = r.metric_kind
WHERE r.timestamp = ? AND r.queue_id = ? AND r.metric_name = ? AND r.labels = ? AND r.metric_kind = ?
  AND c.sample_interval_ms = ?
ORDER BY r.id DESC LIMIT 1`, priorBucket, identity.subjectID, identity.metricName, identity.labels,
		string(identity.kind), interval).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}

	if err != nil {
		return nil, false, fmt.Errorf("query adjacent counter baseline: %w", err)
	}

	return &value, true, nil
}

//nolint:cyclop // Each metric kind has deliberately distinct aggregation invariants.
func aggregateSourceRows(
	kind MetricKind, sourceResolution Resolution, rows []sourceRow, previous *float64,
) (rolledAggregate, error) {
	aggregate := rolledAggregate{usable: true}

	if sourceResolution == ResolutionRaw {
		return aggregateRawRows(kind, rows, previous)
	}

	for _, row := range rows {
		if !row.firstOK || !row.lastOK || row.count <= 0 {
			aggregate.usable = false

			continue
		}

		if kind == MetricKindCounter && !row.increaseOK {
			aggregate.usable = false

			continue
		}

		if kind == MetricKindRate && row.windowMS <= 0 {
			return aggregate, fmt.Errorf("rate child at %d has non-positive window_ms", row.timestamp)
		}

		if !aggregate.hasRows {
			aggregate.first = row.first
			aggregate.min = row.min
			aggregate.max = row.max
			aggregate.hasRows = true
		}

		aggregate.last = row.last
		aggregate.min = math.Min(aggregate.min, row.min)
		aggregate.max = math.Max(aggregate.max, row.max)
		aggregate.sum += row.sum

		aggregate.count += row.count
		if kind == MetricKindCounter {
			aggregate.increase += row.increase
		}

		if kind == MetricKindRate {
			aggregate.weightedRateSum += row.avg * float64(row.windowMS)
			aggregate.windowMS += row.windowMS
		}
	}

	if aggregate.hasRows {
		if kind == MetricKindRate {
			aggregate.avg = aggregate.weightedRateSum / float64(aggregate.windowMS)
		} else {
			aggregate.avg = aggregate.sum / float64(aggregate.count)
		}
	}

	return aggregate, nil
}

//nolint:cyclop,nestif // Ordered reset and first-sample handling is clearest beside the shared accumulator.
func aggregateRawRows(kind MetricKind, rows []sourceRow, previous *float64) (rolledAggregate, error) {
	aggregate := rolledAggregate{usable: true}

	for _, row := range rows {
		if kind == MetricKindRate && row.windowMS <= 0 {
			return aggregate, fmt.Errorf("raw rate at %d has non-positive window_ms", row.timestamp)
		}

		if !aggregate.hasRows {
			aggregate.first = row.value
			aggregate.last = row.value
			aggregate.min = row.value
			aggregate.max = row.value
			aggregate.sum = row.value
			aggregate.count = 1
			aggregate.hasRows = true

			if kind == MetricKindCounter && previous != nil {
				if row.value >= *previous {
					aggregate.increase = row.value - *previous
				} else {
					aggregate.increase = row.value
				}
			}
		} else {
			if kind == MetricKindCounter {
				if row.value >= aggregate.last {
					aggregate.increase += row.value - aggregate.last
				} else {
					aggregate.increase += row.value
				}
			}

			aggregate.last = row.value
			aggregate.min = math.Min(aggregate.min, row.value)
			aggregate.max = math.Max(aggregate.max, row.value)
			aggregate.sum += row.value
			aggregate.count++
		}

		if kind == MetricKindRate {
			aggregate.weightedRateSum += row.value * float64(row.windowMS)
			aggregate.windowMS += row.windowMS
		}
	}

	if aggregate.hasRows {
		if kind == MetricKindRate {
			aggregate.avg = aggregate.weightedRateSum / float64(aggregate.windowMS)
		} else {
			aggregate.avg = aggregate.sum / float64(aggregate.count)
		}
	}

	return aggregate, nil
}

func upsertAggregate(
	ctx context.Context,
	tx *sql.Tx,
	spec rollupSpec,
	bucketStart int64,
	identity seriesIdentity,
	aggregate rolledAggregate,
) error {
	var increase any
	if identity.kind == MetricKindCounter {
		increase = aggregate.increase
	}

	//nolint:gosec // Target table is selected by makeRollupSpec.
	statement := fmt.Sprintf(`INSERT INTO %s
    (bucket_start, queue_id, metric_name, min_value, max_value, avg_value, sum_value, count,
     labels, metric_kind, first_value, last_value, increase_value, window_ms)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(bucket_start, queue_id, metric_name, labels, metric_kind) DO UPDATE SET
    min_value = excluded.min_value,
    max_value = excluded.max_value,
    avg_value = excluded.avg_value,
    sum_value = excluded.sum_value,
    count = excluded.count,
    first_value = excluded.first_value,
    last_value = excluded.last_value,
    increase_value = excluded.increase_value,
    window_ms = excluded.window_ms`, spec.targetTable)
	if _, err := tx.ExecContext(ctx, statement, bucketStart, identity.subjectID, identity.metricName,
		aggregate.min, aggregate.max, aggregate.avg, aggregate.sum, aggregate.count, identity.labels,
		string(identity.kind), aggregate.first, aggregate.last, increase, aggregate.windowMS); err != nil {
		return fmt.Errorf("upsert aggregate: %w", err)
	}

	return nil
}
