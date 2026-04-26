package pgstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/heartwilltell/hc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue/pgstore/sqlcgen"
	"github.com/marsolab/plainq/internal/server/service/telemetry"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/idkit"
	"github.com/marsolab/servekit/logkit"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Compile-time check that Storage implements hc.HealthChecker.
var _ hc.HealthChecker = (*Storage)(nil)

const (
	gcTimeout                            = 30 * time.Minute
	msgVisibilityTimeout                 = 30 * time.Second
	msgRetentionPeriod                   = 7 * 24 * time.Hour
	maxReceiveAttempts                   = 5
	queuePropsCacheSize                  = 1000
	queuePropsCacheFillingTimeout        = 30 * time.Second
	defaultPageSize               uint32 = 10
)

// Option configures a Storage.
type Option func(*Storage)

// WithGCTimeout sets the garbage collection interval.
func WithGCTimeout(to time.Duration) Option { return func(s *Storage) { s.gcTimeout = to } }

// WithLogger sets the logger.
func WithLogger(logger *slog.Logger) Option { return func(s *Storage) { s.logger = logger } }

// Storage is the PostgreSQL-backed implementation of queue.Storage. It
// mirrors litestore: sqlc-generated code handles queue_properties CRUD, while
// per-queue message tables are managed via hand-written SQL (sqlc cannot
// generate queries against dynamic table identifiers).
type Storage struct {
	pool    *pgxpool.Pool
	queries *sqlcgen.Queries
	logger  *slog.Logger

	cache               *QueuePropsCache
	cacheFillingTimeout time.Duration

	gcTimeout time.Duration
	observer  telemetry.Observer
	stop      func()
}

// New returns a PostgreSQL-backed queue storage, pre-populates the queue
// properties cache, and starts the GC loop.
func New(pool *pgxpool.Pool, options ...Option) (*Storage, error) {
	if pool == nil {
		return nil, errors.New("pool is nil")
	}

	s := Storage{
		pool:    pool,
		queries: sqlcgen.New(pool),
		logger:  logkit.NewNop(),

		cache:               NewQueuePropsCache(queuePropsCacheSize),
		cacheFillingTimeout: queuePropsCacheFillingTimeout,

		gcTimeout: gcTimeout,
		observer:  telemetry.NewObserver(),
	}

	for _, option := range options {
		option(&s)
	}

	prepareCtx, prepareCancel := context.WithTimeout(context.Background(), s.cacheFillingTimeout)
	defer prepareCancel()

	count, countErr := s.countQueues(prepareCtx)
	if countErr != nil {
		return nil, fmt.Errorf("count existing queues: %w", countErr)
	}

	if s.observer.QueuesExist().Get() <= 0 {
		s.observer.QueuesExist().Add(count)
	}

	if err := s.fillCache(prepareCtx, ""); err != nil {
		return nil, fmt.Errorf("filling cache: %w", err)
	}

	ctx, stop := context.WithCancel(context.Background())
	s.stop = stop

	go s.gc(ctx)

	return &s, nil
}

func (s *Storage) CreateQueue(ctx context.Context, input *v1.CreateQueueRequest) (_ *v1.CreateQueueResponse, sErr error) {
	queueID := idkit.XID()

	if input.QueueName == "" {
		return nil, fmt.Errorf("%w: queue name is empty", errkit.ErrInvalidArgument)
	}

	if input.MaxReceiveAttempts == 0 {
		input.MaxReceiveAttempts = maxReceiveAttempts
	}

	if input.RetentionPeriodSeconds == 0 {
		input.RetentionPeriodSeconds = uint64(msgRetentionPeriod.Seconds())
	}

	if input.VisibilityTimeoutSeconds == 0 {
		input.VisibilityTimeoutSeconds = uint64(msgVisibilityTimeout.Seconds())
	}

	tx, txErr := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if txErr != nil {
		return nil, fmt.Errorf(fmtBeginTxError, txErr)
	}

	defer func() { sErr = errors.Join(sErr, rollback(ctx, tx)) }()

	if err := s.queries.WithTx(tx).InsertQueueProperties(ctx, sqlcgen.InsertQueuePropertiesParams{
		QueueID:                  queueID,
		QueueName:                input.QueueName,
		RetentionPeriodSeconds:   int32(input.RetentionPeriodSeconds),   //nolint:gosec // retention seconds is bounded by validation.
		VisibilityTimeoutSeconds: int32(input.VisibilityTimeoutSeconds), //nolint:gosec // visibility timeout is bounded by validation.
		MaxReceiveAttempts:       int32(input.MaxReceiveAttempts),       //nolint:gosec // max receive attempts is bounded by validation.
		DropPolicy:               int32(input.EvictionPolicy),
		DeadLetterQueueID:        toPgText(input.DeadLetterQueueId),
	}); err != nil {
		return nil, fmt.Errorf("create queue properties record: %w", err)
	}

	if _, err := tx.Exec(ctx, queryCreateQueueTable(queueID)); err != nil {
		return nil, fmt.Errorf("create queue table: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	s.cache.put(QueueProps{
		ID:                       queueID,
		Name:                     input.QueueName,
		RetentionPeriodSeconds:   input.RetentionPeriodSeconds,
		VisibilityTimeoutSeconds: input.VisibilityTimeoutSeconds,
		MaxReceiveAttempts:       input.MaxReceiveAttempts,
		EvictionPolicy:           uint32(input.EvictionPolicy), //nolint:gosec // EvictionPolicy enum is non-negative.
		DeadLetterQueueID:        input.DeadLetterQueueId,
	})

	s.observer.QueuesExist().Inc()

	return &v1.CreateQueueResponse{QueueId: queueID}, nil
}

func (s *Storage) ListQueues(ctx context.Context, input *v1.ListQueuesRequest) (*v1.ListQueuesResponse, error) {
	pageSize := input.Limit
	if pageSize <= 0 {
		pageSize = int32(defaultPageSize)
	}

	limit := pageSize + 1

	query := queryListQueues(limit, input.Cursor, input.OrderBy, input.SortBy)

	queues, err := s.listQueues(ctx, query, uint32(limit))
	if err != nil {
		return nil, fmt.Errorf("list queues: %w", err)
	}

	var (
		nextCursor string
		hasMore    bool
	)

	if len(queues) > int(pageSize) {
		nextCursor = queues[len(queues)-2].QueueId
		queues = queues[:len(queues)-1]
		hasMore = true
	}

	return &v1.ListQueuesResponse{
		Queues:     queues,
		NextCursor: nextCursor,
		HasMore:    hasMore,
	}, nil
}

func (s *Storage) DescribeQueue(ctx context.Context, input *v1.DescribeQueueRequest) (*v1.DescribeQueueResponse, error) {
	switch {
	case input.QueueId != "":
		if p, ok := s.cache.getByID(input.QueueId); ok {
			return propsToProto(p), nil
		}

	case input.QueueName != "":
		if p, ok := s.cache.getByName(input.QueueName); ok {
			return propsToProto(p), nil
		}
	}

	var (
		row sqlcgen.QueueProperty
		err error
	)

	switch {
	case input.QueueId != "":
		row, err = s.queries.GetQueuePropertiesByID(ctx, input.QueueId)

	case input.QueueName != "":
		row, err = s.queries.GetQueuePropertiesByName(ctx, input.QueueName)

	default:
		return nil, fmt.Errorf("%w: queue_id or queue_name should be specified", pqerr.ErrInvalidInput)
	}

	if err != nil {
		return nil, fmt.Errorf("get queue properties: %w", err)
	}

	output := queuePropertyToProto(row)

	s.cache.put(propsFromProto(output))

	return output, nil
}

func (s *Storage) PurgeQueue(ctx context.Context, input *v1.PurgeQueueRequest) (_ *v1.PurgeQueueResponse, sErr error) {
	queueID := input.GetQueueId()

	tx, txErr := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if txErr != nil {
		return nil, fmt.Errorf(fmtBeginTxError, txErr)
	}

	defer func() { sErr = errors.Join(sErr, rollback(ctx, tx)) }()

	var count uint64
	if err := tx.QueryRow(ctx, queryCountMessages(queueID)).Scan(&count); err != nil {
		return nil, fmt.Errorf("purge queue %q count messages: %w", queueID, err)
	}

	tag, err := tx.Exec(ctx, queryPurgeQueue(queueID))
	if err != nil {
		return nil, fmt.Errorf("purge queue %q table: %w", queueID, err)
	}

	if rows := tag.RowsAffected(); rows != int64(count) {
		return nil, fmt.Errorf("purge queue %q count (%d) != rows affected (%d)", queueID, count, rows)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	return &v1.PurgeQueueResponse{}, nil
}

func (s *Storage) DeleteQueue(ctx context.Context, input *v1.DeleteQueueRequest) (_ *v1.DeleteQueueResponse, sErr error) {
	queueID := input.GetQueueId()

	props, ok := s.cache.getByID(queueID)
	if !ok {
		return nil, fmt.Errorf("queue props (id: %q) not cached", queueID)
	}

	tx, txErr := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if txErr != nil {
		return nil, fmt.Errorf(fmtBeginTxError, txErr)
	}

	defer func() { sErr = errors.Join(sErr, rollback(ctx, tx)) }()

	rows, delErr := s.queries.WithTx(tx).DeleteQueueProperties(ctx, queueID)
	if delErr != nil {
		return nil, fmt.Errorf("delete queue %q info record: %w", queueID, delErr)
	}

	if rows < 1 {
		return nil, fmt.Errorf("delete queue %q info record: %w", queueID, pqerr.ErrNotFound)
	}

	if _, err := tx.Exec(ctx, queryDeleteQueueTable(queueID)); err != nil {
		return nil, fmt.Errorf("drop queue %q table: %w", queueID, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	s.cache.delete(props.ID, props.Name)

	s.observer.QueuesExist().Dec()

	return &v1.DeleteQueueResponse{}, nil
}

func (s *Storage) Send(ctx context.Context, input *v1.SendRequest) (_ *v1.SendResponse, sErr error) {
	queueID := input.GetQueueId()
	s.cache.getByID(queueID)

	tx, txErr := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if txErr != nil {
		return nil, fmt.Errorf(fmtBeginTxError, txErr)
	}

	defer func() { sErr = errors.Join(sErr, rollback(ctx, tx)) }()

	insertSQL := queryInsertMessages(queueID)

	output := v1.SendResponse{
		MessageIds: make([]string, 0, len(input.Messages)),
	}

	for _, m := range input.GetMessages() {
		msgID := idkit.ULID()

		if _, err := tx.Exec(ctx, insertSQL, msgID, m.Body); err != nil {
			return nil, fmt.Errorf("insert message: %w", err)
		}

		output.MessageIds = append(output.MessageIds, msgID)

		s.observer.MessagesSentBytes(queueID).Add(uint64(len(m.Body)))
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	s.observer.MessagesSent(queueID).Add(uint64(len(output.MessageIds)))

	return &output, nil
}

//nolint:cyclop // Complex message receiving with visibility timeout and polling.
func (s *Storage) Receive(ctx context.Context, input *v1.ReceiveRequest) (_ *v1.ReceiveResponse, sErr error) {
	queueID := input.GetQueueId()

	info, describeErr := s.DescribeQueue(ctx, &v1.DescribeQueueRequest{QueueId: queueID})
	if describeErr != nil {
		return nil, fmt.Errorf("describe queue (id: %q): %w", queueID, describeErr)
	}

	tx, txErr := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if txErr != nil {
		return nil, fmt.Errorf(fmtBeginTxError, txErr)
	}

	defer func() { sErr = errors.Join(sErr, rollback(ctx, tx)) }()

	limit := input.BatchSize
	if limit == 0 {
		limit = 1
	}

	rows, queryErr := tx.Query(ctx, querySelectMessages(queueID), info.MaxReceiveAttempts, limit)
	if queryErr != nil {
		return nil, fmt.Errorf("select query: %w", queryErr)
	}

	output := v1.ReceiveResponse{
		Messages: make([]*v1.ReceiveMessage, 0, input.BatchSize),
	}

	for rows.Next() {
		var m v1.ReceiveMessage

		if err := rows.Scan(&m.Id, &m.Body); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan message record: %w", err)
		}

		output.Messages = append(output.Messages, &m)
	}

	rows.Close()

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate messages: %w", err)
	}

	//nolint:gosec // VisibilityTimeoutSeconds is bounded by validation; conversion to int64 is safe.
	visibleAt := time.Now().UTC().Add(time.Duration(info.VisibilityTimeoutSeconds) * time.Second)

	updateSQL := queryUpdateMessages(queueID)

	for _, m := range output.Messages {
		if _, err := tx.Exec(ctx, updateSQL, visibleAt, m.Id); err != nil {
			return nil, fmt.Errorf("update message record: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	if len(output.Messages) == 0 {
		s.observer.EmptyReceives(queueID).Inc()
	}

	s.observer.MessagesReceived(queueID).Add(uint64(len(output.Messages)))

	return &output, nil
}

func (s *Storage) Delete(ctx context.Context, input *v1.DeleteRequest) (_ *v1.DeleteResponse, sErr error) {
	queueID := input.GetQueueId()

	tx, txErr := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if txErr != nil {
		return nil, fmt.Errorf(fmtBeginTxError, txErr)
	}

	defer func() { sErr = errors.Join(sErr, rollback(ctx, tx)) }()

	deleteSQL := queryDeleteMessage(queueID)

	output := v1.DeleteResponse{
		Successful: make([]string, 0, len(input.MessageIds)),
		Failed:     make([]*v1.DeleteFailure, 0, 1),
	}

	for _, id := range input.GetMessageIds() {
		if _, err := tx.Exec(ctx, deleteSQL, id); err != nil {
			output.Failed = append(output.Failed, &v1.DeleteFailure{MessageId: id})

			continue
		}

		if xID, err := idkit.ParseXID(id); err == nil {
			s.observer.TimeInQueue(queueID).Dur(xID.Time())
		} else {
			panic(fmt.Errorf(
				"queue (id: %q) contains messages with invalid id (id: %q): %s",
				queueID, id, err.Error(),
			))
		}

		output.Successful = append(output.Successful, id)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	s.observer.MessagesDeleted(queueID).Add(uint64(len(output.Successful)))

	return &output, nil
}

// Health implements hc.HealthChecker.
func (s *Storage) Health(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("health check: %w", err)
	}

	return nil
}

func (s *Storage) Close() error {
	if s.stop != nil {
		s.stop()
	}

	return nil
}

func (s *Storage) listQueues(ctx context.Context, query string, pageSize uint32) ([]*v1.DescribeQueueResponse, error) {
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("execute query: %w", err)
	}

	defer rows.Close()

	queues := make([]*v1.DescribeQueueResponse, 0, pageSize)

	for rows.Next() {
		var (
			info      v1.DescribeQueueResponse
			createdAt time.Time
			gcAt      time.Time
			dlqID     pgtype.Text
		)

		if scanErr := rows.Scan(
			&info.QueueId,
			&info.QueueName,
			&createdAt,
			&gcAt,
			&info.RetentionPeriodSeconds,
			&info.VisibilityTimeoutSeconds,
			&info.MaxReceiveAttempts,
			&info.EvictionPolicy,
			&dlqID,
		); scanErr != nil {
			return nil, fmt.Errorf("row scan: %w", scanErr)
		}

		info.CreatedAt = timestamppb.New(createdAt)
		info.DeadLetterQueueId = dlqID.String

		if info.EvictionPolicy == v1.EvictionPolicy_EVICTION_POLICY_UNSPECIFIED {
			info.EvictionPolicy = v1.EvictionPolicy_EVICTION_POLICY_DROP
		}

		queues = append(queues, &info)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate queues: %w", err)
	}

	return queues, nil
}

func (s *Storage) fillCache(ctx context.Context, cursor string) error {
	s.logger.Debug("Listing queues to fill the cache")

	queues, listErr := s.ListQueues(ctx, &v1.ListQueuesRequest{Cursor: cursor})
	if listErr != nil {
		return fmt.Errorf("filling cache: %w", listErr)
	}

	for _, q := range queues.GetQueues() {
		s.cache.put(QueueProps{
			ID:                       q.QueueId,
			Name:                     q.QueueName,
			CreatedAt:                q.CreatedAt.AsTime().UTC(),
			RetentionPeriodSeconds:   q.RetentionPeriodSeconds,
			VisibilityTimeoutSeconds: q.VisibilityTimeoutSeconds,
			MaxReceiveAttempts:       q.MaxReceiveAttempts,
			EvictionPolicy:           uint32(q.EvictionPolicy), //nolint:gosec // EvictionPolicy enum is non-negative.
			DeadLetterQueueID:        q.DeadLetterQueueId,
		})
	}

	if queues.HasMore {
		return s.fillCache(ctx, queues.NextCursor)
	}

	return nil
}

func (s *Storage) countQueues(ctx context.Context) (uint64, error) {
	count, err := s.queries.CountQueueProperties(ctx)
	if err != nil {
		return 0, err
	}

	if count < 0 {
		return 0, nil
	}

	return uint64(count), nil
}

// queuePropertyToProto converts a sqlc row to the service-layer response.
func queuePropertyToProto(row sqlcgen.QueueProperty) *v1.DescribeQueueResponse {
	resp := v1.DescribeQueueResponse{
		QueueId:                  row.QueueID,
		QueueName:                row.QueueName,
		RetentionPeriodSeconds:   uint64(row.RetentionPeriodSeconds),   //nolint:gosec // retention seconds is non-negative.
		VisibilityTimeoutSeconds: uint64(row.VisibilityTimeoutSeconds), //nolint:gosec // visibility timeout is non-negative.
		MaxReceiveAttempts:       uint32(row.MaxReceiveAttempts),       //nolint:gosec // max receive attempts is non-negative.
		EvictionPolicy:           v1.EvictionPolicy(row.DropPolicy),
		DeadLetterQueueId:        row.DeadLetterQueueID.String,
	}

	if row.CreatedAt.Valid {
		resp.CreatedAt = timestamppb.New(row.CreatedAt.Time)
	}

	return &resp
}

func toPgText(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}

	return pgtype.Text{String: s, Valid: true}
}

func toTimestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

// rollback is a small wrapper that suppresses the "tx already done" error
// (returned when Commit has succeeded) while reporting anything else.
func rollback(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("rollback transaction: %w", err)
	}

	return nil
}
