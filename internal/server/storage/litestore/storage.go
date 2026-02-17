package litestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/heartwilltell/hc"
	v1 "github.com/plainq/plainq/internal/server/schema/v1"
	"github.com/plainq/plainq/internal/server/telemetry"
	"github.com/plainq/plainq/internal/shared/pqerr"
	"github.com/plainq/servekit/dbkit/litekit"
	"github.com/plainq/servekit/errkit"
	"github.com/plainq/servekit/idkit"
	"github.com/plainq/servekit/logkit"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Compilation time check that Storage implements the hc.HealthChecker.
var _ hc.HealthChecker = (*Storage)(nil)

const (
	// gcTimeout represents default timeout between garbage collection runs.
	gcTimeout = 30 * time.Minute

	// msgVisibilityTimeout represents the visibility timeout for messages,
	// which determines how long a message remains invisible to receivers after it has been received.
	msgVisibilityTimeout = 30 * time.Second

	// msgRetentionPeriod represents the default retention period for messages,
	// which is set to 7 days.
	msgRetentionPeriod = 7 * 24 * time.Hour

	// maxReceiveAttempts represents the maximum number of receive attempts for a message.
	maxReceiveAttempts = 5

	// queuePropsCacheSize represents the size of the queue properties cache.
	queuePropsCacheSize = 1000

	// queuePropsCacheFillingTimeout represents the default timeout duration
	// for filling the queue properties cache.
	queuePropsCacheFillingTimeout = 30 * time.Second

	// defaultPageSize represents the default page size used for listing queues.
	defaultPageSize uint32 = 10
)

// Option represents an optional functions which configures the Storage.
type Option func(o *Storage)

// WithGCTimeout sets the timeout for garbage collection.
func WithGCTimeout(to time.Duration) Option {
	return func(s *Storage) { s.gcTimeout = to }
}

// WithLogger sets the Storage logger.
func WithLogger(logger *slog.Logger) Option {
	return func(o *Storage) { o.logger = logger }
}

// Storage represents a storage system.
// This struct holds the necessary configurations and dependencies for the storage.
type Storage struct {
	db     *litekit.Conn
	logger *slog.Logger

	querier querier

	// cache holds information about queues properties.
	cache *QueuePropsCache

	// cacheFillingTimeout represents duration after which
	// the cache filling procedure will be considered as failed.
	cacheFillingTimeout time.Duration

	// gcTimeout represents timeout duration between the garbage collection schedules.
	gcTimeout time.Duration

	// observer is responsible for observing certain events and transform them to metrics.
	observer telemetry.Observer

	// stop is a function that can be called to stop the telemetry and garbage collection processes.
	stop func()
}

// New returns a pointer to a new instance of Storage with a pointer to sql.DB struct.
func New(db *litekit.Conn, options ...Option) (*Storage, error) {
	s := Storage{
		db:     db,
		logger: logkit.NewNop(),

		querier: newQuerier(),

		cache:               NewQueuePropsCache(queuePropsCacheSize),
		cacheFillingTimeout: queuePropsCacheFillingTimeout,

		gcTimeout: gcTimeout,

		observer: telemetry.NewObserver(),

		stop: nil,
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

	tx, txErr := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if txErr != nil {
		return nil, fmt.Errorf(fmtBeginTxError, txErr)
	}

	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			sErr = errors.Join(sErr, fmt.Errorf("rollback transaction: %w", err))
		}
	}()

	if _, err := tx.ExecContext(ctx, queryInsertQueuePropRecord,
		queueID,
		input.QueueName,
		input.RetentionPeriodSeconds,
		input.VisibilityTimeoutSeconds,
		input.MaxReceiveAttempts,
		input.EvictionPolicy,
		input.DeadLetterQueueId,
	); err != nil {
		return nil, fmt.Errorf("create queue properties record: execute query: %w", err)
	}

	if _, err := tx.ExecContext(ctx, queryCreateQueueTable(queueID)); err != nil {
		return nil, fmt.Errorf("create queue table: execute query: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf(fmtCommitTxError, err)
	}

	props := QueueProps{
		ID:                       queueID,
		Name:                     input.QueueName,
		RetentionPeriodSeconds:   input.RetentionPeriodSeconds,
		VisibilityTimeoutSeconds: input.VisibilityTimeoutSeconds,
		MaxReceiveAttempts:       input.MaxReceiveAttempts,
		EvictionPolicy:           uint32(input.EvictionPolicy), //nolint:gosec // G115: EvictionPolicy values are small enum constants
		DeadLetterQueueID:        input.DeadLetterQueueId,
	}

	s.cache.put(props)

	output := v1.CreateQueueResponse{
		QueueId: queueID,
	}

	s.observer.QueuesExist().Inc()

	return &output, nil
}

func (s *Storage) ListQueues(ctx context.Context, input *v1.ListQueuesRequest) (_ *v1.ListQueuesResponse, sErr error) {
	// Set default page size if not specified.
	pageSize := input.Limit
	if pageSize <= 0 {
		pageSize = int32(defaultPageSize)
	}

	// The +1 is used to fetch one extra item to determine if there are more results.
	limit := pageSize + 1

	query := queryListQueues(limit, input.Cursor, input.OrderBy, input.SortBy)

	queues, listErr := s.queryQueues(ctx, query, uint32(limit)) //nolint:gosec // G115: limit is always positive (pageSize + 1)
	if listErr != nil {
		return nil, fmt.Errorf("list queues: %w", listErr)
	}

	var (
		nextCursor string
		hasMore    bool
	)

	// If we fetched more items than requested page size,
	// we know there are more results and we can set the next page token.
	if len(queues) > int(pageSize) {
		// Remove the extra item before returning.
		lastItem := queues[len(queues)-2]
		nextCursor = lastItem.QueueId
		queues = queues[:len(queues)-1]
		hasMore = true
	}

	output := v1.ListQueuesResponse{
		Queues:     queues,
		NextCursor: nextCursor,
		HasMore:    hasMore,
	}

	return &output, nil
}

func (s *Storage) DescribeQueue(ctx context.Context, input *v1.DescribeQueueRequest) (_ *v1.DescribeQueueResponse, sErr error) {
	switch {
	case input.QueueId != "":
		p, ok := s.cache.getByID(input.QueueId)
		if !ok {
			break
		}

		return propsToProto(p), nil

	case input.QueueName != "":
		p, ok := s.cache.getByName(input.QueueName)
		if !ok {
			break
		}

		return propsToProto(p), nil
	}

	tx, txErr := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if txErr != nil {
		return nil, fmt.Errorf(fmtBeginTxError, txErr)
	}

	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			sErr = errors.Join(sErr, fmt.Errorf("rollback transaction: %w", err))
		}
	}()

	var where string

	switch {
	case input.QueueId != "":
		where = "queue_id = '" + input.QueueId + "'"

	case input.QueueName != "":
		where = "queue_name = '" + input.QueueName + "'"

	default:
		return nil, fmt.Errorf("%w: queue_id or queue_name should be specified", pqerr.ErrInvalidInput)
	}

	var (
		output    v1.DescribeQueueResponse
		createdAt time.Time
		gcAt      time.Time
	)

	query := queueDescribeQueueProps(where)

	if err := s.db.QueryRowContext(ctx, query).Scan(
		&output.QueueId,
		&output.QueueName,
		&createdAt,
		&gcAt,
		&output.RetentionPeriodSeconds,
		&output.VisibilityTimeoutSeconds,
		&output.MaxReceiveAttempts,
		&output.EvictionPolicy,
		&output.DeadLetterQueueId,
	); err != nil {
		return nil, fmt.Errorf("execute query (SQL: %s): %w", query, err)
	}

	output.CreatedAt = timestamppb.New(createdAt)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf(fmtCommitTxError, err)
	}

	s.cache.put(propsFromProto(&output))

	return &output, nil
}

func (s *Storage) PurgeQueue(ctx context.Context, input *v1.PurgeQueueRequest) (_ *v1.PurgeQueueResponse, sErr error) {
	tx, txErr := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if txErr != nil {
		return nil, fmt.Errorf(fmtBeginTxError, txErr)
	}

	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			sErr = errors.Join(sErr, fmt.Errorf("rollback transaction: %w", err))
		}
	}()

	queueID := input.GetQueueId()

	var count uint64
	if err := tx.QueryRowContext(ctx, queryCountMessages(queueID)).Scan(&count); err != nil {
		return nil, fmt.Errorf("purge queue %q count messages: %w", queueID, err)
	}

	purgeQueueRes, purgeQueueErr := tx.ExecContext(ctx, queryPurgeQueue(queueID))
	if purgeQueueErr != nil {
		return nil, fmt.Errorf("purge queue %q table: %w", queueID, purgeQueueErr)
	}

	rows, rowsErr := purgeQueueRes.RowsAffected()
	if rowsErr != nil {
		return nil, fmt.Errorf("purge queue %q info record: %w", queueID, rowsErr)
	}

	if count > math.MaxInt64 || rows != int64(count) {
		return nil, fmt.Errorf("purge queue %q count (%d) != rows affected (%d) by purge", queueID, count, rows)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf(fmtCommitTxError, err)
	}

	output := v1.PurgeQueueResponse{}

	return &output, nil
}

func (s *Storage) DeleteQueue(ctx context.Context, input *v1.DeleteQueueRequest) (_ *v1.DeleteQueueResponse, sErr error) {
	queueID := input.GetQueueId()

	props, ok := s.cache.getByID(queueID)
	if !ok {
		return nil, fmt.Errorf("queue props (id: %q) not cached", queueID)
	}

	tx, txErr := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if txErr != nil {
		return nil, fmt.Errorf(fmtBeginTxError, txErr)
	}

	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			sErr = errors.Join(sErr, fmt.Errorf("rollback transaction: %w", err))
		}
	}()

	queueInfoRes, queueHeaderErr := tx.ExecContext(ctx, queryDeleteQueuePropRecord, queueID)
	if queueHeaderErr != nil {
		return nil, fmt.Errorf("delete queue %q info record: %w", queueID, queueHeaderErr)
	}

	rows, rowsErr := queueInfoRes.RowsAffected()
	if rowsErr != nil {
		return nil, fmt.Errorf("delete queue %q info record: %w", queueID, rowsErr)
	}

	if rows < 1 {
		return nil, fmt.Errorf("delete queue %q info record: %w", queueID, pqerr.ErrNotFound)
	}

	if _, err := tx.ExecContext(ctx, queryDeleteQueueTable(queueID)); err != nil {
		return nil, fmt.Errorf("drop queue %q table: %w", queueID, err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf(fmtCommitTxError, err)
	}

	s.cache.delete(props.ID, props.Name)

	output := v1.DeleteQueueResponse{}

	s.observer.QueuesExist().Dec()

	return &output, nil
}

func (s *Storage) Send(ctx context.Context, input *v1.SendRequest) (_ *v1.SendResponse, sErr error) {
	queueID := input.GetQueueId()

	s.cache.getByID(queueID)

	tx, txErr := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if txErr != nil {
		return nil, fmt.Errorf(fmtBeginTxError, txErr)
	}

	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			sErr = errors.Join(sErr, fmt.Errorf("rollback transaction: %w", err))
		}
	}()

	stmt, prepareErr := tx.PrepareContext(ctx, queryInsertMessages(queueID))
	if prepareErr != nil {
		return nil, fmt.Errorf("prepare statement: %w", prepareErr)
	}

	defer func() {
		if err := stmt.Close(); err != nil {
			sErr = errors.Join(sErr, fmt.Errorf("close prepared statement: %w", err))
		}
	}()

	output := v1.SendResponse{
		MessageIds: make([]string, 0, len(input.Messages)),
	}

	for _, m := range input.GetMessages() {
		msgID := idkit.ULID()

		if _, err := stmt.ExecContext(ctx, msgID, m.Body); err != nil {
			return nil, fmt.Errorf("insert message: %w", err)
		}

		output.MessageIds = append(output.MessageIds, msgID)

		s.observer.MessagesSentBytes(queueID).Add(uint64(len(m.Body)))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf(fmtCommitTxError, err)
	}

	s.observer.MessagesSent(queueID).Add(uint64(len(output.MessageIds)))

	return &output, nil
}

func (s *Storage) Receive(ctx context.Context, input *v1.ReceiveRequest) (_ *v1.ReceiveResponse, sErr error) {
	queueID := input.GetQueueId()

	info, describeErr := s.DescribeQueue(ctx, &v1.DescribeQueueRequest{
		QueueId: queueID,
	})
	if describeErr != nil {
		return nil, fmt.Errorf("describe queue (id: %q): %w", queueID, describeErr)
	}

	tx, txErr := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if txErr != nil {
		return nil, fmt.Errorf(fmtBeginTxError, txErr)
	}

	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			sErr = errors.Join(sErr, fmt.Errorf("rollback transaction: %w", err))
		}
	}()

	limit := input.BatchSize
	if limit == 0 {
		limit = 1
	}

	stmt, prepareErr := tx.PrepareContext(ctx, queryUpdateMessages(queueID))
	if prepareErr != nil {
		return nil, fmt.Errorf("prepare statement: %w", prepareErr)
	}

	defer func() {
		if err := stmt.Close(); err != nil {
			sErr = errors.Join(sErr, fmt.Errorf("close prepared statement: %w", err))
		}
	}()

	rows, queryErr := tx.QueryContext(ctx, querySelectMessages(queueID),
		info.MaxReceiveAttempts,
		limit,
	)
	if queryErr != nil {
		return nil, fmt.Errorf("select query: %w", queryErr)
	}

	defer func() {
		if err := rows.Close(); err != nil {
			sErr = errors.Join(sErr, fmt.Errorf("close rows: %w", err))
		}
	}()

	output := v1.ReceiveResponse{
		Messages: make([]*v1.ReceiveMessage, 0, input.BatchSize),
	}

	//nolint:gosec // G115: VisibilityTimeoutSeconds is a small duration value, well within int64 range.
	visibleAt := time.Now().UTC().Add(time.Duration(info.VisibilityTimeoutSeconds) * time.Second)

	for rows.Next() {
		var m v1.ReceiveMessage

		if err := rows.Scan(&m.Id, &m.Body); err != nil {
			return nil, fmt.Errorf("scan message record: %w", err)
		}

		if _, err := stmt.ExecContext(ctx, visibleAt, m.Id); err != nil {
			return nil, fmt.Errorf("update message record: %w", err)
		}

		output.Messages = append(output.Messages, &m)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf(fmtCommitTxError, err)
	}

	if len(output.Messages) == 0 {
		s.observer.EmptyReceives(queueID).Inc()
	}

	messagesCount := uint64(len(output.Messages))

	s.observer.MessagesReceived(queueID).Add(messagesCount)

	return &output, nil
}

func (s *Storage) Delete(ctx context.Context, input *v1.DeleteRequest) (_ *v1.DeleteResponse, sErr error) {
	queueID := input.GetQueueId()

	tx, txErr := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if txErr != nil {
		return nil, fmt.Errorf(fmtBeginTxError, txErr)
	}

	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			sErr = errors.Join(sErr, fmt.Errorf("rollback transaction: %w", err))
		}
	}()

	stmt, prepareErr := tx.PrepareContext(ctx, queryDeleteMessage(queueID))
	if prepareErr != nil {
		return nil, fmt.Errorf("prepare statement: %w", prepareErr)
	}

	defer func() {
		if err := stmt.Close(); err != nil {
			sErr = errors.Join(sErr, fmt.Errorf("close prepared statement: %w", err))
		}
	}()

	output := v1.DeleteResponse{
		Successful: make([]string, 0, len(input.MessageIds)),
		Failed:     make([]*v1.DeleteFailure, 0, 1),
	}

	for _, id := range input.GetMessageIds() {
		if _, err := stmt.ExecContext(ctx, id); err != nil {
			output.Failed = append(output.Failed, &v1.DeleteFailure{
				MessageId: id,
			})

			continue
		}

		xID, err := idkit.ParseXID(id)
		if err != nil {
			// The fact that queue contains messages with invalid ID format
			// means that something is really wrong with the queue. Looks like
			// someone has modified the storage manually.
			panic(fmt.Errorf(
				"queue (id: %q) contains messages with invalid id (id: %q): %s",
				queueID, id, err.Error(),
			))
		}

		s.observer.TimeInQueue(queueID).Dur(xID.Time())

		output.Successful = append(output.Successful, id)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf(fmtCommitTxError, err)
	}

	messagesCount := uint64(len(output.Successful))

	s.observer.MessagesDeleted(queueID).Add(messagesCount)

	return &output, nil
}

// Health implements hc.HealthChecker interface.
func (s *Storage) Health(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("health check: %w", err)
	}

	return nil
}

func (s *Storage) Close() error {
	s.stop()
	return nil
}

func (s *Storage) queryQueues(ctx context.Context, query string, pageSize uint32) (_ []*v1.DescribeQueueResponse, sErr error) {
	tx, txErr := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if txErr != nil {
		return nil, fmt.Errorf(fmtBeginTxError, txErr)
	}

	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			sErr = errors.Join(sErr, fmt.Errorf("rollback transaction: %w", err))
		}
	}()

	rows, txQueryErr := s.db.QueryContext(ctx, query)
	if txQueryErr != nil {
		return nil, fmt.Errorf("execute query (query: %q): %w", query, txQueryErr)
	}

	defer func() {
		if err := rows.Close(); err != nil {
			sErr = errors.Join(sErr, fmt.Errorf("close rows: %w", err))
		}
	}()

	queues := make([]*v1.DescribeQueueResponse, 0, pageSize)

	for rows.Next() {
		var (
			info      v1.DescribeQueueResponse
			createdAt time.Time
			gcAt      time.Time
		)

		if err := rows.Scan(
			&info.QueueId,
			&info.QueueName,
			&createdAt,
			&gcAt,
			&info.RetentionPeriodSeconds,
			&info.VisibilityTimeoutSeconds,
			&info.MaxReceiveAttempts,
			&info.EvictionPolicy,
			&info.DeadLetterQueueId,
		); err != nil {
			return nil, fmt.Errorf("row scan: %w", err)
		}

		info.CreatedAt = timestamppb.New(createdAt)

		// Default eviction policy is DROP.
		// It should never happen, but we have to handle it anyway.
		if info.EvictionPolicy == v1.EvictionPolicy_EVICTION_POLICY_UNSPECIFIED {
			info.EvictionPolicy = v1.EvictionPolicy_EVICTION_POLICY_DROP
		}

		queues = append(queues, &info)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf(fmtCommitTxError, err)
	}

	return queues, nil
}

func (s *Storage) fillCache(ctx context.Context, cursor string) error {
	s.logger.Debug("Listing queue to fill the cache")

	queues, listErr := s.ListQueues(ctx, &v1.ListQueuesRequest{
		Cursor: cursor,
	})
	if listErr != nil {
		return fmt.Errorf("filling cache: %w", listErr)
	}

	for _, q := range queues.GetQueues() {
		props := QueueProps{
			ID:                       q.QueueId,
			Name:                     q.QueueName,
			CreatedAt:                q.CreatedAt.AsTime().UTC(),
			RetentionPeriodSeconds:   q.RetentionPeriodSeconds,
			VisibilityTimeoutSeconds: q.VisibilityTimeoutSeconds,
			MaxReceiveAttempts:       q.MaxReceiveAttempts,
			EvictionPolicy:           uint32(q.EvictionPolicy), //nolint:gosec // G115: EvictionPolicy is a small enum value
			DeadLetterQueueID:        q.DeadLetterQueueId,
		}

		s.cache.put(props)
	}

	if queues.HasMore {
		return s.fillCache(ctx, queues.NextCursor)
	}

	return nil
}

func (s *Storage) countQueues(ctx context.Context) (uint64, error) {
	q := `select count(*) from queue_properties`

	var count uint64

	if err := s.db.QueryRowContext(ctx, q).Scan(&count); err != nil {
		return 0, err
	}

	return count, nil
}
