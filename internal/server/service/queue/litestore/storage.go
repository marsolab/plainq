package litestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/heartwilltell/hc"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/server/service/queue/litestore/sqlcgen"
	"github.com/marsolab/plainq/internal/server/service/telemetry"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/idkit"
	"github.com/marsolab/servekit/logkit"
	"github.com/oklog/ulid/v2"
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

	// maxSendInsertBatch caps how many messages go into a single multi-row
	// INSERT. Each message binds two parameters, so a batch must stay under
	// SQLite's bind-parameter limit; larger Send batches are split into this
	// many messages per statement.
	maxSendInsertBatch = 5000

	// queuePropsCacheSize represents the size of the queue properties cache.
	queuePropsCacheSize = 1000

	// queuePropsCacheFillingTimeout represents the default timeout duration
	// for filling the queue properties cache.
	queuePropsCacheFillingTimeout = 30 * time.Second

	// defaultPageSize represents the default page size used for listing queues.
	defaultPageSize uint32 = 10

	// peekDefaultLimit is the fallback browse page size when a Peek request
	// leaves Limit unset. Callers (the HTTP handler) normally pre-clamp it.
	peekDefaultLimit uint32 = 50
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
	db      *litekit.Conn
	queries *sqlcgen.Queries
	logger  *slog.Logger

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
		db:      db,
		queries: sqlcgen.New(db),
		logger:  logkit.NewNop(),

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

//nolint:cyclop // Complex queue creation with validation and initialization.
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

	if err := s.queries.WithTx(tx).InsertQueueProperties(ctx, sqlcgen.InsertQueuePropertiesParams{
		QueueID:                  queueID,
		QueueName:                input.QueueName,
		RetentionPeriodSeconds:   int64(input.RetentionPeriodSeconds),   //nolint:gosec // retention seconds is bounded by validation.
		VisibilityTimeoutSeconds: int64(input.VisibilityTimeoutSeconds), //nolint:gosec // visibility timeout is bounded by validation.
		MaxReceiveAttempts:       int64(input.MaxReceiveAttempts),
		DropPolicy:               int64(input.EvictionPolicy),
		DeadLetterQueueID:        toNullString(input.DeadLetterQueueId),
	}); err != nil {
		return nil, fmt.Errorf("create queue properties record: execute query: %w", err)
	}

	if _, err := tx.ExecContext(ctx, queryCreateQueueTable(queueID)); err != nil {
		return nil, fmt.Errorf("create queue table: execute query: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	props := QueueProps{
		ID:                       queueID,
		Name:                     input.QueueName,
		RetentionPeriodSeconds:   input.RetentionPeriodSeconds,
		VisibilityTimeoutSeconds: input.VisibilityTimeoutSeconds,
		MaxReceiveAttempts:       input.MaxReceiveAttempts,
		EvictionPolicy:           uint32(input.EvictionPolicy), //nolint:gosec // EvictionPolicy enum is non-negative.
		DeadLetterQueueID:        input.DeadLetterQueueId,
	}

	s.cache.put(props)

	output := v1.CreateQueueResponse{
		QueueId: queueID,
	}

	s.observer.QueuesExist().Inc()

	return &output, nil
}

//nolint:nonamedreturns // sErr is set by the deferred rollback to surface rollback errors.
func (s *Storage) ListQueues(ctx context.Context, input *v1.ListQueuesRequest) (_ *v1.ListQueuesResponse, sErr error) {
	// Set default page size if not specified.
	pageSize := input.Limit
	if pageSize <= 0 {
		pageSize = int32(defaultPageSize)
	}

	// The +1 is used to fetch one extra item to determine if there are more results.
	limit := pageSize + 1

	query := queryListQueues(limit, input.Cursor, input.OrderBy, input.SortBy)

	queues, listErr := s.listQueues(ctx, query, uint32(limit))
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
	tx, txErr := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if txErr != nil {
		return nil, fmt.Errorf("begin transaction: %w", txErr)
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

	if rows != int64(count) {
		return nil, fmt.Errorf("purge queue %q count (%d) != rows affected (%d) by purge", queueID, count, rows)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
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
		return nil, fmt.Errorf("begin transaction: %w", txErr)
	}

	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			sErr = errors.Join(sErr, fmt.Errorf("rollback transaction: %w", err))
		}
	}()

	rows, queueHeaderErr := s.queries.WithTx(tx).DeleteQueueProperties(ctx, queueID)
	if queueHeaderErr != nil {
		return nil, fmt.Errorf("delete queue %q info record: %w", queueID, queueHeaderErr)
	}

	if rows < 1 {
		return nil, fmt.Errorf("delete queue %q info record: %w", queueID, pqerr.ErrNotFound)
	}

	if _, err := tx.ExecContext(ctx, queryDeleteQueueTable(queueID)); err != nil {
		return nil, fmt.Errorf("drop queue %q table: %w", queueID, err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	s.cache.delete(props.ID, props.Name)

	output := v1.DeleteQueueResponse{}

	s.observer.QueuesExist().Dec()

	return &output, nil
}

func (s *Storage) Send(ctx context.Context, input *v1.SendRequest) (_ *v1.SendResponse, sErr error) {
	queueID := input.GetQueueId()

	messages := input.GetMessages()

	output := v1.SendResponse{
		MessageIds: make([]string, 0, len(messages)),
	}

	if len(messages) == 0 {
		return &output, nil
	}

	// Pre-generate IDs (response order matches request order) and flatten the
	// batch into one (msg_id, msg_body, …) argument slice for multi-row INSERT.
	args := make([]any, 0, len(messages)*2)

	var sentBytes uint64

	for _, m := range messages {
		msgID := idkit.ULID()

		args = append(args, msgID, m.Body)
		output.MessageIds = append(output.MessageIds, msgID)

		sentBytes += uint64(len(m.Body))
	}

	tx, txErr := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if txErr != nil {
		return nil, fmt.Errorf("begin transaction: %w", txErr)
	}

	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			sErr = errors.Join(sErr, fmt.Errorf("rollback transaction: %w", err))
		}
	}()

	// One multi-row INSERT per chunk instead of one INSERT per message. Chunks
	// stay under SQLite's bind-parameter limit; the surrounding transaction
	// keeps the whole Send all-or-nothing.
	for start := 0; start < len(messages); start += maxSendInsertBatch {
		end := min(start+maxSendInsertBatch, len(messages))

		if _, err := tx.ExecContext(ctx, queryInsertMessagesBatch(queueID, end-start), args[start*2:end*2]...); err != nil {
			return nil, fmt.Errorf("insert messages: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	s.observer.MessagesSentBytes(queueID).Add(sentBytes)
	s.observer.MessagesSent(queueID).Add(uint64(len(output.MessageIds)))

	return &output, nil
}

func (s *Storage) Receive(ctx context.Context, input *v1.ReceiveRequest) (_ *v1.ReceiveResponse, sErr error) {
	queueID := input.GetQueueId()

	info, describeErr := s.DescribeQueue(ctx, &v1.DescribeQueueRequest{QueueId: queueID})
	if describeErr != nil {
		return nil, fmt.Errorf("describe queue (id: %q): %w", queueID, describeErr)
	}

	tx, txErr := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if txErr != nil {
		return nil, fmt.Errorf("begin transaction: %w", txErr)
	}

	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			sErr = errors.Join(sErr, fmt.Errorf("rollback transaction: %w", err))
		}
	}()

	messages, selectErr := selectVisibleMessages(ctx, tx, queueID, info.MaxReceiveAttempts, input.BatchSize)
	if selectErr != nil {
		return nil, selectErr
	}

	//nolint:gosec // VisibilityTimeoutSeconds is bounded by validation; conversion to int64 is safe.
	visibleAt := time.Now().UTC().Add(time.Duration(info.VisibilityTimeoutSeconds) * time.Second)

	if err := bumpVisibility(ctx, tx, queueID, messages, visibleAt); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	if len(messages) == 0 {
		s.observer.EmptyReceives(queueID).Inc()
	}

	s.observer.MessagesReceived(queueID).Add(uint64(len(messages)))

	return &v1.ReceiveResponse{Messages: messages}, nil
}

// selectVisibleMessages reads up to limit visible, under-attempt-limit messages
// ordered by created_at. It fully drains and closes the read cursor before
// returning so the caller can issue the batched visibility UPDATE — SQLite
// cannot write through an open read cursor on the same connection. A batch size
// of 0 defaults to 1.
func selectVisibleMessages(
	ctx context.Context,
	tx *sql.Tx,
	queueID string,
	maxReceiveAttempts, batchSize uint32,
) (_ []*v1.ReceiveMessage, err error) {
	limit := batchSize
	if limit == 0 {
		limit = 1
	}

	rows, queryErr := tx.QueryContext(ctx, querySelectMessages(queueID), maxReceiveAttempts, limit)
	if queryErr != nil {
		return nil, fmt.Errorf("select query: %w", queryErr)
	}

	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close rows: %w", closeErr)
		}
	}()

	messages := make([]*v1.ReceiveMessage, 0, limit)

	for rows.Next() {
		var m v1.ReceiveMessage

		if scanErr := rows.Scan(&m.Id, &m.Body); scanErr != nil {
			return nil, fmt.Errorf("scan message record: %w", scanErr)
		}

		messages = append(messages, &m)
	}

	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("iterate message rows: %w", rowsErr)
	}

	return messages, nil
}

// bumpVisibility hides a freshly-received batch until visibleAt and increments
// each message's retry count in a single UPDATE. A nil/empty batch is a no-op.
func bumpVisibility(ctx context.Context, tx *sql.Tx, queueID string, messages []*v1.ReceiveMessage, visibleAt time.Time) error {
	if len(messages) == 0 {
		return nil
	}

	args := make([]any, 0, len(messages)+1)
	args = append(args, visibleAt)

	for _, m := range messages {
		args = append(args, m.Id)
	}

	if _, err := tx.ExecContext(ctx, queryUpdateMessagesVisibility(queueID, len(messages)), args...); err != nil {
		return fmt.Errorf("update messages visibility: %w", err)
	}

	return nil
}

func (s *Storage) Delete(ctx context.Context, input *v1.DeleteRequest) (*v1.DeleteResponse, error) {
	queueID := input.GetQueueId()

	ids := input.GetMessageIds()

	output := v1.DeleteResponse{
		Successful: make([]string, 0, len(ids)),
		Failed:     make([]*v1.DeleteFailure, 0),
	}

	if len(ids) == 0 {
		return &output, nil
	}

	args := make([]any, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
	}

	// One DELETE … IN (…) RETURNING removes the whole batch in a single
	// statement; the returned ids are the messages that actually existed.
	rows, queryErr := s.db.QueryContext(ctx, queryDeleteMessages(queueID, len(ids)), args...)
	if queryErr != nil {
		return nil, fmt.Errorf("delete messages: %w", queryErr)
	}

	deleted, collectErr := collectReturnedIDs(rows)
	if collectErr != nil {
		return nil, collectErr
	}

	// Ids that came back were removed (successful); ids that didn't were not in
	// the queue (failed).
	for _, id := range ids {
		if _, ok := deleted[id]; !ok {
			output.Failed = append(output.Failed, &v1.DeleteFailure{MessageId: id})

			continue
		}

		recordTimeInQueue(s.observer, queueID, id)

		output.Successful = append(output.Successful, id)
	}

	s.observer.MessagesDeleted(queueID).Add(uint64(len(output.Successful)))

	return &output, nil
}

// Peek browses up to input.Limit messages starting at input.Offset, oldest
// first, without consuming them or touching their visibility/retry state. It is
// a pure read for the admin UI; the queue's created_at index backs the scan.
func (s *Storage) Peek(ctx context.Context, input *queue.PeekRequest) (_ *queue.PeekResponse, err error) {
	queueID := input.QueueID

	if _, describeErr := s.DescribeQueue(ctx, &v1.DescribeQueueRequest{QueueId: queueID}); describeErr != nil {
		return nil, fmt.Errorf("describe queue (id: %q): %w", queueID, describeErr)
	}

	limit := input.Limit
	if limit == 0 {
		limit = peekDefaultLimit
	}

	rows, queryErr := s.db.QueryContext(ctx, queryPeekMessages(queueID), limit, input.Offset)
	if queryErr != nil {
		return nil, fmt.Errorf("peek query: %w", queryErr)
	}

	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close rows: %w", closeErr)
		}
	}()

	messages, scanErr := scanPeekMessages(rows, limit)
	if scanErr != nil {
		return nil, scanErr
	}

	total, countErr := s.countMessages(ctx, queueID)
	if countErr != nil {
		return nil, countErr
	}

	return &queue.PeekResponse{
		Messages: messages,
		Total:    total,
	}, nil
}

// scanPeekMessages drains a peek result set into PeekMessage values.
func scanPeekMessages(rows *sql.Rows, capacity uint32) ([]*queue.PeekMessage, error) {
	messages := make([]*queue.PeekMessage, 0, capacity)

	for rows.Next() {
		var (
			m        queue.PeekMessage
			retries  int64
			inFlight int64
		)

		if scanErr := rows.Scan(&m.ID, &m.Body, &m.CreatedAt, &m.VisibleAt, &retries, &inFlight); scanErr != nil {
			return nil, fmt.Errorf("scan message record: %w", scanErr)
		}

		m.Retries = uint32(retries) //nolint:gosec // retries is a non-negative counter.
		m.InFlight = inFlight != 0

		messages = append(messages, &m)
	}

	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("iterate message rows: %w", rowsErr)
	}

	return messages, nil
}

// countMessages returns the total number of messages in a queue.
func (s *Storage) countMessages(ctx context.Context, queueID string) (uint64, error) {
	var total int64
	if err := s.db.QueryRowContext(ctx, queryCountMessages(queueID)).Scan(&total); err != nil {
		return 0, fmt.Errorf("count messages: %w", err)
	}

	if total < 0 {
		return 0, nil
	}

	return uint64(total), nil
}

// collectReturnedIDs drains a RETURNING result set into a set of ids, closing
// the cursor when done.
func collectReturnedIDs(rows *sql.Rows) (_ map[string]struct{}, err error) {
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close rows: %w", closeErr)
		}
	}()

	ids := make(map[string]struct{})

	for rows.Next() {
		var id string

		if scanErr := rows.Scan(&id); scanErr != nil {
			return nil, fmt.Errorf("scan deleted id: %w", scanErr)
		}

		ids[id] = struct{}{}
	}

	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("iterate deleted ids: %w", rowsErr)
	}

	return ids, nil
}

// recordTimeInQueue observes how long a message lived in the queue, using the
// timestamp embedded in its ULID id as the enqueue instant. A message id that
// fails to parse is skipped rather than fatal: the metric is best-effort and
// must never take the server down on delete.
func recordTimeInQueue(observer telemetry.Observer, queueID, msgID string) {
	if u, err := ulid.Parse(msgID); err == nil {
		observer.TimeInQueue(queueID).Dur(ulid.Time(u.Time()))
	}
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

//nolint:cyclop // sErr is set by deferred rollback; covers the full SQL fetch path.
func (s *Storage) listQueues(ctx context.Context, query string, pageSize uint32) (_ []*v1.DescribeQueueResponse, sErr error) {
	tx, txErr := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if txErr != nil {
		return nil, fmt.Errorf("begin transaction: %w", txErr)
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

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate queue rows: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
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
			EvictionPolicy:           uint32(q.EvictionPolicy), //nolint:gosec // EvictionPolicy enum is non-negative.
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
	count, err := s.queries.CountQueueProperties(ctx)
	if err != nil {
		return 0, fmt.Errorf("count queue properties: %w", err)
	}

	if count < 0 {
		return 0, nil
	}

	return uint64(count), nil
}

// toNullString converts a Go string to sql.NullString. Empty strings
// become NULL, which matches the existing on-disk convention for
// "no dead-letter queue configured".
func toNullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}

	return sql.NullString{String: s, Valid: true}
}

// queuePropertyToProto converts a sqlc-generated QueueProperty row into
// the protobuf DescribeQueueResponse used throughout the service layer.
func queuePropertyToProto(row sqlcgen.QueueProperty) *v1.DescribeQueueResponse {
	resp := v1.DescribeQueueResponse{
		QueueId:                  row.QueueID,
		QueueName:                row.QueueName,
		CreatedAt:                timestamppb.New(row.CreatedAt),
		RetentionPeriodSeconds:   uint64(row.RetentionPeriodSeconds),   //nolint:gosec // retention seconds is non-negative.
		VisibilityTimeoutSeconds: uint64(row.VisibilityTimeoutSeconds), //nolint:gosec // visibility timeout is non-negative.
		MaxReceiveAttempts:       uint32(row.MaxReceiveAttempts),       //nolint:gosec // max receive attempts is non-negative.
		EvictionPolicy:           v1.EvictionPolicy(row.DropPolicy),    //nolint:gosec // drop policy is bounded by the EvictionPolicy enum.
		DeadLetterQueueId:        row.DeadLetterQueueID.String,
	}

	return &resp
}
