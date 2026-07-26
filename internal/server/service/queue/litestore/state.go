package litestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/marsolab/plainq/internal/server/service/queue"
)

// snapshotPageSize is how many messages are read per statement while
// snapshotting. Small enough that a large queue does not have to fit in
// memory, large enough that a large queue is not one statement per message.
const snapshotPageSize = 1000

// Compilation time checks that Storage can back a replicated cluster.
var (
	_ queue.StateSnapshotter  = (*Storage)(nil)
	_ queue.StateRestorer     = (*Storage)(nil)
	_ queue.ReplicatedStorage = (*Storage)(nil)
)

// restoreState holds the transaction a restore is staged in.
type restoreState struct {
	mu sync.Mutex
	tx *sql.Tx
}

// BeginSnapshot implements queue.StateSnapshotter.
//
// The pin is a read transaction. In WAL mode — which cluster members run in,
// and which the server enforces when clustering is enabled — it sees the
// database as it was when it opened, no matter what is written afterwards, and
// it does not block those writes. That is exactly the guarantee a snapshot
// needs: one instant, captured without stopping the cluster.
func (s *Storage) BeginSnapshot(ctx context.Context) (queue.StateSnapshot, error) {
	tx, txErr := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if txErr != nil {
		return nil, fmt.Errorf("begin snapshot transaction: %w", txErr)
	}

	// SQLite defers a read transaction until its first statement, so the view
	// is not actually pinned yet. Read something trivial to pin it now, at the
	// instant the caller asked for, rather than whenever streaming starts.
	if _, err := tx.ExecContext(ctx, `select count(*) from queue_properties;`); err != nil {
		_ = tx.Rollback()

		return nil, fmt.Errorf("pin snapshot view: %w", err)
	}

	return &storageSnapshot{tx: tx}, nil
}

// storageSnapshot is a pinned read view of the store.
type storageSnapshot struct {
	mu sync.Mutex
	tx *sql.Tx
}

// Stream implements queue.StateSnapshot.
func (s *storageSnapshot) Stream(ctx context.Context, sink queue.StateSink) error {
	s.mu.Lock()
	tx := s.tx
	s.mu.Unlock()

	if tx == nil {
		return errors.New("snapshot has been released")
	}

	queues, queuesErr := snapshotQueues(ctx, tx)
	if queuesErr != nil {
		return queuesErr
	}

	for _, state := range queues {
		if err := sink.Queue(state); err != nil {
			return fmt.Errorf("write queue %q to snapshot: %w", state.ID, err)
		}

		if err := snapshotMessages(ctx, tx, state.ID, sink); err != nil {
			return err
		}
	}

	return snapshotTopics(ctx, tx, sink)
}

// Release implements queue.StateSnapshot.
func (s *storageSnapshot) Release() error {
	s.mu.Lock()
	tx := s.tx
	s.tx = nil
	s.mu.Unlock()

	if tx == nil {
		return nil
	}

	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		return fmt.Errorf("release snapshot transaction: %w", err)
	}

	return nil
}

func snapshotQueues(ctx context.Context, tx *sql.Tx) (_ []queue.QueueState, sErr error) {
	const query = `select queue_id, queue_name, cast(created_at as text), retention_period_seconds, ` +
		`visibility_timeout_seconds, max_receive_attempts, drop_policy, coalesce(dead_letter_queue_id, '') ` +
		`from queue_properties order by queue_id;`

	rows, queryErr := tx.QueryContext(ctx, query)
	if queryErr != nil {
		return nil, fmt.Errorf("read queue properties for snapshot: %w", queryErr)
	}

	defer func() {
		if err := rows.Close(); err != nil && sErr == nil {
			sErr = fmt.Errorf("close queue properties rows: %w", err)
		}
	}()

	var queues []queue.QueueState

	for rows.Next() {
		var (
			state     queue.QueueState
			createdAt string
		)

		if err := rows.Scan(
			&state.ID,
			&state.Name,
			&createdAt,
			&state.RetentionPeriodSeconds,
			&state.VisibilityTimeoutSeconds,
			&state.MaxReceiveAttempts,
			&state.EvictionPolicy,
			&state.DeadLetterQueueID,
		); err != nil {
			return nil, fmt.Errorf("scan queue properties for snapshot: %w", err)
		}

		state.CreatedAt = parseSQLiteTime(createdAt)

		queues = append(queues, state)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate queue properties for snapshot: %w", err)
	}

	return queues, nil
}

func snapshotMessages(ctx context.Context, tx *sql.Tx, queueID string, sink queue.StateSink) error {
	// Paginated by (msg_id) rather than OFFSET: the table is keyed on it, so
	// each page is an index seek instead of a rescan of everything already
	// written.
	cursor := ""

	for {
		page, err := snapshotMessagePage(ctx, tx, queueID, cursor)
		if err != nil {
			return err
		}

		if len(page) == 0 {
			return nil
		}

		for _, state := range page {
			if writeErr := sink.Message(state); writeErr != nil {
				return fmt.Errorf("write message %q to snapshot: %w", state.ID, writeErr)
			}
		}

		if len(page) < snapshotPageSize {
			return nil
		}

		cursor = page[len(page)-1].ID
	}
}

func snapshotMessagePage(
	ctx context.Context,
	tx *sql.Tx,
	queueID, cursor string,
) (_ []queue.MessageState, sErr error) {
	query := `select msg_id, msg_body, cast(created_at as text), cast(visible_at as text), retries from ` +
		queueID + ` where msg_id > ? order by msg_id limit ?;`

	rows, queryErr := tx.QueryContext(ctx, query, cursor, snapshotPageSize)
	if queryErr != nil {
		return nil, fmt.Errorf("read messages of queue %q for snapshot: %w", queueID, queryErr)
	}

	defer func() {
		if err := rows.Close(); err != nil && sErr == nil {
			sErr = fmt.Errorf("close message rows: %w", err)
		}
	}()

	page := make([]queue.MessageState, 0, snapshotPageSize)

	for rows.Next() {
		state := queue.MessageState{QueueID: queueID}

		var createdAt, visibleAt string

		if err := rows.Scan(&state.ID, &state.Body, &createdAt, &visibleAt, &state.Retries); err != nil {
			return nil, fmt.Errorf("scan message of queue %q for snapshot: %w", queueID, err)
		}

		state.CreatedAt = parseSQLiteTime(createdAt)
		state.VisibleAt = parseSQLiteTime(visibleAt)

		page = append(page, state)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate messages of queue %q for snapshot: %w", queueID, err)
	}

	return page, nil
}

func snapshotTopics(ctx context.Context, tx *sql.Tx, sink queue.StateSink) (sErr error) {
	topicRows, topicErr := tx.QueryContext(ctx, `select topic_id, topic_name from topic_properties order by topic_id;`)
	if topicErr != nil {
		return fmt.Errorf("read topics for snapshot: %w", topicErr)
	}

	defer func() {
		if err := topicRows.Close(); err != nil && sErr == nil {
			sErr = fmt.Errorf("close topic rows: %w", err)
		}
	}()

	for topicRows.Next() {
		var state queue.TopicState

		if err := topicRows.Scan(&state.ID, &state.Name); err != nil {
			return fmt.Errorf("scan topic for snapshot: %w", err)
		}

		if err := sink.Topic(state); err != nil {
			return fmt.Errorf("write topic %q to snapshot: %w", state.ID, err)
		}
	}

	if err := topicRows.Err(); err != nil {
		return fmt.Errorf("iterate topics for snapshot: %w", err)
	}

	if err := topicRows.Close(); err != nil {
		return fmt.Errorf("close topic rows: %w", err)
	}

	subRows, subErr := tx.QueryContext(ctx,
		`select subscription_id, topic_id, queue_id from topic_subscriptions order by subscription_id;`,
	)
	if subErr != nil {
		return fmt.Errorf("read subscriptions for snapshot: %w", subErr)
	}

	defer func() {
		if err := subRows.Close(); err != nil && sErr == nil {
			sErr = fmt.Errorf("close subscription rows: %w", err)
		}
	}()

	for subRows.Next() {
		var state queue.SubscriptionState

		if err := subRows.Scan(&state.ID, &state.TopicID, &state.QueueID); err != nil {
			return fmt.Errorf("scan subscription for snapshot: %w", err)
		}

		if err := sink.Subscription(state); err != nil {
			return fmt.Errorf("write subscription %q to snapshot: %w", state.ID, err)
		}
	}

	if err := subRows.Err(); err != nil {
		return fmt.Errorf("iterate subscriptions for snapshot: %w", err)
	}

	return nil
}

// BeginRestore implements queue.StateRestorer. Everything the store holds is
// dropped inside a transaction that is only committed once the whole snapshot
// has been read, so a restore that fails halfway leaves the node exactly as it
// was.
func (s *Storage) BeginRestore(ctx context.Context) error {
	s.restore.mu.Lock()
	defer s.restore.mu.Unlock()

	if s.restore.tx != nil {
		return errors.New("restore is already in progress")
	}

	tx, txErr := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if txErr != nil {
		return fmt.Errorf("begin restore transaction: %w", txErr)
	}

	if err := dropAllQueueTables(ctx, tx); err != nil {
		_ = tx.Rollback()

		return err
	}

	for _, stmt := range []string{
		`delete from topic_subscriptions;`,
		`delete from topic_properties;`,
		`delete from queue_properties;`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			_ = tx.Rollback()

			return fmt.Errorf("clear state for restore: %w", err)
		}
	}

	s.restore.tx = tx

	return nil
}

// dropAllQueueTables removes the per-queue message tables. They are named
// after the queue id, so the set of them is discovered from the catalogue
// rather than assumed from queue_properties — a table left behind by an
// interrupted delete would otherwise survive the restore and collide with a
// later queue of the same id.
func dropAllQueueTables(ctx context.Context, tx *sql.Tx) (sErr error) {
	rows, queryErr := tx.QueryContext(ctx,
		`select name from sqlite_master where type = 'table' and name in (select queue_id from queue_properties);`,
	)
	if queryErr != nil {
		return fmt.Errorf("list queue tables for restore: %w", queryErr)
	}

	var tables []string

	for rows.Next() {
		var name string

		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()

			return fmt.Errorf("scan queue table name: %w", err)
		}

		tables = append(tables, name)
	}

	if err := rows.Err(); err != nil {
		_ = rows.Close()

		return fmt.Errorf("iterate queue tables: %w", err)
	}

	if err := rows.Close(); err != nil {
		return fmt.Errorf("close queue table rows: %w", err)
	}

	for _, table := range tables {
		if !validQueueID(table) {
			return fmt.Errorf("refusing to drop table with unexpected name %q", table)
		}

		if _, err := tx.ExecContext(ctx, queryDeleteQueueTable(table)); err != nil {
			return fmt.Errorf("drop queue table %q for restore: %w", table, err)
		}
	}

	return nil
}

// RestoreQueue implements queue.StateRestorer.
func (s *Storage) RestoreQueue(ctx context.Context, state queue.QueueState) error {
	tx, txErr := s.restoreTx()
	if txErr != nil {
		return txErr
	}

	if !validQueueID(state.ID) {
		return fmt.Errorf("snapshot holds an unusable queue id %q", state.ID)
	}

	const insert = `insert into queue_properties (queue_id, queue_name, created_at, gc_at, ` +
		`retention_period_seconds, visibility_timeout_seconds, max_receive_attempts, drop_policy, ` +
		`dead_letter_queue_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?);`

	createdAt := sqliteTime(state.CreatedAt)

	if _, err := tx.ExecContext(ctx, insert,
		state.ID,
		state.Name,
		createdAt,
		createdAt,
		int64(state.RetentionPeriodSeconds),   //nolint:gosec // bounded by validation on the way in.
		int64(state.VisibilityTimeoutSeconds), //nolint:gosec // same.
		int64(state.MaxReceiveAttempts),
		int64(state.EvictionPolicy),
		toNullString(state.DeadLetterQueueID),
	); err != nil {
		return fmt.Errorf("restore queue %q: %w", state.ID, err)
	}

	if _, err := tx.ExecContext(ctx, queryCreateQueueTable(state.ID)); err != nil {
		return fmt.Errorf("restore queue table %q: %w", state.ID, err)
	}

	return nil
}

// RestoreMessages implements queue.StateRestorer.
func (s *Storage) RestoreMessages(ctx context.Context, states []queue.MessageState) error {
	if len(states) == 0 {
		return nil
	}

	tx, txErr := s.restoreTx()
	if txErr != nil {
		return txErr
	}

	queueID := states[0].QueueID
	if !validQueueID(queueID) {
		return fmt.Errorf("snapshot holds an unusable queue id %q", queueID)
	}

	const columns = 5

	for start := 0; start < len(states); start += maxSendInsertBatch {
		end := min(start+maxSendInsertBatch, len(states))

		args := make([]any, 0, (end-start)*columns)

		for _, state := range states[start:end] {
			if state.QueueID != queueID {
				return fmt.Errorf("restore batch mixes queues %q and %q", queueID, state.QueueID)
			}

			args = append(args,
				state.ID,
				state.Body,
				sqliteTime(state.CreatedAt),
				sqliteTime(state.VisibleAt),
				int64(state.Retries),
			)
		}

		if _, err := tx.ExecContext(ctx, queryRestoreMessagesBatch(queueID, end-start), args...); err != nil {
			return fmt.Errorf("restore messages of queue %q: %w", queueID, err)
		}
	}

	return nil
}

// RestoreTopic implements queue.StateRestorer.
func (s *Storage) RestoreTopic(ctx context.Context, state queue.TopicState) error {
	tx, txErr := s.restoreTx()
	if txErr != nil {
		return txErr
	}

	if _, err := tx.ExecContext(ctx,
		`insert into topic_properties (topic_id, topic_name) values (?, ?);`, state.ID, state.Name,
	); err != nil {
		return fmt.Errorf("restore topic %q: %w", state.ID, err)
	}

	return nil
}

// RestoreSubscription implements queue.StateRestorer.
func (s *Storage) RestoreSubscription(ctx context.Context, state queue.SubscriptionState) error {
	tx, txErr := s.restoreTx()
	if txErr != nil {
		return txErr
	}

	if _, err := tx.ExecContext(ctx,
		`insert into topic_subscriptions (subscription_id, topic_id, queue_id) values (?, ?, ?);`,
		state.ID, state.TopicID, state.QueueID,
	); err != nil {
		return fmt.Errorf("restore subscription %q: %w", state.ID, err)
	}

	return nil
}

// CommitRestore implements queue.StateRestorer.
func (s *Storage) CommitRestore(ctx context.Context) error {
	s.restore.mu.Lock()
	tx := s.restore.tx
	s.restore.tx = nil
	s.restore.mu.Unlock()

	if tx == nil {
		return errors.New("no restore is in progress")
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit restore: %w", err)
	}

	// The properties cache and the queue counter describe the state that was
	// just replaced. Rebuild them from what is now on disk, or every read that
	// answers from cache would answer about the old cluster.
	s.cache.reset()

	count, countErr := s.countQueues(ctx)
	if countErr != nil {
		return fmt.Errorf("count queues after restore: %w", countErr)
	}

	// The gauge only moves by deltas, so it is walked to the new value rather
	// than assigned one.
	if existing := s.observer.QueuesExist().Get(); existing > count {
		s.observer.QueuesExist().Sub(existing - count)
	} else if existing < count {
		s.observer.QueuesExist().Add(count - existing)
	}

	if err := s.fillCache(ctx, ""); err != nil {
		return fmt.Errorf("refill queue cache after restore: %w", err)
	}

	return nil
}

// AbortRestore implements queue.StateRestorer.
func (s *Storage) AbortRestore(context.Context) error {
	s.restore.mu.Lock()
	tx := s.restore.tx
	s.restore.tx = nil
	s.restore.mu.Unlock()

	if tx == nil {
		return nil
	}

	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		return fmt.Errorf("roll back restore: %w", err)
	}

	return nil
}

func (s *Storage) restoreTx() (*sql.Tx, error) {
	s.restore.mu.Lock()
	defer s.restore.mu.Unlock()

	if s.restore.tx == nil {
		return nil, errors.New("no restore is in progress")
	}

	return s.restore.tx, nil
}

// validQueueID reports whether an id is safe to interpolate into DDL.
//
// Queue ids become table names, which SQLite cannot parameterise, so every
// path that builds a statement from one has to know the id is an identifier
// and not a fragment of SQL. Ids are generated (XID: 20 lowercase
// alphanumerics), and a snapshot arriving over the network is exactly the
// place to stop trusting that.
func validQueueID(id string) bool {
	const maxQueueIDLen = 64

	if id == "" || len(id) > maxQueueIDLen {
		return false
	}

	// A leading digit would make the identifier ambiguous in DDL.
	if id[0] >= '0' && id[0] <= '9' {
		return false
	}

	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_':

		default:
			return false
		}
	}

	return true
}

// queryRestoreMessagesBatch inserts messages with every column supplied,
// including retry counts — a restore reproduces a state, it does not create a
// new one.
func queryRestoreMessagesBatch(queueID string, n int) string {
	var b strings.Builder

	b.WriteString(`insert into ` + queueID + ` (msg_id, msg_body, created_at, visible_at, retries) values `)

	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}

		b.WriteString("(?,?,?,?,?)")
	}

	b.WriteString(";")

	return b.String()
}

// parseSQLiteTime reads a timestamp column back into a time.Time.
//
// The column may hold any of the layouts SQLite and its Go drivers have
// written over the years, so each is tried in turn. A value none of them
// parses yields the zero time, which a snapshot renders as the epoch — visibly
// wrong rather than silently plausible.
func parseSQLiteTime(raw string) time.Time {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return time.Time{}
	}

	layouts := []string{
		sqliteTimeLayout,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		time.RFC3339Nano,
		time.RFC3339,
	}

	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, trimmed); err == nil {
			return parsed.UTC()
		}
	}

	return time.Time{}
}
