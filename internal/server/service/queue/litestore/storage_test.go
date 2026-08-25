package litestore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"testing"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/maxatome/go-testdeep/td"
)

func TestTursoCompatibleTopicConflictAndConnectionFailure(t *testing.T) {
	conflictDB := sql.OpenDB(pubSubFakeConnector{conn: &pubSubFakeConn{}})
	t.Cleanup(func() { _ = conflictDB.Close() })
	conflictStorage := &Storage{db: conflictDB}

	_, err := conflictStorage.CreateTopic(context.Background(), &queue.CreateTopicRequest{TopicName: "events"})
	if !errors.Is(err, pqerr.ErrAlreadyExists) {
		t.Fatalf("zero-row Turso-compatible insert error = %v, want %v", err, pqerr.ErrAlreadyExists)
	}

	unavailableDB := sql.OpenDB(pubSubFakeConnector{conn: &pubSubFakeConn{beginErr: context.DeadlineExceeded}})
	t.Cleanup(func() { _ = unavailableDB.Close() })
	unavailableStorage := &Storage{db: unavailableDB}

	_, err = unavailableStorage.CreateTopic(context.Background(), &queue.CreateTopicRequest{TopicName: "events"})
	if !errors.Is(err, pqerr.ErrUnavailable) {
		t.Fatalf("exported connection failure error = %v, want %v", err, pqerr.ErrUnavailable)
	}
}

type pubSubFakeConnector struct {
	conn driver.Conn
}

func (c pubSubFakeConnector) Connect(context.Context) (driver.Conn, error) { return c.conn, nil }
func (pubSubFakeConnector) Driver() driver.Driver                          { return pubSubFakeDriver{} }

type pubSubFakeDriver struct{}

func (pubSubFakeDriver) Open(string) (driver.Conn, error) { return &pubSubFakeConn{}, nil }

type pubSubFakeConn struct {
	beginErr error
}

func (*pubSubFakeConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (*pubSubFakeConn) Close() error                        { return nil }
func (c *pubSubFakeConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *pubSubFakeConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	if c.beginErr != nil {
		return nil, c.beginErr
	}
	return pubSubFakeTx{}, nil
}
func (*pubSubFakeConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return pubSubFakeResult(0), nil
}

type pubSubFakeTx struct{}

func (pubSubFakeTx) Commit() error   { return nil }
func (pubSubFakeTx) Rollback() error { return nil }

type pubSubFakeResult int64

func (pubSubFakeResult) LastInsertId() (int64, error) { return 0, nil }
func (r pubSubFakeResult) RowsAffected() (int64, error) {
	return int64(r), nil
}

func TestStorageListQueuesHandlesNullableDeadLetterQueue(t *testing.T) {
	ctx := context.Background()
	conn, err := litekit.New(filepath.Join(t.TempDir(), "plainq.db"))
	td.Require(t).CmpNoError(err, "open database")
	t.Cleanup(func() {
		td.CmpNoError(t, conn.Close(), "close database")
	})
	setupPubSubTables(t, ctx, conn)

	storage, err := New(conn)
	td.Require(t).CmpNoError(err, "create storage")
	t.Cleanup(func() {
		td.CmpNoError(t, storage.Close(), "close storage")
	})

	_, err = storage.CreateQueue(ctx, &v1.CreateQueueRequest{
		QueueName:      "drop-queue",
		EvictionPolicy: v1.EvictionPolicy_EVICTION_POLICY_DROP,
	})
	td.Require(t).CmpNoError(err, "create DROP queue")

	listed, err := storage.ListQueues(ctx, &v1.ListQueuesRequest{})
	td.Require(t).CmpNoError(err, "list queue with NULL dead-letter target")
	td.Require(t).Cmp(listed.GetQueues(), td.Len(1), "DROP queue is listed")
	td.Cmp(t, listed.GetQueues()[0].GetDeadLetterQueueId(), "", "DROP queue has no dead-letter target")

	dlq, err := storage.CreateQueue(ctx, &v1.CreateQueueRequest{
		QueueName: "dead-letter-queue",
	})
	td.Require(t).CmpNoError(err, "create dead-letter queue")

	parent, err := storage.CreateQueue(ctx, &v1.CreateQueueRequest{
		QueueName:         "parent-queue",
		EvictionPolicy:    v1.EvictionPolicy_EVICTION_POLICY_DEAD_LETTER,
		DeadLetterQueueId: dlq.GetQueueId(),
	})
	td.Require(t).CmpNoError(err, "create parent queue")

	listed, err = storage.ListQueues(ctx, &v1.ListQueuesRequest{})
	td.Require(t).CmpNoError(err, "list queues with dead-letter target")

	var foundParent *v1.DescribeQueueResponse
	for _, queue := range listed.GetQueues() {
		if queue.GetQueueId() == parent.GetQueueId() {
			foundParent = queue
			break
		}
	}
	td.Require(t).Cmp(foundParent, td.NotNil(), "parent queue is listed")
	td.Cmp(t, foundParent.GetDeadLetterQueueId(), dlq.GetQueueId(), "dead-letter target round-trips")
}

func TestStorageDescribeQueueByNameAndMissingQueue(t *testing.T) {
	ctx := context.Background()
	conn, err := litekit.New(filepath.Join(t.TempDir(), "plainq.db"))
	td.Require(t).CmpNoError(err, "open database")
	t.Cleanup(func() {
		td.CmpNoError(t, conn.Close(), "close database")
	})
	setupPubSubTables(t, ctx, conn)

	storage, err := New(conn)
	td.Require(t).CmpNoError(err, "create storage")
	t.Cleanup(func() {
		td.CmpNoError(t, storage.Close(), "close storage")
	})

	created, err := storage.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "platform.events"})
	td.Require(t).CmpNoError(err, "create queue")

	described, err := storage.DescribeQueue(ctx, &v1.DescribeQueueRequest{QueueName: "platform.events"})
	td.Require(t).CmpNoError(err, "describe queue by name")
	td.Cmp(t, described.GetQueueId(), created.GetQueueId())
	td.Cmp(t, described.GetQueueName(), "platform.events")

	_, err = storage.DescribeQueue(ctx, &v1.DescribeQueueRequest{QueueName: "not-created"})
	td.Cmp(t, errors.Is(err, pqerr.ErrNotFound), true, "missing queue maps to the domain not-found error")
}
