package pgstore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
)

func newPostgresTestStorage(t *testing.T) *Storage {
	t.Helper()

	dsn := os.Getenv("PLAINQ_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PLAINQ_TEST_POSTGRES_DSN is not set")
	}

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open postgres pool: %v", err)
	}
	t.Cleanup(pool.Close)

	store, err := New(pool, WithGCTimeout(time.Hour))
	if err != nil {
		t.Fatalf("new postgres storage: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	return store
}

func TestSweepMovesExhaustedMessageToDLQAtomically(t *testing.T) {
	ctx := context.Background()
	store := newPostgresTestStorage(t)

	dlq, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "dlq-" + time.Now().UTC().Format("20060102150405.000000000")})
	if err != nil {
		t.Fatalf("create DLQ: %v", err)
	}
	t.Cleanup(func() { _, _ = store.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: dlq.GetQueueId(), Force: true}) })

	source, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{
		QueueName:                "source-" + time.Now().UTC().Format("20060102150405.000000000"),
		MaxReceiveAttempts:       1,
		VisibilityTimeoutSeconds: 1,
		EvictionPolicy:           v1.EvictionPolicy_EVICTION_POLICY_DEAD_LETTER,
		DeadLetterQueueId:        dlq.GetQueueId(),
	})
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	t.Cleanup(func() {
		_, _ = store.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: source.GetQueueId(), Force: true})
	})

	sent, err := store.Send(ctx, &v1.SendRequest{
		QueueId:  source.GetQueueId(),
		Messages: []*v1.SendMessage{{Body: []byte("payload")}},
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	if _, err := store.Receive(ctx, &v1.ReceiveRequest{QueueId: source.GetQueueId(), BatchSize: 1}); err != nil {
		t.Fatalf("receive: %v", err)
	}

	if _, err := store.sweep(ctx, source.GetQueueId()); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	messageID := sent.GetMessageIds()[0]
	var sourceCount, dlqCount int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM `+quoteIdent(source.GetQueueId())+` WHERE msg_id = $1`, messageID).Scan(&sourceCount); err != nil {
		t.Fatalf("count source message: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM `+quoteIdent(dlq.GetQueueId())+` WHERE msg_id = $1`, messageID).Scan(&dlqCount); err != nil {
		t.Fatalf("count DLQ message: %v", err)
	}

	if sourceCount != 0 || dlqCount != 1 {
		t.Fatalf("message counts source=%d dlq=%d, want source=0 dlq=1", sourceCount, dlqCount)
	}
}

func TestReceiveDeliversExactlyMaxReceiveAttempts(t *testing.T) {
	ctx := context.Background()
	store := newPostgresTestStorage(t)

	created, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{
		QueueName:                "one-attempt-" + time.Now().UTC().Format("20060102150405.000000000"),
		MaxReceiveAttempts:       1,
		VisibilityTimeoutSeconds: 1,
	})
	if err != nil {
		t.Fatalf("create queue: %v", err)
	}
	queueID := created.GetQueueId()
	t.Cleanup(func() { _, _ = store.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID, Force: true}) })

	if _, err := store.Send(ctx, &v1.SendRequest{QueueId: queueID, Messages: []*v1.SendMessage{{Body: []byte("payload")}}}); err != nil {
		t.Fatalf("send: %v", err)
	}

	first, err := store.Receive(ctx, &v1.ReceiveRequest{QueueId: queueID, BatchSize: 1})
	if err != nil || len(first.GetMessages()) != 1 {
		t.Fatalf("first receive = %#v, %v; want one message", first, err)
	}

	if _, err := store.pool.Exec(ctx, `UPDATE `+quoteIdent(queueID)+` SET visible_at = now() - interval '1 second'`); err != nil {
		t.Fatalf("make message visible: %v", err)
	}

	second, err := store.Receive(ctx, &v1.ReceiveRequest{QueueId: queueID, BatchSize: 1})
	if err != nil || len(second.GetMessages()) != 0 {
		t.Fatalf("second receive = %#v, %v; want no messages", second, err)
	}
}
