package pgstore

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/shared/pqerr"
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

func TestPostgresListQueuesParity(t *testing.T) {
	ctx := context.Background()
	store := newPostgresTestStorage(t)
	prefix := "queue-parity-" + time.Now().UTC().Format("20060102150405.000000000") + "-"

	created := make([]*v1.CreateQueueResponse, 0, 5)
	for _, name := range []string{"alpha", "alpha-2", "omega", "literal%queue", "literalXqueue"} {
		queue, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: prefix + name})
		if err != nil {
			t.Fatalf("create queue %q: %v", name, err)
		}
		created = append(created, queue)
	}
	t.Cleanup(func() {
		for _, queue := range created {
			_, _ = store.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queue.GetQueueId(), Force: true})
		}
	})
	ids := make([]string, 0, len(created))
	for _, queue := range created {
		ids = append(ids, queue.GetQueueId())
	}
	if _, err := store.pool.Exec(ctx, `UPDATE queue_properties SET created_at = $1 WHERE queue_id = ANY($2)`, time.Now().UTC(), ids); err != nil {
		t.Fatalf("tie queue creation times: %v", err)
	}

	for _, orderBy := range []v1.ListQueuesRequest_OrderBy{
		v1.ListQueuesRequest_ORDER_BY_NAME,
		v1.ListQueuesRequest_ORDER_BY_CREATED_AT,
	} {
		t.Run(orderBy.String(), func(t *testing.T) {
			first, err := store.ListQueues(ctx, &v1.ListQueuesRequest{
				QueuePrefix: prefix,
				Limit:       2,
				OrderBy:     orderBy,
				SortBy:      v1.ListQueuesRequest_SORT_BY_ASC,
			})
			if err != nil {
				t.Fatalf("first page: %v", err)
			}
			if len(first.GetQueues()) != 2 || first.GetNextCursor() == "" || first.GetTotalCount() != 5 {
				t.Fatalf("first page queues=%d cursor=%q total=%d, want 2, cursor, 5", len(first.GetQueues()), first.GetNextCursor(), first.GetTotalCount())
			}

			second, err := store.ListQueues(ctx, &v1.ListQueuesRequest{
				QueuePrefix: prefix,
				Limit:       3,
				OrderBy:     orderBy,
				SortBy:      v1.ListQueuesRequest_SORT_BY_ASC,
				Cursor:      first.GetNextCursor(),
			})
			if err != nil {
				t.Fatalf("second page: %v", err)
			}
			if len(second.GetQueues()) != 3 || second.GetTotalCount() != 5 {
				t.Fatalf("second page queues=%d total=%d, want 3 and 5", len(second.GetQueues()), second.GetTotalCount())
			}

			seen := map[string]bool{}
			for _, queue := range append(first.GetQueues(), second.GetQueues()...) {
				if seen[queue.GetQueueId()] {
					t.Fatalf("duplicate queue %q across pages", queue.GetQueueId())
				}
				seen[queue.GetQueueId()] = true
			}
		})
	}

	literal, err := store.ListQueues(ctx, &v1.ListQueuesRequest{QueuePrefix: prefix + "literal%"})
	if err != nil {
		t.Fatalf("literal prefix: %v", err)
	}
	if len(literal.GetQueues()) != 1 || literal.GetTotalCount() != 1 {
		t.Fatalf("literal prefix queues=%d total=%d, want 1 and 1", len(literal.GetQueues()), literal.GetTotalCount())
	}

	for _, name := range []string{"CaseQueue", "caseQueue"} {
		queue, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: prefix + name})
		if err != nil {
			t.Fatalf("create mixed-case queue %q: %v", name, err)
		}
		created = append(created, queue)
	}

	caseSensitive, err := store.ListQueues(ctx, &v1.ListQueuesRequest{QueuePrefix: prefix + "Case"})
	if err != nil {
		t.Fatalf("case-sensitive prefix: %v", err)
	}
	if len(caseSensitive.GetQueues()) != 1 || caseSensitive.GetTotalCount() != 1 || caseSensitive.GetQueues()[0].GetQueueName() != prefix+"CaseQueue" {
		t.Fatalf("case-sensitive prefix queues=%v total=%d, want %q only", caseSensitive.GetQueues(), caseSensitive.GetTotalCount(), prefix+"CaseQueue")
	}
}

func TestPostgresDeleteQueueRequiresForceWhenNonEmpty(t *testing.T) {
	ctx := context.Background()
	store := newPostgresTestStorage(t)

	created, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "force-" + time.Now().UTC().Format("20060102150405.000000000")})
	if err != nil {
		t.Fatalf("create queue: %v", err)
	}
	queueID := created.GetQueueId()
	t.Cleanup(func() { _, _ = store.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID, Force: true}) })

	if _, err := store.Send(ctx, &v1.SendRequest{QueueId: queueID, Messages: []*v1.SendMessage{{Body: []byte("payload")}}}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if _, err := store.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID}); !errors.Is(err, pqerr.ErrFailedPrecondition) {
		t.Fatalf("delete without force error = %v, want failed precondition", err)
	}
}

type scriptedSweeper struct {
	results []error
	seen    []string
}

func (s *scriptedSweeper) Sweep(_ context.Context, queueID string) error {
	s.seen = append(s.seen, queueID)
	err := s.results[0]
	s.results = s.results[1:]

	return err
}

func TestGCContinuesAfterOneQueueFails(t *testing.T) {
	broken := errors.New("broken queue")
	sweeper := &scriptedSweeper{results: []error{broken, nil}}

	err := runSweepBatch(context.Background(), []string{"broken", "healthy"}, sweeper.Sweep, slog.Default())
	if !errors.Is(err, broken) {
		t.Fatalf("sweep error = %v, want broken queue", err)
	}
	if !reflect.DeepEqual(sweeper.seen, []string{"broken", "healthy"}) {
		t.Fatalf("swept queues = %v, want [broken healthy]", sweeper.seen)
	}
}
