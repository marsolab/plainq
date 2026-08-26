package pgstore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/marsolab/plainq/internal/server/mutations"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

func TestPostgresDeadLetterSweepMovesMessagesExactlyOnce(t *testing.T) {
	ctx, storage, pool, _ := newPostgresPubSubStorage(t)
	sourceID, targetID := createPostgresDeadLetterQueues(t, ctx, storage)
	createdAt := time.Date(2026, time.August, 25, 10, 20, 30, 0, time.UTC)
	makePostgresMessageEvictable(t, ctx, storage, pool, sourceID, createdAt)

	result, err := storage.sweep(ctx, sourceID)
	if err != nil {
		t.Fatalf("sweep dead-letter source: %v", err)
	}
	if result.MessagesDropped != 1 {
		t.Fatalf("first sweep moved %d messages, want 1", result.MessagesDropped)
	}
	assertPostgresQueueMessageCount(t, ctx, pool, sourceID, 0)
	assertPostgresQueueMessageCount(t, ctx, pool, targetID, 1)

	var (
		movedCreatedAt time.Time
		movedVisibleAt time.Time
		visibleNow     bool
	)
	if err := pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT created_at, visible_at, visible_at <= now() FROM %s`, quoteIdent(targetID),
	)).Scan(&movedCreatedAt, &movedVisibleAt, &visibleNow); err != nil {
		t.Fatalf("read moved message timestamps: %v", err)
	}
	if !movedCreatedAt.Equal(createdAt) {
		t.Fatalf("moved created_at = %s, want %s", movedCreatedAt, createdAt)
	}
	if !visibleNow {
		t.Fatalf("moved visible_at = %s, want immediately visible according to PostgreSQL", movedVisibleAt)
	}

	repeated, err := storage.sweep(ctx, sourceID)
	if err != nil {
		t.Fatalf("repeat dead-letter sweep: %v", err)
	}
	if repeated.MessagesDropped != 0 {
		t.Fatalf("repeat sweep moved %d messages, want 0", repeated.MessagesDropped)
	}
	assertPostgresQueueMessageCount(t, ctx, pool, sourceID, 0)
	assertPostgresQueueMessageCount(t, ctx, pool, targetID, 1)
}

func TestPostgresSweepLocksSourceParentBeforeQueueTables(t *testing.T) {
	ctx, storage, pool, applicationName := newPostgresPubSubStorage(t)
	sourceID, targetID := createPostgresDeadLetterQueues(t, ctx, storage)
	makePostgresMessageEvictable(t, ctx, storage, pool, sourceID, time.Now().Add(-time.Hour))

	const advisoryKey int64 = 82620271
	installBlockingQueueInsertTrigger(t, ctx, pool, targetID, advisoryKey)
	blocker := holdPostgresAdvisoryLock(t, ctx, pool, advisoryKey)

	sweepDone := make(chan postgresSweepOutcome, 1)
	go func() {
		result, err := storage.sweep(ctx, sourceID)
		sweepDone <- postgresSweepOutcome{result: result, err: err}
	}()
	waitForPostgresQueryWait(t, ctx, pool, applicationName, "INSERT INTO "+quoteIdent(targetID), "advisory")

	deleteDone := make(chan postgresQueueDeleteOutcome, 1)
	go func() {
		result, err := storage.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: sourceID, Force: true})
		deleteDone <- postgresQueueDeleteOutcome{result: result, err: err}
	}()
	waitingAt := waitForPostgresOneOfQueryWait(
		t,
		ctx,
		pool,
		applicationName,
		"SELECT queue_id FROM queue_properties",
		"LOCK TABLE "+quoteIdent(sourceID),
	)

	commitPostgresBlocker(t, ctx, blocker)
	swept := awaitPostgresSweep(t, sweepDone)
	deleted := awaitPostgresQueueDelete(t, deleteDone)

	if waitingAt != "SELECT queue_id FROM queue_properties" {
		t.Errorf("DeleteQueue waited at %q, want source parent row lock", waitingAt)
	}
	if swept.err != nil || swept.result == nil || swept.result.MessagesDropped != 1 {
		t.Errorf("overlapping sweep = %#v, %v; want one committed move", swept.result, swept.err)
	}
	if deleted.err != nil || deleted.result == nil {
		t.Errorf("overlapping source delete = %#v, %v; want committed delete", deleted.result, deleted.err)
	}
	assertPostgresQueueMessageCount(t, ctx, pool, targetID, 1)
}

func TestPostgresSweepMissingParentReturnsNotFoundWithoutEffects(t *testing.T) {
	ctx, storage, pool, _ := newPostgresPubSubStorage(t)
	queueID := createPostgresDropQueue(t, ctx, storage, "gc-missing-parent")
	makePostgresMessageEvictable(t, ctx, storage, pool, queueID, time.Now().Add(-time.Hour))

	if _, err := pool.Exec(ctx, `DELETE FROM queue_properties WHERE queue_id = $1`, queueID); err != nil {
		t.Fatalf("remove queue parent out of band: %v", err)
	}
	result, err := storage.sweep(ctx, queueID)
	if result != nil || !errors.Is(err, pqerr.ErrNotFound) {
		t.Fatalf("sweep missing parent = %#v, %v; want nil %v", result, err, pqerr.ErrNotFound)
	}
	assertPostgresQueueMessageCount(t, ctx, pool, queueID, 1)
}

func TestPostgresCollectContinuesAfterConcurrentQueueDeletion(t *testing.T) {
	ctx, storage, pool, applicationName := newPostgresPubSubStorage(t)
	firstID := createPostgresDropQueue(t, ctx, storage, "gc-first")
	staleID := createPostgresDropQueue(t, ctx, storage, "gc-stale")
	laterID := createPostgresDropQueue(t, ctx, storage, "gc-later")
	makePostgresMessageEvictable(t, ctx, storage, pool, firstID, time.Now().Add(-3*time.Hour))
	makePostgresMessageEvictable(t, ctx, storage, pool, laterID, time.Now().Add(-time.Hour))

	if _, err := pool.Exec(ctx, `UPDATE queue_properties SET gc_at = CASE queue_id
WHEN $1 THEN now() - interval '3 hours'
WHEN $2 THEN now() - interval '2 hours'
WHEN $3 THEN now() - interval '1 hour'
ELSE gc_at END`, firstID, staleID, laterID); err != nil {
		t.Fatalf("order queues for collection: %v", err)
	}

	const advisoryKey int64 = 82620272
	installBlockingQueueMessageDeleteTrigger(t, ctx, pool, firstID, advisoryKey)
	blocker := holdPostgresAdvisoryLock(t, ctx, pool, advisoryKey)

	collectDone := make(chan any, 1)
	go func() {
		defer func() { collectDone <- recover() }()
		storage.collect(ctx)
	}()
	waitForPostgresQueryWait(t, ctx, pool, applicationName, "DELETE FROM "+quoteIdent(firstID), "advisory")

	deleted, err := storage.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: staleID, Force: true})
	if err != nil || deleted == nil {
		t.Fatalf("delete queue from captured GC snapshot: %#v, %v", deleted, err)
	}
	commitPostgresBlocker(t, ctx, blocker)

	select {
	case recovered := <-collectDone:
		if recovered != nil {
			t.Errorf("collection panicked after concurrent queue deletion: %v", recovered)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("collection did not finish after concurrent queue deletion")
	}
	assertPostgresQueueMessageCount(t, ctx, pool, laterID, 0)
}

type postgresSweepOutcome struct {
	result *sweepResult
	err    error
}

func createPostgresDeadLetterQueues(t *testing.T, ctx context.Context, storage *Storage) (string, string) {
	t.Helper()
	targetID := createPostgresDropQueue(t, ctx, storage, "gc-dead-letter-target")
	source, err := storage.CreateQueue(ctx, &v1.CreateQueueRequest{
		QueueName:          "gc-dead-letter-source",
		MaxReceiveAttempts: 1,
		EvictionPolicy:     v1.EvictionPolicy_EVICTION_POLICY_DEAD_LETTER,
		DeadLetterQueueId:  targetID,
	})
	if err != nil {
		t.Fatalf("create dead-letter source: %v", err)
	}
	return source.QueueId, targetID
}

func createPostgresDropQueue(t *testing.T, ctx context.Context, storage *Storage, name string) string {
	t.Helper()
	created, err := storage.CreateQueue(ctx, &v1.CreateQueueRequest{
		QueueName:      name,
		EvictionPolicy: v1.EvictionPolicy_EVICTION_POLICY_DROP,
	})
	if err != nil {
		t.Fatalf("create DROP queue: %v", err)
	}
	return created.QueueId
}

func makePostgresMessageEvictable(
	t *testing.T,
	ctx context.Context,
	storage *Storage,
	pool *pgxpool.Pool,
	queueID string,
	createdAt time.Time,
) {
	t.Helper()
	response, err := storage.Send(ctx, &v1.SendRequest{
		QueueId:  queueID,
		Messages: []*v1.SendMessage{{Body: []byte("evict me")}},
	})
	if err != nil {
		t.Fatalf("send evictable message: %v", err)
	}
	if len(response.MessageIds) != 1 {
		t.Fatalf("send returned %d message IDs, want 1", len(response.MessageIds))
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(
		`UPDATE %s SET retries = 999, created_at = $1, visible_at = now() + interval '1 hour' WHERE msg_id = $2`,
		quoteIdent(queueID),
	), createdAt, response.MessageIds[0]); err != nil {
		t.Fatalf("make message eligible for sweep: %v", err)
	}
}

func installBlockingQueueInsertTrigger(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	queueID string,
	advisoryKey int64,
) {
	t.Helper()
	query := fmt.Sprintf(`
CREATE FUNCTION block_gc_queue_insert() RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
  PERFORM pg_advisory_xact_lock(%d);
  RETURN NEW;
END;
$function$;
CREATE TRIGGER block_gc_queue_insert
BEFORE INSERT ON %s
FOR EACH ROW EXECUTE FUNCTION block_gc_queue_insert();`, advisoryKey, quoteIdent(queueID))
	if _, err := pool.Exec(ctx, query); err != nil {
		t.Fatalf("create blocking queue-insert trigger: %v", err)
	}
}

func installBlockingQueueMessageDeleteTrigger(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	queueID string,
	advisoryKey int64,
) {
	t.Helper()
	query := fmt.Sprintf(`
CREATE FUNCTION block_gc_message_delete() RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
  PERFORM pg_advisory_xact_lock(%d);
  RETURN OLD;
END;
$function$;
CREATE TRIGGER block_gc_message_delete
BEFORE DELETE ON %s
FOR EACH ROW EXECUTE FUNCTION block_gc_message_delete();`, advisoryKey, quoteIdent(queueID))
	if _, err := pool.Exec(ctx, query); err != nil {
		t.Fatalf("create blocking message-delete trigger: %v", err)
	}
}

func waitForPostgresOneOfQueryWait(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	applicationName string,
	firstPrefix string,
	secondPrefix string,
) string {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for {
		var query string
		err := pool.QueryRow(ctx, `SELECT query FROM pg_stat_activity
WHERE application_name = $1
  AND wait_event_type = 'Lock'
  AND (left(query, length($2)) = $2 OR left(query, length($3)) = $3)
LIMIT 1`, applicationName, firstPrefix, secondPrefix).Scan(&query)
		if err == nil {
			if len(query) >= len(firstPrefix) && query[:len(firstPrefix)] == firstPrefix {
				return firstPrefix
			}
			return secondPrefix
		}
		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatalf("PostgreSQL queries %q and %q did not reach a lock wait", firstPrefix, secondPrefix)
		case <-ctx.Done():
			t.Fatalf("wait for PostgreSQL lock order: %v", ctx.Err())
		}
	}
}

func awaitPostgresSweep(t *testing.T, done <-chan postgresSweepOutcome) postgresSweepOutcome {
	t.Helper()
	select {
	case outcome := <-done:
		return outcome
	case <-time.After(10 * time.Second):
		t.Fatal("PostgreSQL sweep did not finish")
		return postgresSweepOutcome{}
	}
}

func awaitPostgresQueueDelete(t *testing.T, done <-chan postgresQueueDeleteOutcome) postgresQueueDeleteOutcome {
	t.Helper()
	select {
	case outcome := <-done:
		return outcome
	case <-time.After(10 * time.Second):
		t.Fatal("PostgreSQL queue delete did not finish")
		return postgresQueueDeleteOutcome{}
	}
}

func assertPostgresQueueMessageCount(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	queueID string,
	want int64,
) {
	t.Helper()
	var got int64
	if err := pool.QueryRow(ctx, queryCountMessages(queueID)).Scan(&got); err != nil {
		t.Fatalf("count queue %q messages: %v", queueID, err)
	}
	if got != want {
		t.Fatalf("queue %q message count = %d, want %d", queueID, got, want)
	}
}

func newPostgresTestStorage(t *testing.T) *Storage {
	t.Helper()

	dsn := os.Getenv("PLAINQ_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PLAINQ_TEST_POSTGRES_DSN is not set")
	}

	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open postgres admin pool: %v", err)
	}
	t.Cleanup(admin.Close)

	schema := fmt.Sprintf("queue_store_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatalf("create postgres schema: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Errorf("drop postgres schema: %v", err)
		}
	})

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse postgres DSN: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("open postgres fixture pool: %v", err)
	}
	t.Cleanup(pool.Close)

	storageFS, err := mutations.ValidatedStorageFS(mutations.PostgresStorageMutations())
	if err != nil {
		t.Fatalf("validate postgres migrations: %v", err)
	}
	entries, err := fs.ReadDir(storageFS, ".")
	if err != nil {
		t.Fatalf("read postgres migrations: %v", err)
	}
	for _, entry := range entries {
		changes, err := fs.ReadFile(storageFS, entry.Name())
		if err != nil {
			t.Fatalf("read postgres migration %s: %v", entry.Name(), err)
		}
		if _, err := pool.Exec(ctx, string(changes)); err != nil {
			t.Fatalf("apply postgres migration %s: %v", entry.Name(), err)
		}
	}

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
