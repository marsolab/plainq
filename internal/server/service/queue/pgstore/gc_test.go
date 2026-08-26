package pgstore

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
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
	)
	if err := pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT created_at, visible_at FROM %s`, quoteIdent(targetID),
	)).Scan(&movedCreatedAt, &movedVisibleAt); err != nil {
		t.Fatalf("read moved message timestamps: %v", err)
	}
	if !movedCreatedAt.Equal(createdAt) {
		t.Fatalf("moved created_at = %s, want %s", movedCreatedAt, createdAt)
	}
	if movedVisibleAt.After(time.Now()) {
		t.Fatalf("moved visible_at = %s, want immediately visible", movedVisibleAt)
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
