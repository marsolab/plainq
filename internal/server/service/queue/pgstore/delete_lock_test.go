package pgstore

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

func TestLockTopicForDeleteUsesParentRowLock(t *testing.T) {
	ctx := context.Background()
	scope := queue.ScopeFromContext(ctx)
	db := &parentLockDB{row: parentLockRow{value: "topic-1"}}
	if err := lockTopicForDeleteInScope(ctx, db, "topic-1", scope); err != nil {
		t.Fatalf("lock topic: %v", err)
	}
	if !strings.Contains(db.query, "FROM topic_properties") || !strings.Contains(db.query, "FOR UPDATE") {
		t.Fatalf("topic lock query = %q, want topic parent SELECT FOR UPDATE", db.query)
	}
}

func TestLockQueueForDeleteUsesParentRowLock(t *testing.T) {
	ctx := context.Background()
	scope := queue.ScopeFromContext(ctx)
	db := &parentLockDB{row: parentLockRow{value: "queue-1"}}
	if err := lockQueueForDeleteInScope(ctx, db, "queue-1", scope); err != nil {
		t.Fatalf("lock queue: %v", err)
	}
	if !strings.Contains(db.query, "FROM queue_properties") || !strings.Contains(db.query, "FOR UPDATE") {
		t.Fatalf("queue lock query = %q, want queue parent SELECT FOR UPDATE", db.query)
	}
}

func TestLockParentForDeleteMapsMissingParent(t *testing.T) {
	ctx := context.Background()
	scope := queue.ScopeFromContext(ctx)
	db := &parentLockDB{row: parentLockRow{err: pgx.ErrNoRows}}
	if err := lockTopicForDeleteInScope(ctx, db, "missing", scope); !errors.Is(err, pqerr.ErrNotFound) {
		t.Fatalf("lock missing topic error = %v, want %v", err, pqerr.ErrNotFound)
	}
	if err := lockQueueForDeleteInScope(ctx, db, "missing", scope); !errors.Is(err, pqerr.ErrNotFound) {
		t.Fatalf("lock missing queue error = %v, want %v", err, pqerr.ErrNotFound)
	}
}

func TestDeleteCaptureQueriesLockSubscriptionRowsInDeterministicOrder(t *testing.T) {
	tests := map[string]string{
		"topic": captureTopicSubscriptionsQuery,
		"queue": captureQueueSubscriptionsQuery,
	}
	for name, query := range tests {
		t.Run(name, func(t *testing.T) {
			order := strings.Index(query, "ORDER BY")
			lock := strings.Index(query, "FOR UPDATE OF s")
			if order < 0 || lock < 0 || order > lock {
				t.Fatalf("capture query = %q, want deterministic ORDER BY before FOR UPDATE OF s", query)
			}
		})
	}
}

type parentLockDB struct {
	query string
	row   pgx.Row
}

func (db *parentLockDB) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	db.query = query
	return db.row
}

type parentLockRow struct {
	value string
	err   error
}

func (r parentLockRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*string)) = r.value
	return nil
}
