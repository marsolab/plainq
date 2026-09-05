package pgstore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/marsolab/servekit/idkit"

	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/principal"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
)

func TestPostgresListTopicsWorksWithSingleConnectionPool(t *testing.T) {
	ctx, first, pool, _ := newPostgresPubSubStorage(t)
	if _, err := first.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "single-connection"}); err != nil {
		t.Fatalf("create topic: %v", err)
	}

	config := pool.Config()
	config.MaxConns = 1
	singlePool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("open single-connection PostgreSQL pool: %v", err)
	}
	t.Cleanup(singlePool.Close)

	single, err := New(singlePool)
	if err != nil {
		t.Fatalf("create single-connection PostgreSQL storage: %v", err)
	}
	t.Cleanup(func() {
		if err := single.Close(); err != nil {
			t.Errorf("close single-connection PostgreSQL storage: %v", err)
		}
	})

	listCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	listed, err := single.ListTopics(listCtx)
	if err != nil {
		t.Fatalf("list topics with one pooled connection: %v", err)
	}
	if len(listed.Topics) != 1 || listed.Topics[0].TopicName != "single-connection" {
		t.Fatalf("listed topics = %#v, want single-connection topic", listed.Topics)
	}
}

func TestPostgresConcurrentCreateQueuesAcrossStorages(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	first := newPostgresTestStorage(t)

	secondPool, err := pgxpool.NewWithConfig(ctx, first.pool.Config())
	if err != nil {
		t.Fatalf("open second PostgreSQL pool: %v", err)
	}
	t.Cleanup(secondPool.Close)

	second, err := New(secondPool)
	if err != nil {
		t.Fatalf("create second PostgreSQL storage: %v", err)
	}
	t.Cleanup(func() {
		if err := second.Close(); err != nil {
			t.Errorf("close second PostgreSQL storage: %v", err)
		}
	})

	const queueCount = 20
	tenantID := idkit.XID()
	seedPostgresPolicyTenant(t, first, tenantID, queueCount)
	if _, err := first.pool.Exec(ctx, `UPDATE tenant_quotas SET max_queues = $1 WHERE tenant_id = $2`, queueCount, tenantID); err != nil {
		t.Fatalf("raise PostgreSQL queue quota: %v", err)
	}
	actor := principal.Principal{Kind: principal.KindSystem, ID: "concurrent-create-test", TenantID: tenantID}
	actorCtx := principal.With(ctx, actor)
	createdAt := time.Now().UTC()

	start := make(chan struct{})
	results := make(chan error, queueCount)

	var group sync.WaitGroup
	for i := range queueCount {
		store := first
		if i%2 == 1 {
			store = second
		}
		queueName := fmt.Sprintf("concurrent-%02d", i)

		group.Add(1)
		go func() {
			defer group.Done()
			<-start

			mutation := buildPostgresQueueMutation(
				tenantID, actor.Ref(), authz.ActionQueueCreate, authz.ResourceTenant,
				tenantID, queueName, createdAt, 1,
			)
			if _, err := store.CreateQueuePolicy(actorCtx, &v1.CreateQueueRequest{QueueName: queueName}, mutation); err != nil {
				results <- fmt.Errorf("create %q: %w", queueName, err)
			}
		}()
	}

	close(start)
	group.Wait()
	close(results)

	var failures []error
	for err := range results {
		failures = append(failures, err)
	}
	if len(failures) > 0 {
		t.Fatalf("%d/%d concurrent queue creates failed: %v", len(failures), queueCount, errors.Join(failures...))
	}

	assertPostgresCount(t, first, `SELECT count(*) FROM queue_properties WHERE tenant_id = $1`, []any{tenantID}, queueCount)
	assertPostgresCount(t, first, `SELECT queue_count FROM tenant_resource_usage WHERE tenant_id = $1`, []any{tenantID}, queueCount)
	assertPostgresCount(t, first, `SELECT used FROM quota_windows WHERE tenant_id = $1 AND action = $2`,
		[]any{tenantID, authz.ActionQueueCreate}, queueCount)
	assertPostgresCount(t, first, `SELECT count(*) FROM security_audit_events WHERE tenant_id = $1 AND action = $2`,
		[]any{tenantID, authz.ActionQueueCreate}, queueCount)
	assertPostgresCount(t, first, `SELECT count(*) FROM agent_idempotency WHERE tenant_id = $1 AND operation = $2`,
		[]any{tenantID, authz.ActionQueueCreate}, queueCount)
}
