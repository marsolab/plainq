package pgstore

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/marsolab/servekit/idkit"

	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/policytx"
	"github.com/marsolab/plainq/internal/server/principal"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/server/service/quota"
	"github.com/marsolab/plainq/internal/server/service/securityaudit"
)

func TestPostgresQueuePolicyIdempotencyAndAtomicRollback(t *testing.T) {
	ctx := context.Background()
	store := newPostgresTestStorage(t)

	t.Run("idempotent retry consumes quota once", func(t *testing.T) {
		tenantID := idkit.XID()
		seedPostgresPolicyTenant(t, store, tenantID, 1)
		actor := principal.Principal{Kind: principal.KindSystem, ID: "policy-test", TenantID: tenantID}
		actorCtx := principal.With(ctx, actor)
		now := time.Unix(300, 0).UTC()

		created, err := store.CreateQueuePolicy(actorCtx, &v1.CreateQueueRequest{QueueName: "policy-queue"},
			buildPostgresQueueMutation(tenantID, actor.Ref(), authz.ActionQueueCreate, authz.ResourceTenant, tenantID, "create-1", now, 1))
		if err != nil {
			t.Fatalf("create policy queue: %v", err)
		}
		t.Cleanup(func() {
			_, _ = store.DeleteQueue(actorCtx, &v1.DeleteQueueRequest{QueueId: created.GetQueueId(), Force: true})
		})

		request := &v1.SendRequest{
			QueueId:  created.GetQueueId(),
			Messages: []*v1.SendMessage{{Body: []byte("once")}},
		}
		mutation := buildPostgresQueueMutation(
			tenantID, actor.Ref(), authz.ActionQueueSend, authz.ResourceQueue,
			created.GetQueueId(), "send-1", now, 1,
		)
		first, err := store.SendPolicy(actorCtx, request, mutation)
		if err != nil {
			t.Fatalf("first policy send: %v", err)
		}
		second, err := store.SendPolicy(actorCtx, request, mutation)
		if err != nil {
			t.Fatalf("idempotent policy send: %v", err)
		}
		if fmt.Sprint(first.GetMessageIds()) != fmt.Sprint(second.GetMessageIds()) {
			t.Fatalf("replayed message IDs = %v, want %v", second.GetMessageIds(), first.GetMessageIds())
		}

		conflicting := buildPostgresQueueMutation(
			tenantID, actor.Ref(), authz.ActionQueueSend, authz.ResourceQueue,
			created.GetQueueId(), "send-2", now, 1,
		)
		if _, err := store.SendPolicy(actorCtx, request, conflicting); !errors.Is(err, quota.ErrExhausted) {
			t.Fatalf("second unique policy send error = %v, want quota exhausted", err)
		}

		assertPostgresCount(t, store, `SELECT count(*) FROM `+quoteIdent(created.GetQueueId()), nil, 1)
		assertPostgresCount(t, store, `SELECT used FROM quota_windows WHERE tenant_id = $1 AND action = $2`,
			[]any{tenantID, authz.ActionQueueSend}, 1)
		assertPostgresCount(t, store, `SELECT count(*) FROM security_audit_events WHERE tenant_id = $1 AND action = $2`,
			[]any{tenantID, authz.ActionQueueSend}, 1)
		assertPostgresCount(t, store, `SELECT count(*) FROM agent_idempotency WHERE tenant_id = $1 AND operation = $2`,
			[]any{tenantID, authz.ActionQueueSend}, 1)

		if _, err := store.DeletePolicy(actorCtx, &v1.DeleteRequest{
			QueueId: created.GetQueueId(), MessageIds: first.GetMessageIds(),
		}, buildPostgresQueueMutation(
			tenantID, actor.Ref(), authz.ActionQueueAck, authz.ResourceQueue,
			created.GetQueueId(), "ack-1", now, 1,
		)); err != nil {
			t.Fatalf("ack postgres policy message: %v", err)
		}
		assertPostgresCount(t, store, `SELECT count(*) FROM `+quoteIdent(created.GetQueueId()), nil, 0)
	})

	t.Run("audit failure rolls back resource quota and ledger", func(t *testing.T) {
		tenantID := idkit.XID()
		seedPostgresPolicyTenant(t, store, tenantID, 10)
		actor := principal.Principal{Kind: principal.KindSystem, ID: "policy-test", TenantID: tenantID}
		actorCtx := principal.With(ctx, actor)
		now := time.Unix(400, 0).UTC()

		if _, err := store.pool.Exec(ctx, `CREATE OR REPLACE FUNCTION reject_queue_policy_audit()
			RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
				IF NEW.action = 'queue.create' THEN
					RAISE EXCEPTION 'injected queue audit failure';
				END IF;
				RETURN NEW;
			END $$;
			CREATE TRIGGER reject_queue_policy_audit
			BEFORE INSERT ON security_audit_events
			FOR EACH ROW EXECUTE FUNCTION reject_queue_policy_audit()`); err != nil {
			t.Fatalf("create postgres audit trigger: %v", err)
		}
		t.Cleanup(func() {
			if _, err := store.pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS reject_queue_policy_audit
				ON security_audit_events; DROP FUNCTION IF EXISTS reject_queue_policy_audit()`); err != nil {
				t.Errorf("drop postgres audit failure trigger: %v", err)
			}
		})

		_, err := store.CreateQueuePolicy(actorCtx, &v1.CreateQueueRequest{QueueName: "must-rollback"},
			buildPostgresQueueMutation(tenantID, actor.Ref(), authz.ActionQueueCreate, authz.ResourceTenant, tenantID, "create-fail", now, 1))
		if err == nil {
			t.Fatal("CreateQueuePolicy() error = nil, want injected audit failure")
		}

		assertPostgresCount(t, store, `SELECT count(*) FROM queue_properties WHERE tenant_id = $1`, []any{tenantID}, 0)
		assertPostgresCount(t, store, `SELECT queue_count FROM tenant_resource_usage WHERE tenant_id = $1`, []any{tenantID}, 0)
		assertPostgresCount(t, store, `SELECT count(*) FROM quota_windows WHERE tenant_id = $1 AND action = $2`,
			[]any{tenantID, authz.ActionQueueCreate}, 0)
		assertPostgresCount(t, store, `SELECT count(*) FROM agent_idempotency WHERE tenant_id = $1 AND operation = $2`,
			[]any{tenantID, authz.ActionQueueCreate}, 0)
		assertPostgresCount(t, store, `SELECT count(*) FROM security_audit_events WHERE tenant_id = $1 AND action = $2`,
			[]any{tenantID, authz.ActionQueueCreate}, 0)
	})

	t.Run("publish fanout is idempotent and audited once", func(t *testing.T) {
		tenantID := idkit.XID()
		seedPostgresPolicyTenant(t, store, tenantID, 10)
		actor := principal.Principal{Kind: principal.KindSystem, ID: "policy-test", TenantID: tenantID}
		actorCtx := principal.With(ctx, actor)
		now := time.Unix(500, 0).UTC()

		queueIDs := make([]string, 0, 2)
		for index := range 2 {
			created, err := store.CreateQueuePolicy(actorCtx, &v1.CreateQueueRequest{
				QueueName: fmt.Sprintf("pg-fanout-%d", index),
			}, buildPostgresQueueMutation(
				tenantID, actor.Ref(), authz.ActionQueueCreate, authz.ResourceTenant,
				tenantID, fmt.Sprintf("pg-fanout-queue-%d", index), now, 1,
			))
			if err != nil {
				t.Fatalf("create postgres fanout queue %d: %v", index, err)
			}
			queueIDs = append(queueIDs, created.GetQueueId())
		}

		topic, err := store.CreateTopicPolicy(actorCtx, &queue.CreateTopicRequest{TopicName: "pg-fanout"},
			buildPostgresQueueMutation(
				tenantID, actor.Ref(), authz.ActionTopicCreate, authz.ResourceTenant,
				tenantID, "pg-fanout-topic", now, 1,
			))
		if err != nil {
			t.Fatalf("create postgres fanout topic: %v", err)
		}
		for index, queueID := range queueIDs {
			if _, err := store.SubscribePolicy(actorCtx, topic.TopicID, &queue.SubscribeRequest{QueueID: queueID},
				buildPostgresQueueMutation(
					tenantID, actor.Ref(), authz.ActionTopicSubscribe, authz.ResourceTopic,
					topic.TopicID, fmt.Sprintf("pg-fanout-sub-%d", index), now, 1,
				)); err != nil {
				t.Fatalf("subscribe postgres fanout queue %d: %v", index, err)
			}
		}

		request := &queue.PublishRequest{Messages: []queue.PublishMessage{{Body: []byte("abc")}}}
		mutation := buildPostgresQueueMutation(
			tenantID, actor.Ref(), authz.ActionTopicPublish, authz.ResourceTopic,
			topic.TopicID, "pg-fanout-publish", now, 1,
		)
		first, err := store.PublishPolicy(actorCtx, topic.TopicID, request, mutation)
		if err != nil {
			t.Fatalf("publish postgres fanout message: %v", err)
		}
		second, err := store.PublishPolicy(actorCtx, topic.TopicID, request, mutation)
		if err != nil {
			t.Fatalf("replay postgres fanout message: %v", err)
		}
		if fmt.Sprint(first.MessageIDs) != fmt.Sprint(second.MessageIDs) {
			t.Fatalf("replayed postgres published IDs = %v, want %v", second.MessageIDs, first.MessageIDs)
		}
		for _, queueID := range queueIDs {
			assertPostgresCount(t, store, `SELECT count(*) FROM `+quoteIdent(queueID), nil, 1)
		}
		assertPostgresCount(t, store, `SELECT used FROM quota_windows WHERE tenant_id = $1 AND action = $2`,
			[]any{tenantID, authz.ActionTopicPublish}, 1)
		assertPostgresCount(t, store, `SELECT count(*) FROM security_audit_events WHERE tenant_id = $1 AND action = $2`,
			[]any{tenantID, authz.ActionTopicPublish}, 1)
		assertPostgresCount(t, store, `SELECT count(*) FROM agent_idempotency WHERE tenant_id = $1 AND operation = $2`,
			[]any{tenantID, authz.ActionTopicPublish}, 1)

		for index, queueID := range queueIDs {
			if _, err := store.PurgeQueuePolicy(actorCtx, &v1.PurgeQueueRequest{QueueId: queueID},
				buildPostgresQueueMutation(
					tenantID, actor.Ref(), authz.ActionQueuePurge, authz.ResourceQueue,
					queueID, fmt.Sprintf("pg-fanout-purge-%d", index), now, 1,
				)); err != nil {
				t.Fatalf("purge postgres fanout queue %d: %v", index, err)
			}
		}
		for _, queueID := range queueIDs {
			assertPostgresCount(t, store, `SELECT count(*) FROM `+quoteIdent(queueID), nil, 0)
		}
	})
}

func seedPostgresPolicyTenant(t *testing.T, store *Storage, tenantID string, sendLimit int64) {
	t.Helper()
	ctx := context.Background()
	t.Cleanup(func() {
		if _, err := store.pool.Exec(context.Background(), `DELETE FROM organizations WHERE org_id = $1`, tenantID); err != nil {
			t.Errorf("delete postgres policy tenant: %v", err)
		}
	})

	if _, err := store.pool.Exec(ctx, `INSERT INTO organizations (org_id, org_code, org_name)
		VALUES ($1, $2, $3)`, tenantID, tenantID, tenantID); err != nil {
		t.Fatalf("seed postgres policy organization: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO tenant_quotas (
		tenant_id, max_agents, max_credentials_per_agent, max_queues, max_topics,
		max_subscriptions, max_message_bytes, max_stored_bytes, send_per_second,
		publish_per_second, updated_at_ns
	) VALUES ($1, 10, 2, 10, 10, 10, 1048576, 1073741824, $2, 10, 0)`, tenantID, sendLimit); err != nil {
		t.Fatalf("seed postgres policy quota: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO tenant_resource_usage (
		tenant_id, agent_count, queue_count, topic_count, subscription_count,
		stored_messaging_bytes, updated_at_ns
	) VALUES ($1, 0, 0, 0, 0, 0, 0)`, tenantID); err != nil {
		t.Fatalf("seed postgres policy usage: %v", err)
	}
}

func buildPostgresQueueMutation(
	tenantID string,
	actor principal.Ref,
	action authz.Action,
	resourceType authz.ResourceType,
	resourceID, key string,
	now time.Time,
	rateUnits uint64,
) policytx.Mutation {
	hash := sha256.Sum256([]byte(key))

	return policytx.Mutation{
		TenantID:       tenantID,
		Actor:          actor,
		Action:         action,
		Resource:       authz.Resource{Type: resourceType, TenantID: tenantID, ID: resourceID},
		IdempotencyKey: key,
		RequestHash:    hash,
		RateUnits:      rateUnits,
		Audit: securityaudit.Event{
			EventID:      idkit.XID(),
			TenantID:     tenantID,
			ActorKind:    actor.Kind,
			ActorID:      actor.ID,
			Action:       string(action),
			ResourceType: string(resourceType),
			ResourceID:   resourceID,
			Outcome:      "success",
			CreatedAt:    now,
		},
	}
}

func assertPostgresCount(t *testing.T, store *Storage, query string, args []any, want int64) {
	t.Helper()
	var got int64
	if err := store.pool.QueryRow(context.Background(), query, args...).Scan(&got); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	if got != want {
		t.Fatalf("query %q = %d, want %d", query, got, want)
	}
}
