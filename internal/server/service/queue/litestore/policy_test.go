package litestore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/policytx"
	"github.com/marsolab/plainq/internal/server/principal"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	queueservice "github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/server/service/quota"
	"github.com/marsolab/plainq/internal/server/service/securityaudit"
)

func TestQueuePolicyIdempotentRetryDoesNotConsumeQuotaTwice(t *testing.T) {
	ctx := principal.With(context.Background(), principal.Principal{
		Kind: principal.KindSystem, ID: principal.LegacyPrincipalID, TenantID: principal.LegacyTenantID,
	})
	conn := newMigratedConn(t)
	store := newTestStorage(t, conn)
	now := time.Unix(100, 0).UTC()

	created, err := store.CreateQueuePolicy(ctx, &v1.CreateQueueRequest{QueueName: "policy-queue"},
		queueMutation(authz.ActionQueueCreate, authz.ResourceTenant, principal.LegacyTenantID, "create-1", now, 1))
	if err != nil {
		t.Fatalf("create policy queue: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `UPDATE tenant_quotas SET send_per_second = 1 WHERE tenant_id = ?`,
		principal.LegacyTenantID); err != nil {
		t.Fatalf("set send quota: %v", err)
	}

	request := &v1.SendRequest{QueueId: created.GetQueueId(), Messages: []*v1.SendMessage{{Body: []byte("once")}}}
	mutation := queueMutation(authz.ActionQueueSend, authz.ResourceQueue, created.GetQueueId(), "send-1", now, 1)
	first, err := store.SendPolicy(ctx, request, mutation)
	if err != nil {
		t.Fatalf("first policy send: %v", err)
	}
	second, err := store.SendPolicy(ctx, request, mutation)
	if err != nil {
		t.Fatalf("idempotent policy send: %v", err)
	}
	if fmt.Sprint(first.GetMessageIds()) != fmt.Sprint(second.GetMessageIds()) {
		t.Fatalf("replayed message IDs = %v, want %v", second.GetMessageIds(), first.GetMessageIds())
	}

	conflicting := queueMutation(authz.ActionQueueSend, authz.ResourceQueue, created.GetQueueId(), "send-2", now, 1)
	if _, err := store.SendPolicy(ctx, request, conflicting); !errors.Is(err, quota.ErrExhausted) {
		t.Fatalf("second unique policy send error = %v, want quota exhausted", err)
	}

	assertSQLiteCount(t, conn, `SELECT count(*) FROM `+created.GetQueueId(), nil, 1)
	assertSQLiteCount(t, conn, `SELECT used FROM quota_windows WHERE tenant_id = ? AND action = ?`,
		[]any{principal.LegacyTenantID, authz.ActionQueueSend}, 1)
	assertSQLiteCount(t, conn, `SELECT count(*) FROM security_audit_events WHERE tenant_id = ? AND action = ?`,
		[]any{principal.LegacyTenantID, authz.ActionQueueSend}, 1)
	assertSQLiteCount(t, conn, `SELECT count(*) FROM agent_idempotency WHERE tenant_id = ? AND operation = ?`,
		[]any{principal.LegacyTenantID, authz.ActionQueueSend}, 1)
}

func TestQueuePolicyPublishFanoutIsIdempotentAndAuditedOnce(t *testing.T) {
	ctx := principal.With(context.Background(), principal.Principal{
		Kind: principal.KindSystem, ID: principal.LegacyPrincipalID, TenantID: principal.LegacyTenantID,
	})
	conn := newMigratedConn(t)
	store := newTestStorage(t, conn)
	now := time.Unix(175, 0).UTC()

	queues := make([]string, 0, 2)
	for index := range 2 {
		created, err := store.CreateQueuePolicy(ctx, &v1.CreateQueueRequest{QueueName: fmt.Sprintf("fanout-%d", index)},
			queueMutation(authz.ActionQueueCreate, authz.ResourceTenant, principal.LegacyTenantID,
				fmt.Sprintf("fanout-queue-%d", index), now, 1))
		if err != nil {
			t.Fatalf("create fanout queue %d: %v", index, err)
		}
		queues = append(queues, created.GetQueueId())
	}

	topic, err := store.CreateTopicPolicy(ctx, &queueservice.CreateTopicRequest{TopicName: "fanout"},
		queueMutation(authz.ActionTopicCreate, authz.ResourceTenant, principal.LegacyTenantID, "fanout-topic", now, 1))
	if err != nil {
		t.Fatalf("create fanout topic: %v", err)
	}
	for index, queueID := range queues {
		if _, err := store.SubscribePolicy(ctx, topic.TopicID, &queueservice.SubscribeRequest{QueueID: queueID},
			queueMutation(authz.ActionTopicSubscribe, authz.ResourceTopic, topic.TopicID,
				fmt.Sprintf("fanout-sub-%d", index), now, 1)); err != nil {
			t.Fatalf("subscribe fanout queue %d: %v", index, err)
		}
	}

	request := &queueservice.PublishRequest{Messages: []queueservice.PublishMessage{{Body: []byte("abc")}}}
	mutation := queueMutation(authz.ActionTopicPublish, authz.ResourceTopic, topic.TopicID, "fanout-publish", now, 1)
	first, err := store.PublishPolicy(ctx, topic.TopicID, request, mutation)
	if err != nil {
		t.Fatalf("publish fanout message: %v", err)
	}
	second, err := store.PublishPolicy(ctx, topic.TopicID, request, mutation)
	if err != nil {
		t.Fatalf("replay fanout message: %v", err)
	}
	if fmt.Sprint(first.MessageIDs) != fmt.Sprint(second.MessageIDs) {
		t.Fatalf("replayed published IDs = %v, want %v", second.MessageIDs, first.MessageIDs)
	}
	for _, queueID := range queues {
		assertSQLiteCount(t, conn, `SELECT count(*) FROM `+queueID, nil, 1)
	}
	assertSQLiteCount(t, conn, `SELECT used FROM quota_windows WHERE tenant_id = ? AND action = ?`,
		[]any{principal.LegacyTenantID, authz.ActionTopicPublish}, 1)
	assertSQLiteCount(t, conn, `SELECT count(*) FROM security_audit_events WHERE tenant_id = ? AND action = ?`,
		[]any{principal.LegacyTenantID, authz.ActionTopicPublish}, 1)
	assertSQLiteCount(t, conn, `SELECT count(*) FROM agent_idempotency WHERE tenant_id = ? AND operation = ?`,
		[]any{principal.LegacyTenantID, authz.ActionTopicPublish}, 1)
}

func TestQueuePolicyAuditFailureRollsBackResourceQuotaLedgerAndIdempotency(t *testing.T) {
	ctx := principal.With(context.Background(), principal.Principal{
		Kind: principal.KindSystem, ID: principal.LegacyPrincipalID, TenantID: principal.LegacyTenantID,
	})
	conn := newMigratedConn(t)
	store := newTestStorage(t, conn)
	now := time.Unix(200, 0).UTC()

	if _, err := conn.ExecContext(ctx, `CREATE TRIGGER reject_queue_policy_audit
		BEFORE INSERT ON security_audit_events WHEN NEW.action = 'queue.create'
		BEGIN SELECT RAISE(ABORT, 'injected queue audit failure'); END`); err != nil {
		t.Fatalf("create queue audit trigger: %v", err)
	}

	_, err := store.CreateQueuePolicy(ctx, &v1.CreateQueueRequest{QueueName: "must-rollback"},
		queueMutation(authz.ActionQueueCreate, authz.ResourceTenant, principal.LegacyTenantID, "create-fail", now, 1))
	if err == nil {
		t.Fatal("CreateQueuePolicy() error = nil, want injected audit failure")
	}

	assertSQLiteCount(t, conn, `SELECT count(*) FROM queue_properties WHERE tenant_id = ?`,
		[]any{principal.LegacyTenantID}, 0)
	assertSQLiteCount(t, conn, `SELECT queue_count FROM tenant_resource_usage WHERE tenant_id = ?`,
		[]any{principal.LegacyTenantID}, 0)
	assertSQLiteCount(t, conn, `SELECT count(*) FROM quota_windows WHERE tenant_id = ? AND action = ?`,
		[]any{principal.LegacyTenantID, authz.ActionQueueCreate}, 0)
	assertSQLiteCount(t, conn, `SELECT count(*) FROM agent_idempotency WHERE tenant_id = ? AND operation = ?`,
		[]any{principal.LegacyTenantID, authz.ActionQueueCreate}, 0)
	assertSQLiteCount(t, conn, `SELECT count(*) FROM security_audit_events WHERE tenant_id = ? AND action = ?`,
		[]any{principal.LegacyTenantID, authz.ActionQueueCreate}, 0)
}

func TestQueueOperationsHideCrossTenantAndHonorDirectAgentGrant(t *testing.T) {
	ctx := context.Background()
	conn := newMigratedConn(t)
	store := newTestStorage(t, conn)
	legacyCtx := principal.With(ctx, principal.Principal{
		Kind: principal.KindSystem, ID: principal.LegacyPrincipalID, TenantID: principal.LegacyTenantID,
	})
	created, err := store.CreateQueue(legacyCtx, &v1.CreateQueueRequest{QueueName: "private"})
	if err != nil {
		t.Fatalf("create private queue: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO organizations (org_id, org_code, org_name)
		VALUES ('tenant-b', 'tenant-b', 'Tenant B')`); err != nil {
		t.Fatalf("seed tenant B: %v", err)
	}

	operations, err := queueservice.NewOperations(store, nil)
	if err != nil {
		t.Fatalf("new queue operations: %v", err)
	}
	crossTenant := principal.With(ctx, principal.Principal{
		Kind: principal.KindHuman, ID: "admin-b", TenantID: "tenant-b", Roles: []string{"admin"},
	})
	if _, err := operations.DescribeQueue(crossTenant, &v1.DescribeQueueRequest{
		QueueId: created.GetQueueId(),
	}); !errors.Is(err, authz.ErrNotFound) {
		t.Fatalf("cross-tenant describe error = %v, want not found", err)
	}

	for _, agentID := range []string{"agent-granted", "agent-denied"} {
		if _, err := conn.ExecContext(ctx, `INSERT INTO security_principals (
			tenant_id, principal_kind, principal_id, status, roles_json, auth_version, updated_at_ns
		) VALUES (?, 'agent', ?, 'active', '["agent"]', 1, 0)`, principal.LegacyTenantID, agentID); err != nil {
			t.Fatalf("seed %s principal: %v", agentID, err)
		}
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO agent_resource_grants (
		grant_id, tenant_id, subject_kind, subject_id, resource_kind, resource_id, action, created_at_ns
	) VALUES ('grant-send', ?, 'agent', 'agent-granted', 'queue', ?, 'queue.send', 0)`,
		principal.LegacyTenantID, created.GetQueueId()); err != nil {
		t.Fatalf("seed direct queue grant: %v", err)
	}

	request := &v1.SendRequest{QueueId: created.GetQueueId(), Messages: []*v1.SendMessage{{Body: []byte("granted")}}}
	grantedCtx := principal.With(ctx, principal.Principal{
		Kind: principal.KindAgent, ID: "agent-granted", TenantID: principal.LegacyTenantID,
	})
	if _, err := operations.Send(grantedCtx, request); err != nil {
		t.Fatalf("directly granted agent send: %v", err)
	}
	deniedCtx := principal.With(ctx, principal.Principal{
		Kind: principal.KindAgent, ID: "agent-denied", TenantID: principal.LegacyTenantID,
	})
	if _, err := operations.Send(deniedCtx, request); !errors.Is(err, authz.ErrPermissionDenied) {
		t.Fatalf("ungranted agent send error = %v, want permission denied", err)
	}
}

func queueMutation(
	action authz.Action,
	resourceType authz.ResourceType,
	resourceID, key string,
	now time.Time,
	rateUnits uint64,
) policytx.Mutation {
	hash := sha256.Sum256([]byte(key))
	resource := authz.Resource{Type: resourceType, TenantID: principal.LegacyTenantID, ID: resourceID}

	return policytx.Mutation{
		TenantID: principal.LegacyTenantID,
		Actor:    principal.Ref{Kind: principal.KindSystem, ID: principal.LegacyPrincipalID},
		Action:   action, Resource: resource, IdempotencyKey: key, RequestHash: hash, RateUnits: rateUnits,
		Audit: securityaudit.Event{
			EventID: "audit-" + key, TenantID: principal.LegacyTenantID,
			ActorKind: principal.KindSystem, ActorID: principal.LegacyPrincipalID,
			Action: string(action), ResourceType: string(resourceType), ResourceID: resourceID,
			Outcome: "success", CreatedAt: now,
		},
	}
}

func assertSQLiteCount(t *testing.T, conn interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, query string, args []any, want int64) {
	t.Helper()
	var got int64
	if err := conn.QueryRowContext(context.Background(), query, args...).Scan(&got); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	if got != want {
		t.Fatalf("query %q = %d, want %d", query, got, want)
	}
}
