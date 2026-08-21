package litestore

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/policytx"
	"github.com/marsolab/plainq/internal/server/principal"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/server/service/quota"
	"github.com/marsolab/plainq/internal/server/service/securityaudit"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

const (
	queuePolicyIdempotencyTTL = 24 * time.Hour
	auditMetadataMessageCount = "message_count"
)

var _ queue.PolicyStorage = (*Storage)(nil)
var _ authz.PolicyStore = (*Storage)(nil)

type sqliteQueueMutationKey struct{}

func withSQLiteQueueMutation(ctx context.Context, mutation policytx.Mutation) context.Context {
	return context.WithValue(ctx, sqliteQueueMutationKey{}, mutation)
}

func sqliteQueueMutation(ctx context.Context) (policytx.Mutation, bool) {
	mutation, ok := ctx.Value(sqliteQueueMutationKey{}).(policytx.Mutation)

	return mutation, ok
}

func (s *Storage) CreateQueuePolicy(
	ctx context.Context,
	input *v1.CreateQueueRequest,
	mutation policytx.Mutation,
) (*v1.CreateQueueResponse, error) {
	return s.CreateQueue(withSQLiteQueueMutation(ctx, mutation), input)
}

func (s *Storage) PurgeQueuePolicy(
	ctx context.Context,
	input *v1.PurgeQueueRequest,
	mutation policytx.Mutation,
) (*v1.PurgeQueueResponse, error) {
	return s.PurgeQueue(withSQLiteQueueMutation(ctx, mutation), input)
}

func (s *Storage) DeleteQueuePolicy(
	ctx context.Context,
	input *v1.DeleteQueueRequest,
	mutation policytx.Mutation,
) (*v1.DeleteQueueResponse, error) {
	return s.DeleteQueue(withSQLiteQueueMutation(ctx, mutation), input)
}

func (s *Storage) SendPolicy(
	ctx context.Context,
	input *v1.SendRequest,
	mutation policytx.Mutation,
) (*v1.SendResponse, error) {
	return s.Send(withSQLiteQueueMutation(ctx, mutation), input)
}

func (s *Storage) ReceivePolicy(
	ctx context.Context,
	input *v1.ReceiveRequest,
	mutation policytx.Mutation,
) (*v1.ReceiveResponse, error) {
	return s.Receive(withSQLiteQueueMutation(ctx, mutation), input)
}

func (s *Storage) DeletePolicy(
	ctx context.Context,
	input *v1.DeleteRequest,
	mutation policytx.Mutation,
) (*v1.DeleteResponse, error) {
	return s.Delete(withSQLiteQueueMutation(ctx, mutation), input)
}

func (s *Storage) CreateTopicPolicy(
	ctx context.Context,
	input *queue.CreateTopicRequest,
	mutation policytx.Mutation,
) (*queue.CreateTopicResponse, error) {
	return s.CreateTopic(withSQLiteQueueMutation(ctx, mutation), input)
}

func (s *Storage) DeleteTopicPolicy(ctx context.Context, topicID string, mutation policytx.Mutation) error {
	return s.DeleteTopic(withSQLiteQueueMutation(ctx, mutation), topicID)
}

func (s *Storage) SubscribePolicy(
	ctx context.Context,
	topicID string,
	input *queue.SubscribeRequest,
	mutation policytx.Mutation,
) (*queue.SubscribeResponse, error) {
	return s.Subscribe(withSQLiteQueueMutation(ctx, mutation), topicID, input)
}

func (s *Storage) UnsubscribePolicy(
	ctx context.Context,
	topicID, subscriptionID string,
	mutation policytx.Mutation,
) error {
	return s.Unsubscribe(withSQLiteQueueMutation(ctx, mutation), topicID, subscriptionID)
}

func (s *Storage) PublishPolicy(
	ctx context.Context,
	topicID string,
	input *queue.PublishRequest,
	mutation policytx.Mutation,
) (*queue.PublishResponse, error) {
	return s.Publish(withSQLiteQueueMutation(ctx, mutation), topicID, input)
}

func (s *Storage) ResolveQueueResource(
	ctx context.Context,
	tenantID, queueID, queueName string,
) (authz.Resource, error) {
	if tenantID == "" || (queueID == "") == (queueName == "") {
		return authz.Resource{}, fmt.Errorf("resolve queue resource: %w", pqerr.ErrInvalidInput)
	}

	scope := queue.ScopeFromContext(ctx)
	queryText := `SELECT queue_id FROM queue_properties
		WHERE tenant_id = ? AND (? = FALSE OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1')))`
	args := []any{tenantID, scope.Compatibility}

	if queueID != "" {
		queryText += ` AND queue_id = ?`

		args = append(args, queueID)
	} else {
		queryText += ` AND queue_name = ?`

		args = append(args, queueName)
	}

	var resolvedID string
	if err := s.db.QueryRowContext(ctx, queryText, args...).Scan(&resolvedID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return authz.Resource{}, authz.ErrNotFound
		}

		return authz.Resource{}, fmt.Errorf("resolve queue policy resource: %w", err)
	}

	return authz.Resource{Type: authz.ResourceQueue, TenantID: tenantID, ID: resolvedID}, nil
}

func (s *Storage) ResolveTopicResource(
	ctx context.Context,
	tenantID, topicID string,
) (authz.Resource, error) {
	if tenantID == "" || topicID == "" {
		return authz.Resource{}, fmt.Errorf("resolve topic resource: %w", pqerr.ErrInvalidInput)
	}

	scope := queue.ScopeFromContext(ctx)

	var resolvedID string

	err := s.db.QueryRowContext(ctx, `SELECT topic_id FROM topic_properties
		WHERE tenant_id = ? AND topic_id = ?
		  AND (? = FALSE OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1')))`,
		tenantID, topicID, scope.Compatibility,
	).Scan(&resolvedID)
	if errors.Is(err, sql.ErrNoRows) {
		return authz.Resource{}, authz.ErrNotFound
	}

	if err != nil {
		return authz.Resource{}, fmt.Errorf("resolve topic policy resource: %w", err)
	}

	return authz.Resource{Type: authz.ResourceTopic, TenantID: tenantID, ID: resolvedID}, nil
}

func (s *Storage) ResolveSubscriptionResource(
	ctx context.Context,
	tenantID, topicID, subscriptionID string,
) (authz.Resource, error) {
	if tenantID == "" || topicID == "" || subscriptionID == "" {
		return authz.Resource{}, fmt.Errorf("resolve subscription resource: %w", pqerr.ErrInvalidInput)
	}

	scope := queue.ScopeFromContext(ctx)

	var resolvedID string

	err := s.db.QueryRowContext(ctx, `SELECT s.subscription_id
		FROM topic_subscriptions s JOIN topic_properties t ON t.topic_id = s.topic_id
		WHERE t.tenant_id = ? AND s.topic_id = ? AND s.subscription_id = ?
		  AND (? = FALSE OR (t.created_by_kind = 'system' AND t.created_by_id IN ('migration', 'legacy-v1')))`,
		tenantID, topicID, subscriptionID, scope.Compatibility,
	).Scan(&resolvedID)
	if errors.Is(err, sql.ErrNoRows) {
		return authz.Resource{}, authz.ErrNotFound
	}

	if err != nil {
		return authz.Resource{}, fmt.Errorf("resolve subscription policy resource: %w", err)
	}

	return authz.Resource{Type: authz.ResourceSubscription, TenantID: tenantID, ID: resolvedID}, nil
}

func (s *Storage) HasGrant(
	ctx context.Context,
	p principal.Principal,
	action authz.Action,
	resource authz.Resource,
) (bool, error) {
	var granted bool

	err := s.db.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM agent_resource_grants g
		JOIN security_principals p ON p.tenant_id = g.tenant_id
		 AND p.principal_kind = g.subject_kind AND p.principal_id = g.subject_id AND p.status = 'active'
		WHERE g.tenant_id = ? AND g.subject_kind = ? AND g.subject_id = ?
		 AND g.resource_kind = ? AND g.resource_id = ? AND g.action = ?)`,
		p.TenantID, p.Kind, p.ID, resource.Type, resource.ID, action,
	).Scan(&granted)
	if err != nil {
		return false, fmt.Errorf("check sqlite direct policy grant: %w", err)
	}

	return granted, nil
}

func (s *Storage) HasLegacyPermission(
	ctx context.Context,
	p principal.Principal,
	action authz.Action,
	resource authz.Resource,
) (bool, error) {
	if p.Kind != principal.KindHuman {
		return false, nil
	}

	var granted bool

	err := s.db.QueryRowContext(ctx, `WITH effective_roles AS (
		SELECT ur.role_id FROM user_roles ur WHERE ur.user_id = ?
		UNION
		SELECT tr.role_id FROM user_teams ut
		JOIN teams t ON t.team_id = ut.team_id
		JOIN team_roles tr ON tr.team_id = t.team_id
		WHERE ut.user_id = ? AND t.org_id = ? AND t.is_active = TRUE
	)
	SELECT EXISTS (
		SELECT 1 FROM users u
		JOIN organizations o ON o.org_id = u.org_id AND o.is_active = TRUE
		JOIN effective_roles er
		JOIN roles r ON r.role_id = er.role_id
		LEFT JOIN queue_properties q ON q.queue_id = ? AND q.tenant_id = u.org_id
		LEFT JOIN queue_permissions qp ON qp.queue_id = q.queue_id AND qp.role_id = r.role_id
		WHERE u.user_id = ? AND u.org_id = ? AND u.status = 'active'
		AND (r.role_name = 'admin' OR (
			? = 'queue' AND q.queue_id IS NOT NULL AND CASE ?
				WHEN 'queue.send' THEN coalesce(qp.can_send, FALSE)
				WHEN 'queue.receive' THEN coalesce(qp.can_receive, FALSE)
				WHEN 'queue.read' THEN coalesce(qp.can_receive, FALSE)
				WHEN 'queue.ack' THEN coalesce(qp.can_delete, FALSE)
				WHEN 'queue.purge' THEN coalesce(qp.can_purge, FALSE)
				WHEN 'queue.delete' THEN coalesce(qp.can_delete, FALSE)
				ELSE FALSE END)))`,
		p.ID, p.ID, p.TenantID, resource.ID, p.ID, p.TenantID, resource.Type, action,
	).Scan(&granted)
	if err != nil {
		return false, fmt.Errorf("check sqlite retained policy permission: %w", err)
	}

	return granted, nil
}

func (s *Storage) AppendReadAudit(ctx context.Context, event securityaudit.Event) error {
	if err := event.Validate(); err != nil {
		return fmt.Errorf("validate sqlite read audit: %w", err)
	}

	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("encode read audit metadata: %w", err)
	}

	_, err = s.db.ExecContext(ctx, sqliteQueueAuditInsert,
		event.EventID, event.TenantID, event.ActorKind, event.ActorID, event.Action,
		event.ResourceType, event.ResourceID, event.Outcome, event.RequestID, event.Reason,
		event.SourceIP, event.UserAgent, string(metadata), event.CreatedAt.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("append queue read audit: %w", err)
	}

	return nil
}

type sqliteQueuePolicyTx struct {
	tx  *sql.Tx
	now time.Time
}

func (tx sqliteQueuePolicyTx) ReserveRate(
	ctx context.Context,
	tenantID string,
	action authz.Action,
	units uint64,
	now time.Time,
) (time.Time, error) {
	if units == 0 || units > math.MaxInt64 {
		return time.Time{}, errors.New("queue rate units are outside database range")
	}

	var limit int64

	err := tx.tx.QueryRowContext(ctx, `SELECT CASE WHEN ? = 'topic.publish'
		THEN publish_per_second ELSE send_per_second END FROM tenant_quotas WHERE tenant_id = ?`,
		action, tenantID,
	).Scan(&limit)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, authz.ErrNotFound
	}

	if err != nil {
		return time.Time{}, fmt.Errorf("read queue mutation rate limit: %w", err)
	}

	window := now.UTC().Truncate(time.Second)
	storedUnits := int64(units)

	var used int64

	err = tx.tx.QueryRowContext(ctx, `INSERT INTO quota_windows
		(tenant_id, action, window_started_at_ns, used)
		SELECT ?, ?, ?, ? WHERE ? <= ?
		ON CONFLICT (tenant_id, action, window_started_at_ns) DO NOTHING RETURNING used`,
		tenantID, action, window.UnixNano(), storedUnits, storedUnits, limit,
	).Scan(&used)
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.tx.QueryRowContext(ctx, `UPDATE quota_windows SET used = used + ?
			WHERE tenant_id = ? AND action = ? AND window_started_at_ns = ? AND used <= ? - ?
			RETURNING used`, storedUnits, tenantID, action, window.UnixNano(), limit, storedUnits,
		).Scan(&used)
	}

	if errors.Is(err, sql.ErrNoRows) {
		return window.Add(time.Second), quota.ErrExhausted
	}

	if err != nil {
		return time.Time{}, fmt.Errorf("reserve queue mutation rate: %w", err)
	}

	return time.Time{}, nil
}

//nolint:cyclop // Queue/topic/subscription ledger fields are validated explicitly before applying exact deltas.
func (tx sqliteQueuePolicyTx) ApplyActualUsage(ctx context.Context, delta quota.UsageDelta) error {
	if delta.AgentCountAdded != 0 || delta.AgentCountRemoved != 0 || delta.StoredBytesAdded != 0 ||
		delta.StoredBytesRemoved != 0 || delta.PendingDirectAdded != 0 || delta.PendingDirectRemoved != 0 ||
		delta.PendingBytesAdded != 0 || delta.PendingBytesRemoved != 0 ||
		delta.AgentSubscriptionsAdded != 0 || delta.AgentSubscriptionsRemoved != 0 ||
		delta.ActiveCredentialsAdded != 0 || delta.ActiveCredentialsRemoved != 0 {
		return errors.New("unsupported queue policy usage delta")
	}

	for _, change := range []struct {
		column, capColumn string
		added, removed    uint64
	}{
		{"queue_count", "max_queues", delta.QueueCountAdded, delta.QueueCountRemoved},
		{"topic_count", "max_topics", delta.TopicCountAdded, delta.TopicCountRemoved},
		{"subscription_count", "max_subscriptions", delta.SubscriptionCountAdded, delta.SubscriptionCountRemoved},
	} {
		if err := tx.applyUsageColumn(ctx, delta.TenantID, change.column, change.capColumn, change.added, change.removed); err != nil {
			return err
		}
	}

	return nil
}

//nolint:cyclop // Addition, removal, cap, range, and underflow paths are intentionally distinct.
func (tx sqliteQueuePolicyTx) applyUsageColumn(
	ctx context.Context,
	tenantID, column, capColumn string,
	added, removed uint64,
) error {
	if added != 0 && removed != 0 {
		return errors.New("usage delta cannot add and remove the same resource")
	}

	amount := added
	direction := "+"

	condition := fmt.Sprintf(`%s <= (SELECT %s FROM tenant_quotas WHERE tenant_id = ?) - ?`, column, capColumn)
	if removed != 0 {
		amount, direction, condition = removed, "-", column+" >= ?"
	}

	if amount == 0 {
		return nil
	}

	if amount > math.MaxInt64 {
		return errors.New("queue usage delta is outside database range")
	}

	//nolint:gosec // Identifiers and operators come only from the fixed internal ledger allowlist.
	queryText := fmt.Sprintf(`UPDATE tenant_resource_usage SET %s = %s %s ?, updated_at_ns = ?
		WHERE tenant_id = ? AND %s`, column, column, direction, condition)
	stored := int64(amount)

	var (
		result sql.Result
		err    error
	)
	if removed == 0 {
		result, err = tx.tx.ExecContext(ctx, queryText, stored, tx.now.UnixNano(), tenantID, tenantID, stored)
	} else {
		result, err = tx.tx.ExecContext(ctx, queryText, stored, tx.now.UnixNano(), tenantID, stored)
	}

	if err != nil {
		return fmt.Errorf("apply %s queue usage: %w", column, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read %s queue usage rows: %w", column, err)
	}

	if rows != 1 {
		if added != 0 {
			return quota.ErrExhausted
		}

		return errors.New("queue usage ledger underflow or missing tenant")
	}

	return nil
}

func (tx sqliteQueuePolicyTx) AppendAuditEvent(ctx context.Context, event securityaudit.Event) error {
	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("encode queue audit metadata: %w", err)
	}

	_, err = tx.tx.ExecContext(ctx, sqliteQueueAuditInsert,
		event.EventID, event.TenantID, event.ActorKind, event.ActorID, event.Action,
		event.ResourceType, event.ResourceID, event.Outcome, event.RequestID, event.Reason,
		event.SourceIP, event.UserAgent, string(metadata), event.CreatedAt.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("insert queue audit event: %w", err)
	}

	return nil
}

const sqliteQueueAuditInsert = `INSERT INTO security_audit_events (
	audit_id, tenant_id, principal_kind, principal_id, action, resource_kind,
	resource_id, outcome, request_id, reason, source_ip, user_agent, metadata_json, created_at_ns
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

//nolint:gocritic // Generic replay returns the decoded value plus a distinct found state.
func replaySQLiteQueuePolicy[T any](
	ctx context.Context,
	tx *sql.Tx,
	mutation policytx.Mutation,
	expectedAction authz.Action,
	expectedResourceID string,
) (T, bool, error) {
	var zero T
	if err := validateSQLiteQueuePolicy(mutation, expectedAction, expectedResourceID); err != nil {
		return zero, false, err
	}

	var (
		requestHash  []byte
		responseJSON string
	)

	err := tx.QueryRowContext(ctx, `SELECT request_hash, response_json FROM agent_idempotency
		WHERE tenant_id = ? AND principal_kind = ? AND principal_id = ?
		 AND operation = ? AND idempotency_key = ? AND expires_at_ns > ?`,
		mutation.TenantID, mutation.Actor.Kind, mutation.Actor.ID, mutation.Action,
		mutation.IdempotencyKey, mutation.Audit.CreatedAt.UnixNano(),
	).Scan(&requestHash, &responseJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return zero, false, nil
	}

	if err != nil {
		return zero, false, fmt.Errorf("read queue idempotency result: %w", err)
	}

	if len(requestHash) != sha256.Size || subtle.ConstantTimeCompare(requestHash, mutation.RequestHash[:]) != 1 {
		return zero, false, quota.ErrIdempotencyConflict
	}

	if err := json.Unmarshal([]byte(responseJSON), &zero); err != nil {
		return zero, false, fmt.Errorf("decode queue idempotency result: %w", err)
	}

	return zero, true, nil
}

func reserveSQLiteQueuePolicy(
	ctx context.Context,
	tx *sql.Tx,
	mutation policytx.Mutation,
) (sqliteQueuePolicyTx, error) {
	policyTransaction := sqliteQueuePolicyTx{tx: tx, now: mutation.Audit.CreatedAt.UTC()}
	if _, err := quota.ReserveRateTx(
		ctx, policyTransaction, mutation.TenantID, mutation.Action, mutation.RateUnits, mutation.Audit.CreatedAt,
	); err != nil {
		return sqliteQueuePolicyTx{}, fmt.Errorf("reserve sqlite queue mutation rate: %w", err)
	}

	return policyTransaction, nil
}

func finishSQLiteQueuePolicy[T any](
	ctx context.Context,
	tx sqliteQueuePolicyTx,
	mutation policytx.Mutation,
	result *T,
) error {
	if err := securityaudit.AppendTx(ctx, tx, mutation.Audit); err != nil {
		return fmt.Errorf("append sqlite queue policy audit: %w", err)
	}

	response, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode queue idempotency result: %w", err)
	}

	_, err = tx.tx.ExecContext(ctx, `INSERT INTO agent_idempotency (
		tenant_id, principal_kind, principal_id, operation, idempotency_key,
		request_hash, response_json, created_at_ns, expires_at_ns
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		mutation.TenantID, mutation.Actor.Kind, mutation.Actor.ID, mutation.Action,
		mutation.IdempotencyKey, mutation.RequestHash[:], string(response),
		mutation.Audit.CreatedAt.UnixNano(), mutation.Audit.CreatedAt.Add(queuePolicyIdempotencyTTL).UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("insert queue idempotency result: %w", err)
	}

	return nil
}

func validateSQLiteQueuePolicy(
	mutation policytx.Mutation,
	expectedAction authz.Action,
	expectedResourceID string,
) error {
	if err := mutation.Validate(); err != nil {
		return fmt.Errorf("validate queue policy mutation: %w", err)
	}

	if mutation.Action != expectedAction || mutation.Resource.ID != expectedResourceID {
		return errors.New("queue policy mutation does not match operation")
	}

	return nil
}

func deleteSQLiteSubscriptionsForQueue(
	ctx context.Context,
	tx *sql.Tx,
	tenantID, queueID string,
) (_ uint64, err error) {
	rows, err := tx.QueryContext(ctx, `DELETE FROM topic_subscriptions
		WHERE queue_id = ? AND EXISTS (
			SELECT 1 FROM topic_properties t
			WHERE t.topic_id = topic_subscriptions.topic_id AND t.tenant_id = ?
		) RETURNING subscription_id`, queueID, tenantID)
	if err != nil {
		return 0, fmt.Errorf("delete queue subscriptions: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close deleted queue subscriptions: %w", closeErr)
		}
	}()

	var count uint64

	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return 0, fmt.Errorf("scan deleted queue subscription: %w", err)
		}

		count++
	}

	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate deleted queue subscriptions: %w", err)
	}

	return count, nil
}

//nolint:cyclop,gocyclo // Exact acknowledgement results, audit, and replay commit in one transaction.
func (s *Storage) deleteWithPolicy(
	ctx context.Context,
	input *v1.DeleteRequest,
	mutation policytx.Mutation,
) (_ *v1.DeleteResponse, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin queue ack transaction: %w", err)
	}
	defer func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("rollback queue ack transaction: %w", rollbackErr))
		}
	}()

	replayed, found, err := replaySQLiteQueuePolicy[v1.DeleteResponse](
		ctx, tx, mutation, authz.ActionQueueAck, input.GetQueueId(),
	)
	if err != nil {
		return nil, err
	}

	if found {
		return &replayed, nil
	}

	policyTransaction, err := reserveSQLiteQueuePolicy(ctx, tx, mutation)
	if err != nil {
		return nil, err
	}

	ids := input.GetMessageIds()
	output := v1.DeleteResponse{
		Successful: make([]string, 0, len(ids)),
		Failed:     make([]*v1.DeleteFailure, 0),
	}
	deleted := map[string]struct{}{}

	if len(ids) != 0 {
		args := make([]any, 0, len(ids))
		for _, id := range ids {
			args = append(args, id)
		}

		rows, queryErr := tx.QueryContext(ctx, queryDeleteMessages(input.GetQueueId(), len(ids)), args...)
		if queryErr != nil {
			return nil, fmt.Errorf("delete messages in policy transaction: %w", queryErr)
		}

		deleted, err = collectReturnedIDs(rows)
		if err != nil {
			return nil, err
		}
	}

	for _, id := range ids {
		if _, ok := deleted[id]; ok {
			output.Successful = append(output.Successful, id)
		} else {
			output.Failed = append(output.Failed, &v1.DeleteFailure{MessageId: id})
		}
	}

	mutation.Audit.Metadata = map[string]string{auditMetadataMessageCount: strconv.Itoa(len(output.Successful))}
	if err := finishSQLiteQueuePolicy(ctx, policyTransaction, mutation, &output); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit queue ack transaction: %w", err)
	}

	for _, id := range output.Successful {
		recordTimeInQueue(s.observer, input.GetQueueId(), id)
	}

	return &output, nil
}

//nolint:nonamedreturns // The deferred rollback joins any cleanup failure into the returned error.
func (s *Storage) createTopicWithPolicy(
	ctx context.Context,
	topicID string,
	input *queue.CreateTopicRequest,
	scope queue.AccessScope,
	mutation policytx.Mutation,
) (_ *queue.CreateTopicResponse, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin create topic transaction: %w", err)
	}
	defer rollbackSQLiteQueuePolicy(tx, &err)()

	replayed, found, err := replaySQLiteQueuePolicy[queue.CreateTopicResponse](
		ctx, tx, mutation, authz.ActionTopicCreate, mutation.TenantID,
	)
	if err != nil {
		return nil, err
	}

	if found {
		return &replayed, nil
	}

	policyTransaction, err := reserveSQLiteQueuePolicy(ctx, tx, mutation)
	if err != nil {
		return nil, err
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO topic_properties (
		topic_id, topic_name, created_at, tenant_id, created_by_kind, created_by_id
	) VALUES (?, ?, ?, ?, ?, ?)`, topicID, input.TopicName, writeTime(ctx), scope.TenantID, scope.CreatorKind, scope.CreatorID)
	if err != nil {
		return nil, fmt.Errorf("create topic in policy transaction: %w", err)
	}

	if err := quota.ApplyActualUsageTx(ctx, policyTransaction, quota.UsageDelta{
		TenantID: mutation.TenantID, TopicCountAdded: 1,
	}); err != nil {
		return nil, fmt.Errorf("apply created topic usage: %w", err)
	}

	output := queue.CreateTopicResponse{TopicID: topicID}
	if err := finishSQLiteQueuePolicy(ctx, policyTransaction, mutation, &output); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit create topic transaction: %w", err)
	}

	return &output, nil
}

//nolint:cyclop,nonamedreturns // Topic rollback joins cleanup failures while exact rows and policy state remain atomic.
func (s *Storage) deleteTopicWithPolicy(
	ctx context.Context,
	topicID string,
	scope queue.AccessScope,
	mutation policytx.Mutation,
) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete topic transaction: %w", err)
	}
	defer rollbackSQLiteQueuePolicy(tx, &err)()

	_, found, err := replaySQLiteQueuePolicy[struct{}](
		ctx, tx, mutation, authz.ActionTopicDelete, topicID,
	)
	if err != nil || found {
		return err
	}

	policyTransaction, err := reserveSQLiteQueuePolicy(ctx, tx, mutation)
	if err != nil {
		return err
	}

	removedSubscriptions, err := deleteSQLiteSubscriptionsForTopic(ctx, tx, scope.TenantID, topicID)
	if err != nil {
		return err
	}

	result, err := tx.ExecContext(ctx, `DELETE FROM topic_properties
		WHERE topic_id = ? AND tenant_id = ?
		 AND (? = FALSE OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1')))`,
		topicID, scope.TenantID, scope.Compatibility)
	if err != nil {
		return fmt.Errorf("delete topic in policy transaction: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read deleted topic rows: %w", err)
	}

	if rows != 1 {
		return authz.ErrNotFound
	}

	if err := quota.ApplyActualUsageTx(ctx, policyTransaction, quota.UsageDelta{
		TenantID: mutation.TenantID, TopicCountRemoved: 1,
		SubscriptionCountRemoved: removedSubscriptions,
	}); err != nil {
		return fmt.Errorf("apply deleted topic usage: %w", err)
	}

	if err := finishSQLiteQueuePolicy(ctx, policyTransaction, mutation, &struct{}{}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete topic transaction: %w", err)
	}

	return nil
}

//nolint:cyclop,nonamedreturns // Subscription rollback joins cleanup failures while policy state remains atomic.
func (s *Storage) subscribeWithPolicy(
	ctx context.Context,
	subscriptionID, topicID string,
	input *queue.SubscribeRequest,
	mutation policytx.Mutation,
) (_ *queue.SubscribeResponse, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin subscribe transaction: %w", err)
	}
	defer rollbackSQLiteQueuePolicy(tx, &err)()

	replayed, found, err := replaySQLiteQueuePolicy[queue.SubscribeResponse](
		ctx, tx, mutation, authz.ActionTopicSubscribe, topicID,
	)
	if err != nil {
		return nil, err
	}

	if found {
		return &replayed, nil
	}

	policyTransaction, err := reserveSQLiteQueuePolicy(ctx, tx, mutation)
	if err != nil {
		return nil, err
	}

	result, err := tx.ExecContext(ctx, `INSERT INTO topic_subscriptions (
		subscription_id, topic_id, queue_id, created_at
	) SELECT ?, ?, ?, ? WHERE EXISTS (
		SELECT 1 FROM topic_properties WHERE topic_id = ? AND tenant_id = ?
	) AND EXISTS (
		SELECT 1 FROM queue_properties WHERE queue_id = ? AND tenant_id = ?
	)`, subscriptionID, topicID, input.QueueID, writeTime(ctx),
		topicID, mutation.TenantID, input.QueueID, mutation.TenantID)
	if err != nil {
		return nil, fmt.Errorf("subscribe in policy transaction: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("read subscribed rows: %w", err)
	}

	if rows != 1 {
		return nil, authz.ErrNotFound
	}

	if err := quota.ApplyActualUsageTx(ctx, policyTransaction, quota.UsageDelta{
		TenantID: mutation.TenantID, SubscriptionCountAdded: 1,
	}); err != nil {
		return nil, fmt.Errorf("apply subscribed usage: %w", err)
	}

	output := queue.SubscribeResponse{SubscriptionID: subscriptionID}
	if err := finishSQLiteQueuePolicy(ctx, policyTransaction, mutation, &output); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit subscribe transaction: %w", err)
	}

	return &output, nil
}

//nolint:cyclop,nonamedreturns // Unsubscribe rollback joins cleanup failures while policy state remains atomic.
func (s *Storage) unsubscribeWithPolicy(
	ctx context.Context,
	topicID, subscriptionID string,
	scope queue.AccessScope,
	mutation policytx.Mutation,
) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin unsubscribe transaction: %w", err)
	}
	defer rollbackSQLiteQueuePolicy(tx, &err)()

	_, found, err := replaySQLiteQueuePolicy[struct{}](
		ctx, tx, mutation, authz.ActionSubscriptionDelete, subscriptionID,
	)
	if err != nil || found {
		return err
	}

	policyTransaction, err := reserveSQLiteQueuePolicy(ctx, tx, mutation)
	if err != nil {
		return err
	}

	result, err := tx.ExecContext(ctx, `DELETE FROM topic_subscriptions
		WHERE topic_id = ? AND subscription_id = ? AND EXISTS (
		 SELECT 1 FROM topic_properties t WHERE t.topic_id = topic_subscriptions.topic_id
		  AND t.tenant_id = ?
		  AND (? = FALSE OR (t.created_by_kind = 'system' AND t.created_by_id IN ('migration', 'legacy-v1')))
		)`, topicID, subscriptionID, scope.TenantID, scope.Compatibility)
	if err != nil {
		return fmt.Errorf("unsubscribe in policy transaction: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read unsubscribed rows: %w", err)
	}

	if rows != 1 {
		return authz.ErrNotFound
	}

	if err := quota.ApplyActualUsageTx(ctx, policyTransaction, quota.UsageDelta{
		TenantID: mutation.TenantID, SubscriptionCountRemoved: 1,
	}); err != nil {
		return fmt.Errorf("apply unsubscribed usage: %w", err)
	}

	if err := finishSQLiteQueuePolicy(ctx, policyTransaction, mutation, &struct{}{}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit unsubscribe transaction: %w", err)
	}

	return nil
}

//nolint:cyclop,nonamedreturns // Publish rollback joins cleanup failures while fan-out and policy state remain atomic.
func (s *Storage) publishWithPolicy(
	ctx context.Context,
	topicID string,
	input *queue.PublishRequest,
	mutation policytx.Mutation,
) (_ *queue.PublishResponse, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin publish transaction: %w", err)
	}
	defer rollbackSQLiteQueuePolicy(tx, &err)()

	replayed, found, err := replaySQLiteQueuePolicy[queue.PublishResponse](
		ctx, tx, mutation, authz.ActionTopicPublish, topicID,
	)
	if err != nil {
		return nil, err
	}

	if found {
		return &replayed, nil
	}

	policyTransaction, err := reserveSQLiteQueuePolicy(ctx, tx, mutation)
	if err != nil {
		return nil, err
	}

	queueIDs, err := sqlitePublishQueueIDs(ctx, tx, mutation.TenantID, topicID)
	if err != nil {
		return nil, err
	}

	if queueIDs == nil {
		return nil, authz.ErrNotFound
	}

	output := queue.PublishResponse{
		TopicID: topicID, QueueIDs: make([]string, 0, len(queueIDs)),
		MessageIDs: make([]string, 0, len(queueIDs)*len(input.Messages)),
	}

	messages := make([]*v1.SendMessage, 0, len(input.Messages))
	for _, message := range input.Messages {
		messages = append(messages, &v1.SendMessage{Body: message.Body})
	}

	stamped := queue.Replicated(ctx)

	columns := sendInsertColumnsFor(stamped)
	for _, queueID := range queueIDs {
		args, ids := buildSendArgs(ctx, messages, stamped)
		for start := 0; start < len(messages); start += maxSendInsertBatch {
			end := min(start+maxSendInsertBatch, len(messages))

			chunk := args[start*columns : end*columns]
			if _, err := tx.ExecContext(ctx, queryInsertMessagesBatch(queueID, end-start, stamped), chunk...); err != nil {
				return nil, fmt.Errorf("publish to queue %q: %w", queueID, err)
			}
		}

		output.QueueIDs = append(output.QueueIDs, queueID)
		output.MessageIDs = append(output.MessageIDs, ids...)
		output.DeliveredCount += len(ids)
	}

	mutation.Audit.Metadata = map[string]string{
		auditMetadataMessageCount: strconv.Itoa(len(input.Messages)),
		"delivery_count":          strconv.Itoa(output.DeliveredCount),
	}
	if err := finishSQLiteQueuePolicy(ctx, policyTransaction, mutation, &output); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit publish transaction: %w", err)
	}

	for _, queueID := range queueIDs {
		s.observer.Sent(queueID, uint64(len(input.Messages)), publishedBytes(messages))
	}

	return &output, nil
}

//nolint:gocritic // The closure updates the owning function's named error after deferred rollback.
func rollbackSQLiteQueuePolicy(tx *sql.Tx, returnErr *error) func() {
	return func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			*returnErr = errors.Join(*returnErr, fmt.Errorf("rollback queue policy transaction: %w", err))
		}
	}
}

func deleteSQLiteSubscriptionsForTopic(
	ctx context.Context,
	tx *sql.Tx,
	tenantID, topicID string,
) (uint64, error) {
	rows, err := tx.QueryContext(ctx, `DELETE FROM topic_subscriptions
		WHERE topic_id = ? AND EXISTS (
		 SELECT 1 FROM topic_properties t
		 WHERE t.topic_id = topic_subscriptions.topic_id AND t.tenant_id = ?
		) RETURNING subscription_id`, topicID, tenantID)
	if err != nil {
		return 0, fmt.Errorf("delete topic subscriptions: %w", err)
	}
	defer rows.Close()

	var count uint64

	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return 0, fmt.Errorf("scan deleted topic subscription: %w", err)
		}

		count++
	}

	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate deleted topic subscriptions: %w", err)
	}

	return count, nil
}

func sqlitePublishQueueIDs(
	ctx context.Context,
	tx *sql.Tx,
	tenantID, topicID string,
) ([]string, error) {
	var topicExists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM topic_properties WHERE tenant_id = ? AND topic_id = ?)`,
		tenantID, topicID,
	).Scan(&topicExists); err != nil {
		return nil, fmt.Errorf("check publish topic: %w", err)
	}

	if !topicExists {
		return nil, nil
	}

	rows, err := tx.QueryContext(ctx, `SELECT s.queue_id FROM topic_subscriptions s
		JOIN topic_properties t ON t.topic_id = s.topic_id
		JOIN queue_properties q ON q.queue_id = s.queue_id
		WHERE s.topic_id = ? AND t.tenant_id = ? AND q.tenant_id = ?
		ORDER BY s.subscription_id`, topicID, tenantID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list publish subscriptions: %w", err)
	}
	defer rows.Close()

	queueIDs := make([]string, 0)

	for rows.Next() {
		var queueID string
		if err := rows.Scan(&queueID); err != nil {
			return nil, fmt.Errorf("scan publish subscription: %w", err)
		}

		queueIDs = append(queueIDs, queueID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate publish subscriptions: %w", err)
	}

	return queueIDs, nil
}
