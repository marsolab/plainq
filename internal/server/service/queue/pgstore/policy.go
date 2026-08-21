package pgstore

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/marsolab/servekit/idkit"

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

type postgresQueueMutationKey struct{}

func withPostgresQueueMutation(ctx context.Context, mutation policytx.Mutation) context.Context {
	return context.WithValue(ctx, postgresQueueMutationKey{}, mutation)
}

func postgresQueueMutation(ctx context.Context) (policytx.Mutation, bool) {
	mutation, ok := ctx.Value(postgresQueueMutationKey{}).(policytx.Mutation)

	return mutation, ok
}

func (s *Storage) CreateQueuePolicy(
	ctx context.Context,
	input *v1.CreateQueueRequest,
	mutation policytx.Mutation,
) (*v1.CreateQueueResponse, error) {
	return s.CreateQueue(withPostgresQueueMutation(ctx, mutation), input)
}

func (s *Storage) PurgeQueuePolicy(
	ctx context.Context,
	input *v1.PurgeQueueRequest,
	mutation policytx.Mutation,
) (*v1.PurgeQueueResponse, error) {
	return s.PurgeQueue(withPostgresQueueMutation(ctx, mutation), input)
}

func (s *Storage) DeleteQueuePolicy(
	ctx context.Context,
	input *v1.DeleteQueueRequest,
	mutation policytx.Mutation,
) (*v1.DeleteQueueResponse, error) {
	return s.DeleteQueue(withPostgresQueueMutation(ctx, mutation), input)
}

func (s *Storage) SendPolicy(
	ctx context.Context,
	input *v1.SendRequest,
	mutation policytx.Mutation,
) (*v1.SendResponse, error) {
	return s.Send(withPostgresQueueMutation(ctx, mutation), input)
}

func (s *Storage) ReceivePolicy(
	ctx context.Context,
	input *v1.ReceiveRequest,
	mutation policytx.Mutation,
) (*v1.ReceiveResponse, error) {
	return s.Receive(withPostgresQueueMutation(ctx, mutation), input)
}

func (s *Storage) DeletePolicy(
	ctx context.Context,
	input *v1.DeleteRequest,
	mutation policytx.Mutation,
) (*v1.DeleteResponse, error) {
	return s.Delete(withPostgresQueueMutation(ctx, mutation), input)
}

func (s *Storage) CreateTopicPolicy(
	ctx context.Context,
	input *queue.CreateTopicRequest,
	mutation policytx.Mutation,
) (*queue.CreateTopicResponse, error) {
	return s.CreateTopic(withPostgresQueueMutation(ctx, mutation), input)
}

func (s *Storage) DeleteTopicPolicy(ctx context.Context, topicID string, mutation policytx.Mutation) error {
	return s.DeleteTopic(withPostgresQueueMutation(ctx, mutation), topicID)
}

func (s *Storage) SubscribePolicy(
	ctx context.Context,
	topicID string,
	input *queue.SubscribeRequest,
	mutation policytx.Mutation,
) (*queue.SubscribeResponse, error) {
	return s.Subscribe(withPostgresQueueMutation(ctx, mutation), topicID, input)
}

func (s *Storage) UnsubscribePolicy(
	ctx context.Context,
	topicID, subscriptionID string,
	mutation policytx.Mutation,
) error {
	return s.Unsubscribe(withPostgresQueueMutation(ctx, mutation), topicID, subscriptionID)
}

func (s *Storage) PublishPolicy(
	ctx context.Context,
	topicID string,
	input *queue.PublishRequest,
	mutation policytx.Mutation,
) (*queue.PublishResponse, error) {
	return s.Publish(withPostgresQueueMutation(ctx, mutation), topicID, input)
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
		WHERE tenant_id = $1 AND (NOT $2::boolean OR
		(created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1')))`
	args := []any{tenantID, scope.Compatibility}

	if queueID != "" {
		queryText += ` AND queue_id = $3`

		args = append(args, queueID)
	} else {
		queryText += ` AND queue_name = $3`

		args = append(args, queueName)
	}

	var resolvedID string

	err := s.pool.QueryRow(ctx, queryText, args...).Scan(&resolvedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return authz.Resource{}, authz.ErrNotFound
	}

	if err != nil {
		return authz.Resource{}, fmt.Errorf("resolve postgres queue policy resource: %w", err)
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

	err := s.pool.QueryRow(ctx, `SELECT topic_id FROM topic_properties
		WHERE tenant_id = $1 AND topic_id = $2
		 AND (NOT $3::boolean OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1')))`,
		tenantID, topicID, scope.Compatibility,
	).Scan(&resolvedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return authz.Resource{}, authz.ErrNotFound
	}

	if err != nil {
		return authz.Resource{}, fmt.Errorf("resolve postgres topic policy resource: %w", err)
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

	err := s.pool.QueryRow(ctx, `SELECT s.subscription_id
		FROM topic_subscriptions s JOIN topic_properties t ON t.topic_id = s.topic_id
		WHERE t.tenant_id = $1 AND s.topic_id = $2 AND s.subscription_id = $3
		 AND (NOT $4::boolean OR (t.created_by_kind = 'system' AND t.created_by_id IN ('migration', 'legacy-v1')))`,
		tenantID, topicID, subscriptionID, scope.Compatibility,
	).Scan(&resolvedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return authz.Resource{}, authz.ErrNotFound
	}

	if err != nil {
		return authz.Resource{}, fmt.Errorf("resolve postgres subscription policy resource: %w", err)
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

	err := s.pool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM agent_resource_grants g
		JOIN security_principals p ON p.tenant_id = g.tenant_id
		 AND p.principal_kind = g.subject_kind AND p.principal_id = g.subject_id AND p.status = 'active'
		WHERE g.tenant_id = $1 AND g.subject_kind = $2 AND g.subject_id = $3
		 AND g.resource_kind = $4 AND g.resource_id = $5 AND g.action = $6)`,
		p.TenantID, p.Kind, p.ID, resource.Type, resource.ID, action,
	).Scan(&granted)
	if err != nil {
		return false, fmt.Errorf("check postgres direct policy grant: %w", err)
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

	err := s.pool.QueryRow(ctx, `WITH effective_roles AS (
		SELECT ur.role_id FROM user_roles ur WHERE ur.user_id = $1
		UNION
		SELECT tr.role_id FROM user_teams ut
		JOIN teams t ON t.team_id = ut.team_id
		JOIN team_roles tr ON tr.team_id = t.team_id
		WHERE ut.user_id = $1 AND t.org_id = $2 AND t.is_active = TRUE
	)
	SELECT EXISTS (
		SELECT 1 FROM users u
		JOIN organizations o ON o.org_id = u.org_id AND o.is_active = TRUE
		JOIN effective_roles er ON TRUE
		JOIN roles r ON r.role_id = er.role_id
		LEFT JOIN queue_properties q ON q.queue_id = $3 AND q.tenant_id = u.org_id
		LEFT JOIN queue_permissions qp ON qp.queue_id = q.queue_id AND qp.role_id = r.role_id
		WHERE u.user_id = $1 AND u.org_id = $2 AND u.status = 'active'
		AND (r.role_name = 'admin' OR ($4 = 'queue' AND q.queue_id IS NOT NULL AND CASE $5
			WHEN 'queue.send' THEN coalesce(qp.can_send, FALSE)
			WHEN 'queue.receive' THEN coalesce(qp.can_receive, FALSE)
			WHEN 'queue.read' THEN coalesce(qp.can_receive, FALSE)
			WHEN 'queue.ack' THEN coalesce(qp.can_delete, FALSE)
			WHEN 'queue.purge' THEN coalesce(qp.can_purge, FALSE)
			WHEN 'queue.delete' THEN coalesce(qp.can_delete, FALSE)
			ELSE FALSE END)))`, p.ID, p.TenantID, resource.ID, resource.Type, action,
	).Scan(&granted)
	if err != nil {
		return false, fmt.Errorf("check postgres retained policy permission: %w", err)
	}

	return granted, nil
}

func (s *Storage) AppendReadAudit(ctx context.Context, event securityaudit.Event) error {
	if err := event.Validate(); err != nil {
		return fmt.Errorf("validate postgres read audit: %w", err)
	}

	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("encode postgres read audit metadata: %w", err)
	}

	_, err = s.pool.Exec(ctx, postgresQueueAuditInsert,
		event.EventID, event.TenantID, event.ActorKind, event.ActorID, event.Action,
		event.ResourceType, event.ResourceID, event.Outcome, event.RequestID, event.Reason,
		event.SourceIP, event.UserAgent, string(metadata), event.CreatedAt.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("append postgres queue read audit: %w", err)
	}

	return nil
}

type postgresQueuePolicyTx struct {
	tx  pgx.Tx
	now time.Time
}

func (tx postgresQueuePolicyTx) ReserveRate(
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

	err := tx.tx.QueryRow(ctx, `SELECT CASE WHEN $1 = 'topic.publish'
		THEN publish_per_second ELSE send_per_second END FROM tenant_quotas WHERE tenant_id = $2`,
		action, tenantID,
	).Scan(&limit)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, authz.ErrNotFound
	}

	if err != nil {
		return time.Time{}, fmt.Errorf("read postgres queue mutation rate limit: %w", err)
	}

	window := now.UTC().Truncate(time.Second)
	storedUnits := int64(units)

	var used int64

	err = tx.tx.QueryRow(ctx, `INSERT INTO quota_windows
		(tenant_id, action, window_started_at_ns, used)
		SELECT $1::text, $2::text, $3::bigint, $4::bigint WHERE $4::bigint <= $5::bigint
		ON CONFLICT (tenant_id, action, window_started_at_ns) DO NOTHING RETURNING used`,
		tenantID, action, window.UnixNano(), storedUnits, limit,
	).Scan(&used)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.tx.QueryRow(ctx, `UPDATE quota_windows SET used = used + $1::bigint
			WHERE tenant_id = $2::text AND action = $3::text AND window_started_at_ns = $4::bigint
			AND used <= $5::bigint - $1::bigint
			RETURNING used`, storedUnits, tenantID, action, window.UnixNano(), limit,
		).Scan(&used)
	}

	if errors.Is(err, pgx.ErrNoRows) {
		return window.Add(time.Second), quota.ErrExhausted
	}

	if err != nil {
		return time.Time{}, fmt.Errorf("reserve postgres queue mutation rate: %w", err)
	}

	return time.Time{}, nil
}

//nolint:cyclop // Queue/topic/subscription ledger fields are validated explicitly before applying exact deltas.
func (tx postgresQueuePolicyTx) ApplyActualUsage(ctx context.Context, delta quota.UsageDelta) error {
	if delta.AgentCountAdded != 0 || delta.AgentCountRemoved != 0 || delta.StoredBytesAdded != 0 ||
		delta.StoredBytesRemoved != 0 || delta.PendingDirectAdded != 0 || delta.PendingDirectRemoved != 0 ||
		delta.PendingBytesAdded != 0 || delta.PendingBytesRemoved != 0 ||
		delta.AgentSubscriptionsAdded != 0 || delta.AgentSubscriptionsRemoved != 0 ||
		delta.ActiveCredentialsAdded != 0 || delta.ActiveCredentialsRemoved != 0 {
		return errors.New("unsupported postgres queue policy usage delta")
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

func (tx postgresQueuePolicyTx) applyUsageColumn(
	ctx context.Context,
	tenantID, column, capColumn string,
	added, removed uint64,
) error {
	if added != 0 && removed != 0 {
		return errors.New("usage delta cannot add and remove the same resource")
	}

	amount := added
	direction := "+"

	condition := fmt.Sprintf(
		`%s <= (SELECT %s FROM tenant_quotas WHERE tenant_id = $2::text) - $1::bigint`, column, capColumn,
	)
	if removed != 0 {
		amount, direction, condition = removed, "-", column+" >= $1::bigint"
	}

	if amount == 0 {
		return nil
	}

	if amount > math.MaxInt64 {
		return errors.New("postgres queue usage delta is outside database range")
	}

	queryText := fmt.Sprintf(`UPDATE tenant_resource_usage SET %s = %s %s $1::bigint, updated_at_ns = $3::bigint
		WHERE tenant_id = $2::text AND %s`, column, column, direction, condition)

	tag, err := tx.tx.Exec(ctx, queryText, int64(amount), tenantID, tx.now.UnixNano())
	if err != nil {
		return fmt.Errorf("apply postgres %s queue usage: %w", column, err)
	}

	if tag.RowsAffected() != 1 {
		if added != 0 {
			return quota.ErrExhausted
		}

		return errors.New("postgres queue usage ledger underflow or missing tenant")
	}

	return nil
}

func (tx postgresQueuePolicyTx) AppendAuditEvent(ctx context.Context, event securityaudit.Event) error {
	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("encode postgres queue audit metadata: %w", err)
	}

	_, err = tx.tx.Exec(ctx, postgresQueueAuditInsert,
		event.EventID, event.TenantID, event.ActorKind, event.ActorID, event.Action,
		event.ResourceType, event.ResourceID, event.Outcome, event.RequestID, event.Reason,
		event.SourceIP, event.UserAgent, string(metadata), event.CreatedAt.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("insert postgres queue audit event: %w", err)
	}

	return nil
}

const postgresQueueAuditInsert = `INSERT INTO security_audit_events (
	audit_id, tenant_id, principal_kind, principal_id, action, resource_kind,
	resource_id, outcome, request_id, reason, source_ip, user_agent, metadata_json, created_at_ns
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`

//nolint:gocritic // Generic replay returns the decoded value plus a distinct found state.
func replayPostgresQueuePolicy[T any](
	ctx context.Context,
	tx pgx.Tx,
	mutation policytx.Mutation,
	expectedAction authz.Action,
	expectedResourceID string,
) (T, bool, error) {
	var zero T
	if err := validatePostgresQueuePolicy(mutation, expectedAction, expectedResourceID); err != nil {
		return zero, false, err
	}

	var (
		requestHash  []byte
		responseJSON string
	)

	err := tx.QueryRow(ctx, `SELECT request_hash, response_json FROM agent_idempotency
		WHERE tenant_id = $1 AND principal_kind = $2 AND principal_id = $3
		 AND operation = $4 AND idempotency_key = $5 AND expires_at_ns > $6`,
		mutation.TenantID, mutation.Actor.Kind, mutation.Actor.ID, mutation.Action,
		mutation.IdempotencyKey, mutation.Audit.CreatedAt.UnixNano(),
	).Scan(&requestHash, &responseJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, false, nil
	}

	if err != nil {
		return zero, false, fmt.Errorf("read postgres queue idempotency result: %w", err)
	}

	if len(requestHash) != sha256.Size || subtle.ConstantTimeCompare(requestHash, mutation.RequestHash[:]) != 1 {
		return zero, false, quota.ErrIdempotencyConflict
	}

	if err := json.Unmarshal([]byte(responseJSON), &zero); err != nil {
		return zero, false, fmt.Errorf("decode postgres queue idempotency result: %w", err)
	}

	return zero, true, nil
}

func reservePostgresQueuePolicy(
	ctx context.Context,
	tx pgx.Tx,
	mutation policytx.Mutation,
) (postgresQueuePolicyTx, error) {
	policyTransaction := postgresQueuePolicyTx{tx: tx, now: mutation.Audit.CreatedAt.UTC()}
	if _, err := quota.ReserveRateTx(
		ctx, policyTransaction, mutation.TenantID, mutation.Action, mutation.RateUnits, mutation.Audit.CreatedAt,
	); err != nil {
		return postgresQueuePolicyTx{}, fmt.Errorf("reserve postgres queue mutation rate: %w", err)
	}

	return policyTransaction, nil
}

func finishPostgresQueuePolicy[T any](
	ctx context.Context,
	tx postgresQueuePolicyTx,
	mutation policytx.Mutation,
	result *T,
) error {
	if err := securityaudit.AppendTx(ctx, tx, mutation.Audit); err != nil {
		return fmt.Errorf("append postgres queue policy audit: %w", err)
	}

	response, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode postgres queue idempotency result: %w", err)
	}

	_, err = tx.tx.Exec(ctx, `INSERT INTO agent_idempotency (
		tenant_id, principal_kind, principal_id, operation, idempotency_key,
		request_hash, response_json, created_at_ns, expires_at_ns
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		mutation.TenantID, mutation.Actor.Kind, mutation.Actor.ID, mutation.Action,
		mutation.IdempotencyKey, mutation.RequestHash[:], string(response),
		mutation.Audit.CreatedAt.UnixNano(), mutation.Audit.CreatedAt.Add(queuePolicyIdempotencyTTL).UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("insert postgres queue idempotency result: %w", err)
	}

	return nil
}

func validatePostgresQueuePolicy(
	mutation policytx.Mutation,
	expectedAction authz.Action,
	expectedResourceID string,
) error {
	if err := mutation.Validate(); err != nil {
		return fmt.Errorf("validate postgres queue policy mutation: %w", err)
	}

	if mutation.Action != expectedAction || mutation.Resource.ID != expectedResourceID {
		return errors.New("postgres queue policy mutation does not match operation")
	}

	return nil
}

//nolint:gocritic // The closure updates the owning function's named error after deferred rollback.
func rollbackPostgresQueuePolicy(ctx context.Context, tx pgx.Tx, returnErr *error) func() {
	return func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			*returnErr = errors.Join(*returnErr, fmt.Errorf("rollback postgres queue policy transaction: %w", err))
		}
	}
}

func deletePostgresSubscriptionsForQueue(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, queueID string,
) (uint64, error) {
	rows, err := tx.Query(ctx, `DELETE FROM topic_subscriptions
		WHERE queue_id = $1 AND EXISTS (
		 SELECT 1 FROM topic_properties t
		 WHERE t.topic_id = topic_subscriptions.topic_id AND t.tenant_id = $2
		) RETURNING subscription_id`, queueID, tenantID)
	if err != nil {
		return 0, fmt.Errorf("delete postgres queue subscriptions: %w", err)
	}
	defer rows.Close()

	var count uint64

	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return 0, fmt.Errorf("scan deleted postgres queue subscription: %w", err)
		}

		count++
	}

	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate deleted postgres queue subscriptions: %w", err)
	}

	return count, nil
}

//nolint:nonamedreturns // The deferred rollback joins cleanup failures into the returned error.
func (s *Storage) sendWithPolicy(
	ctx context.Context,
	input *v1.SendRequest,
	mutation policytx.Mutation,
) (_ *v1.SendResponse, err error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, fmt.Errorf("begin postgres queue send transaction: %w", err)
	}
	defer rollbackPostgresQueuePolicy(ctx, tx, &err)()

	replayed, found, err := replayPostgresQueuePolicy[v1.SendResponse](
		ctx, tx, mutation, authz.ActionQueueSend, input.GetQueueId(),
	)
	if err != nil {
		return nil, err
	}

	if found {
		return &replayed, nil
	}

	policyTransaction, err := reservePostgresQueuePolicy(ctx, tx, mutation)
	if err != nil {
		return nil, err
	}

	messages := input.GetMessages()
	output := v1.SendResponse{MessageIds: make([]string, 0, len(messages))}

	args := make([]any, 0, len(messages)*2)
	for _, message := range messages {
		messageID := idkit.ULID()
		args = append(args, messageID, message.GetBody())
		output.MessageIds = append(output.MessageIds, messageID)
	}

	for start := 0; start < len(messages); start += maxSendInsertBatch {
		end := min(start+maxSendInsertBatch, len(messages))
		if _, err := tx.Exec(ctx, queryInsertMessagesBatch(input.GetQueueId(), end-start), args[start*2:end*2]...); err != nil {
			return nil, fmt.Errorf("insert postgres policy messages: %w", err)
		}
	}

	mutation.Audit.Metadata = map[string]string{auditMetadataMessageCount: strconv.Itoa(len(output.MessageIds))}
	if err := finishPostgresQueuePolicy(ctx, policyTransaction, mutation, &output); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit postgres queue send transaction: %w", err)
	}

	return &output, nil
}

//nolint:cyclop,nonamedreturns // Lease policy stays atomic and rollback joins cleanup failures.
func (s *Storage) receiveWithPolicy(
	ctx context.Context,
	input *v1.ReceiveRequest,
	info *v1.DescribeQueueResponse,
	mutation policytx.Mutation,
) (_ *v1.ReceiveResponse, err error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, fmt.Errorf("begin postgres queue receive transaction: %w", err)
	}
	defer rollbackPostgresQueuePolicy(ctx, tx, &err)()

	replayed, found, err := replayPostgresQueuePolicy[v1.ReceiveResponse](
		ctx, tx, mutation, authz.ActionQueueReceive, input.GetQueueId(),
	)
	if err != nil {
		return nil, err
	}

	if found {
		return &replayed, nil
	}

	policyTransaction, err := reservePostgresQueuePolicy(ctx, tx, mutation)
	if err != nil {
		return nil, err
	}

	limit := input.GetBatchSize()
	if limit == 0 {
		limit = 1
	}
	//nolint:gosec // VisibilityTimeoutSeconds is bounded by request validation.
	visibleAt := mutation.Audit.CreatedAt.Add(time.Duration(info.GetVisibilityTimeoutSeconds()) * time.Second)

	rows, err := tx.Query(ctx, queryReceiveMessages(input.GetQueueId()), visibleAt, info.GetMaxReceiveAttempts(), limit)
	if err != nil {
		return nil, fmt.Errorf("receive postgres policy messages: %w", err)
	}

	output := v1.ReceiveResponse{Messages: make([]*v1.ReceiveMessage, 0, limit)}

	var redelivered uint64

	for rows.Next() {
		var (
			message v1.ReceiveMessage
			retries int64
		)
		if err := rows.Scan(&message.Id, &message.Body, &retries); err != nil {
			rows.Close()

			return nil, fmt.Errorf("scan postgres policy receive message: %w", err)
		}

		if retries > 1 {
			redelivered++
		}

		output.Messages = append(output.Messages, &message)
	}

	rows.Close()

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate postgres policy receive messages: %w", err)
	}

	mutation.Audit.Metadata = map[string]string{"batch_size": strconv.Itoa(len(output.Messages))}
	if err := finishPostgresQueuePolicy(ctx, policyTransaction, mutation, &output); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit postgres queue receive transaction: %w", err)
	}

	s.observer.Redelivered(input.GetQueueId(), redelivered)

	return &output, nil
}

//nolint:cyclop,nonamedreturns // Exact acknowledgement stays atomic and rollback joins cleanup failures.
func (s *Storage) deleteWithPolicy(
	ctx context.Context,
	input *v1.DeleteRequest,
	mutation policytx.Mutation,
) (_ *v1.DeleteResponse, err error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, fmt.Errorf("begin postgres queue ack transaction: %w", err)
	}
	defer rollbackPostgresQueuePolicy(ctx, tx, &err)()

	replayed, found, err := replayPostgresQueuePolicy[v1.DeleteResponse](
		ctx, tx, mutation, authz.ActionQueueAck, input.GetQueueId(),
	)
	if err != nil {
		return nil, err
	}

	if found {
		return &replayed, nil
	}

	policyTransaction, err := reservePostgresQueuePolicy(ctx, tx, mutation)
	if err != nil {
		return nil, err
	}

	ids := input.GetMessageIds()
	output := v1.DeleteResponse{
		Successful: make([]string, 0, len(ids)), Failed: make([]*v1.DeleteFailure, 0),
	}

	deleted := make(map[string]struct{}, len(ids))
	if len(ids) != 0 {
		rows, err := tx.Query(ctx, queryDeleteMessages(input.GetQueueId()), ids)
		if err != nil {
			return nil, fmt.Errorf("delete postgres policy messages: %w", err)
		}

		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()

				return nil, fmt.Errorf("scan deleted postgres policy message: %w", err)
			}

			deleted[id] = struct{}{}
		}

		rows.Close()

		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("iterate deleted postgres policy messages: %w", err)
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
	if err := finishPostgresQueuePolicy(ctx, policyTransaction, mutation, &output); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit postgres queue ack transaction: %w", err)
	}

	for _, id := range output.Successful {
		recordTimeInQueue(s.observer, input.GetQueueId(), id)
	}

	return &output, nil
}

//nolint:nonamedreturns // The deferred rollback joins cleanup failures into the returned error.
func (s *Storage) createTopicWithPolicy(
	ctx context.Context,
	topicID string,
	input *queue.CreateTopicRequest,
	scope queue.AccessScope,
	mutation policytx.Mutation,
) (_ *queue.CreateTopicResponse, err error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, fmt.Errorf("begin postgres create topic transaction: %w", err)
	}
	defer rollbackPostgresQueuePolicy(ctx, tx, &err)()

	replayed, found, err := replayPostgresQueuePolicy[queue.CreateTopicResponse](
		ctx, tx, mutation, authz.ActionTopicCreate, mutation.TenantID,
	)
	if err != nil {
		return nil, err
	}

	if found {
		return &replayed, nil
	}

	policyTransaction, err := reservePostgresQueuePolicy(ctx, tx, mutation)
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec(ctx, `INSERT INTO topic_properties (
		topic_id, topic_name, tenant_id, created_by_kind, created_by_id
	) VALUES ($1, $2, $3, $4, $5)`, topicID, input.TopicName, scope.TenantID, scope.CreatorKind, scope.CreatorID)
	if err != nil {
		return nil, fmt.Errorf("create postgres topic in policy transaction: %w", err)
	}

	if err := quota.ApplyActualUsageTx(ctx, policyTransaction, quota.UsageDelta{
		TenantID: mutation.TenantID, TopicCountAdded: 1,
	}); err != nil {
		return nil, fmt.Errorf("apply created postgres topic usage: %w", err)
	}

	output := queue.CreateTopicResponse{TopicID: topicID}
	if err := finishPostgresQueuePolicy(ctx, policyTransaction, mutation, &output); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit postgres create topic transaction: %w", err)
	}

	return &output, nil
}

//nolint:cyclop,nonamedreturns // Topic policy stays atomic and rollback joins cleanup failures.
func (s *Storage) deleteTopicWithPolicy(
	ctx context.Context,
	topicID string,
	scope queue.AccessScope,
	mutation policytx.Mutation,
) (err error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin postgres delete topic transaction: %w", err)
	}
	defer rollbackPostgresQueuePolicy(ctx, tx, &err)()

	_, found, err := replayPostgresQueuePolicy[struct{}](ctx, tx, mutation, authz.ActionTopicDelete, topicID)
	if err != nil || found {
		return err
	}

	policyTransaction, err := reservePostgresQueuePolicy(ctx, tx, mutation)
	if err != nil {
		return err
	}

	removedSubscriptions, err := deletePostgresSubscriptionsForTopic(ctx, tx, scope.TenantID, topicID)
	if err != nil {
		return err
	}

	tag, err := tx.Exec(ctx, `DELETE FROM topic_properties WHERE topic_id = $1 AND tenant_id = $2
		AND (NOT $3::boolean OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1')))`,
		topicID, scope.TenantID, scope.Compatibility)
	if err != nil {
		return fmt.Errorf("delete postgres topic in policy transaction: %w", err)
	}

	if tag.RowsAffected() != 1 {
		return authz.ErrNotFound
	}

	if err := quota.ApplyActualUsageTx(ctx, policyTransaction, quota.UsageDelta{
		TenantID: mutation.TenantID, TopicCountRemoved: 1,
		SubscriptionCountRemoved: removedSubscriptions,
	}); err != nil {
		return fmt.Errorf("apply deleted postgres topic usage: %w", err)
	}

	if err := finishPostgresQueuePolicy(ctx, policyTransaction, mutation, &struct{}{}); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit postgres delete topic transaction: %w", err)
	}

	return nil
}

//nolint:nonamedreturns // The deferred rollback joins cleanup failures into the returned error.
func (s *Storage) subscribeWithPolicy(
	ctx context.Context,
	subscriptionID, topicID string,
	input *queue.SubscribeRequest,
	mutation policytx.Mutation,
) (_ *queue.SubscribeResponse, err error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, fmt.Errorf("begin postgres subscribe transaction: %w", err)
	}
	defer rollbackPostgresQueuePolicy(ctx, tx, &err)()

	replayed, found, err := replayPostgresQueuePolicy[queue.SubscribeResponse](
		ctx, tx, mutation, authz.ActionTopicSubscribe, topicID,
	)
	if err != nil {
		return nil, err
	}

	if found {
		return &replayed, nil
	}

	policyTransaction, err := reservePostgresQueuePolicy(ctx, tx, mutation)
	if err != nil {
		return nil, err
	}

	tag, err := tx.Exec(ctx, `INSERT INTO topic_subscriptions (subscription_id, topic_id, queue_id)
		SELECT $1::text, $2::text, $3::text WHERE EXISTS (
		 SELECT 1 FROM topic_properties WHERE topic_id = $2::text AND tenant_id = $4::text
		) AND EXISTS (
		 SELECT 1 FROM queue_properties WHERE queue_id = $3::text AND tenant_id = $4::text
		)`, subscriptionID, topicID, input.QueueID, mutation.TenantID)
	if err != nil {
		return nil, fmt.Errorf("subscribe postgres queue in policy transaction: %w", err)
	}

	if tag.RowsAffected() != 1 {
		return nil, authz.ErrNotFound
	}

	if err := quota.ApplyActualUsageTx(ctx, policyTransaction, quota.UsageDelta{
		TenantID: mutation.TenantID, SubscriptionCountAdded: 1,
	}); err != nil {
		return nil, fmt.Errorf("apply postgres subscribed usage: %w", err)
	}

	output := queue.SubscribeResponse{SubscriptionID: subscriptionID}
	if err := finishPostgresQueuePolicy(ctx, policyTransaction, mutation, &output); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit postgres subscribe transaction: %w", err)
	}

	return &output, nil
}

//nolint:nonamedreturns // The deferred rollback joins cleanup failures into the returned error.
func (s *Storage) unsubscribeWithPolicy(
	ctx context.Context,
	topicID, subscriptionID string,
	scope queue.AccessScope,
	mutation policytx.Mutation,
) (err error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin postgres unsubscribe transaction: %w", err)
	}
	defer rollbackPostgresQueuePolicy(ctx, tx, &err)()

	_, found, err := replayPostgresQueuePolicy[struct{}](
		ctx, tx, mutation, authz.ActionSubscriptionDelete, subscriptionID,
	)
	if err != nil || found {
		return err
	}

	policyTransaction, err := reservePostgresQueuePolicy(ctx, tx, mutation)
	if err != nil {
		return err
	}

	tag, err := tx.Exec(ctx, `DELETE FROM topic_subscriptions WHERE topic_id = $1 AND subscription_id = $2
		AND EXISTS (SELECT 1 FROM topic_properties t WHERE t.topic_id = topic_subscriptions.topic_id
		 AND t.tenant_id = $3
		 AND (NOT $4::boolean OR (t.created_by_kind = 'system' AND t.created_by_id IN ('migration', 'legacy-v1'))))`,
		topicID, subscriptionID, scope.TenantID, scope.Compatibility)
	if err != nil {
		return fmt.Errorf("unsubscribe postgres queue in policy transaction: %w", err)
	}

	if tag.RowsAffected() != 1 {
		return authz.ErrNotFound
	}

	if err := quota.ApplyActualUsageTx(ctx, policyTransaction, quota.UsageDelta{
		TenantID: mutation.TenantID, SubscriptionCountRemoved: 1,
	}); err != nil {
		return fmt.Errorf("apply postgres unsubscribed usage: %w", err)
	}

	if err := finishPostgresQueuePolicy(ctx, policyTransaction, mutation, &struct{}{}); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit postgres unsubscribe transaction: %w", err)
	}

	return nil
}

//nolint:cyclop,nonamedreturns // Fan-out policy stays atomic and rollback joins cleanup failures.
func (s *Storage) publishWithPolicy(
	ctx context.Context,
	topicID string,
	input *queue.PublishRequest,
	mutation policytx.Mutation,
) (_ *queue.PublishResponse, err error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, fmt.Errorf("begin postgres publish transaction: %w", err)
	}
	defer rollbackPostgresQueuePolicy(ctx, tx, &err)()

	replayed, found, err := replayPostgresQueuePolicy[queue.PublishResponse](
		ctx, tx, mutation, authz.ActionTopicPublish, topicID,
	)
	if err != nil {
		return nil, err
	}

	if found {
		return &replayed, nil
	}

	policyTransaction, err := reservePostgresQueuePolicy(ctx, tx, mutation)
	if err != nil {
		return nil, err
	}

	queueIDs, err := postgresPublishQueueIDs(ctx, tx, mutation.TenantID, topicID)
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
	for _, queueID := range queueIDs {
		args := make([]any, 0, len(input.Messages)*2)

		ids := make([]string, 0, len(input.Messages))
		for _, message := range input.Messages {
			messageID := idkit.ULID()
			args = append(args, messageID, message.Body)
			ids = append(ids, messageID)
		}

		for start := 0; start < len(input.Messages); start += maxSendInsertBatch {
			end := min(start+maxSendInsertBatch, len(input.Messages))
			if _, err := tx.Exec(ctx, queryInsertMessagesBatch(queueID, end-start), args[start*2:end*2]...); err != nil {
				return nil, fmt.Errorf("publish postgres policy messages to queue %q: %w", queueID, err)
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
	if err := finishPostgresQueuePolicy(ctx, policyTransaction, mutation, &output); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit postgres publish transaction: %w", err)
	}

	messages := make([]*v1.SendMessage, 0, len(input.Messages))
	for _, message := range input.Messages {
		messages = append(messages, &v1.SendMessage{Body: message.Body})
	}

	for _, queueID := range queueIDs {
		s.observer.Sent(queueID, uint64(len(input.Messages)), publishedBytes(messages))
	}

	return &output, nil
}

func deletePostgresSubscriptionsForTopic(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, topicID string,
) (uint64, error) {
	rows, err := tx.Query(ctx, `DELETE FROM topic_subscriptions
		WHERE topic_id = $1 AND EXISTS (
		 SELECT 1 FROM topic_properties t
		 WHERE t.topic_id = topic_subscriptions.topic_id AND t.tenant_id = $2
		) RETURNING subscription_id`, topicID, tenantID)
	if err != nil {
		return 0, fmt.Errorf("delete postgres topic subscriptions: %w", err)
	}
	defer rows.Close()

	var count uint64

	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return 0, fmt.Errorf("scan deleted postgres topic subscription: %w", err)
		}

		count++
	}

	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate deleted postgres topic subscriptions: %w", err)
	}

	return count, nil
}

func postgresPublishQueueIDs(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, topicID string,
) ([]string, error) {
	var topicExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM topic_properties WHERE tenant_id = $1 AND topic_id = $2)`,
		tenantID, topicID,
	).Scan(&topicExists); err != nil {
		return nil, fmt.Errorf("check postgres publish topic: %w", err)
	}

	if !topicExists {
		return nil, nil
	}

	rows, err := tx.Query(ctx, `SELECT s.queue_id FROM topic_subscriptions s
		JOIN topic_properties t ON t.topic_id = s.topic_id
		JOIN queue_properties q ON q.queue_id = s.queue_id
		WHERE s.topic_id = $1 AND t.tenant_id = $2 AND q.tenant_id = $2
		ORDER BY s.subscription_id`, topicID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list postgres publish subscriptions: %w", err)
	}
	defer rows.Close()

	queueIDs := make([]string, 0)

	for rows.Next() {
		var queueID string
		if err := rows.Scan(&queueID); err != nil {
			return nil, fmt.Errorf("scan postgres publish subscription: %w", err)
		}

		queueIDs = append(queueIDs, queueID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate postgres publish subscriptions: %w", err)
	}

	return queueIDs, nil
}
