package pgstore

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/policytx"
	"github.com/marsolab/plainq/internal/server/service/agent"
	"github.com/marsolab/plainq/internal/server/service/agent/pgstore/sqlcgen"
	"github.com/marsolab/plainq/internal/server/service/quota"
	"github.com/marsolab/plainq/internal/server/service/securityaudit"
)

const policyIdempotencyTTL = 24 * time.Hour

// postgresPolicyTransaction adapts generated queries from an already-open
// registry transaction to the shared quota and audit transaction seams.
type postgresPolicyTransaction struct {
	queries *sqlcgen.Queries
	now     time.Time
}

func (tx postgresPolicyTransaction) ReserveRate(
	ctx context.Context,
	tenantID string,
	action authz.Action,
	units uint64,
	now time.Time,
) (time.Time, error) {
	storedUnits, err := postgresPolicyInt64(units, "rate units")
	if err != nil {
		return time.Time{}, err
	}

	limit, err := tx.queries.GetMutationRateLimit(ctx, sqlcgen.GetMutationRateLimitParams{
		Action: string(action), TenantID: tenantID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return time.Time{}, agent.ErrNotFound
		}

		return time.Time{}, fmt.Errorf("read mutation rate limit: %w", err)
	}

	if limit <= 0 {
		return time.Time{}, fmt.Errorf("invalid mutation rate limit %d", limit)
	}

	window := now.UTC().Truncate(time.Second)

	params := sqlcgen.InsertMutationQuotaWindowParams{
		TenantID: tenantID, Action: string(action), WindowStartedAtNs: window.UnixNano(),
		Units: storedUnits, QuotaLimit: limit,
	}
	if _, err := tx.queries.InsertMutationQuotaWindow(ctx, params); err == nil {
		return time.Time{}, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, fmt.Errorf("insert mutation quota window: %w", err)
	}

	_, err = tx.queries.IncrementMutationQuotaWindow(ctx, sqlcgen.IncrementMutationQuotaWindowParams{
		Units: storedUnits, TenantID: tenantID, Action: string(action),
		WindowStartedAtNs: window.UnixNano(), QuotaLimit: limit,
	})
	if err == nil {
		return time.Time{}, nil
	}

	if errors.Is(err, pgx.ErrNoRows) {
		return window.Add(time.Second), quota.ErrExhausted
	}

	return time.Time{}, fmt.Errorf("increment mutation quota window: %w", err)
}

//nolint:cyclop,gocyclo // Exact ledger additions and removals are deliberately validated field by field.
func (tx postgresPolicyTransaction) ApplyActualUsage(ctx context.Context, delta quota.UsageDelta) error {
	if delta.AgentCountRemoved != 0 || delta.QueueCountAdded != 0 || delta.QueueCountRemoved != 0 ||
		delta.TopicCountAdded != 0 || delta.TopicCountRemoved != 0 ||
		delta.SubscriptionCountAdded != 0 || delta.SubscriptionCountRemoved != 0 ||
		delta.StoredBytesAdded != 0 || delta.StoredBytesRemoved != 0 ||
		delta.PendingDirectAdded != 0 || delta.PendingDirectRemoved != 0 ||
		delta.PendingBytesAdded != 0 || delta.PendingBytesRemoved != 0 ||
		delta.AgentSubscriptionsAdded != 0 || delta.AgentSubscriptionsRemoved != 0 {
		return errors.New("unsupported registry usage delta")
	}

	if delta.AgentCountAdded > 1 {
		return errors.New("registry transaction can add only one agent")
	}

	if delta.AgentCountAdded == 1 {
		rows, err := tx.queries.IncrementTenantAgentUsage(ctx, sqlcgen.IncrementTenantAgentUsageParams{
			UpdatedAtNs: tx.now.UnixNano(), TenantID: delta.TenantID,
		})
		if err != nil {
			return fmt.Errorf("increment tenant agent usage: %w", err)
		}

		if rows != 1 {
			return fmt.Errorf("increment tenant agent usage changed %d rows", rows)
		}
	}

	if delta.ActiveCredentialsRemoved != 0 {
		removed, err := postgresPolicyInt64(delta.ActiveCredentialsRemoved, "removed credentials")
		if err != nil {
			return err
		}

		rows, err := tx.queries.RemoveExpiredCredentialUsage(ctx, sqlcgen.RemoveExpiredCredentialUsageParams{
			Removed: removed, UpdatedAtNs: tx.now.UnixNano(),
			TenantID: delta.TenantID, AgentID: delta.AgentID,
		})
		if err != nil {
			return fmt.Errorf("decrement active credential usage: %w", err)
		}

		if rows != 1 {
			return fmt.Errorf("decrement active credential usage changed %d rows", rows)
		}
	}

	if delta.ActiveCredentialsAdded > 1 {
		return errors.New("registry transaction can add only one credential")
	}

	if delta.ActiveCredentialsAdded == 1 {
		capacity, err := tx.queries.GetAgentCredentialCapacity(ctx, sqlcgen.GetAgentCredentialCapacityParams{
			TenantID: delta.TenantID, AgentID: delta.AgentID,
		})
		if err != nil {
			return fmt.Errorf("read agent credential capacity: %w", err)
		}

		rows, err := tx.queries.IncrementActiveCredentialUsage(ctx, sqlcgen.IncrementActiveCredentialUsageParams{
			UpdatedAtNs: tx.now.UnixNano(), TenantID: delta.TenantID,
			AgentID: delta.AgentID, CredentialLimit: capacity.MaxCredentialsPerAgent,
		})
		if err != nil {
			return fmt.Errorf("increment active credential usage: %w", err)
		}

		if rows != 1 {
			return errors.Join(agent.ErrFailedPrecondition, quota.ErrExhausted)
		}
	}

	return nil
}

func (tx postgresPolicyTransaction) AppendAuditEvent(ctx context.Context, event securityaudit.Event) error {
	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("encode audit metadata: %w", err)
	}

	if err := tx.queries.InsertAgentAuditEvent(ctx, sqlcgen.InsertAgentAuditEventParams{
		AuditID: event.EventID, TenantID: event.TenantID, PrincipalKind: string(event.ActorKind),
		PrincipalID: event.ActorID, Action: event.Action, ResourceKind: event.ResourceType,
		ResourceID: event.ResourceID, Outcome: event.Outcome, RequestID: event.RequestID,
		Reason: event.Reason, SourceIp: event.SourceIP, UserAgent: event.UserAgent,
		MetadataJson: metadata, CreatedAtNs: event.CreatedAt.UnixNano(),
	}); err != nil {
		return fmt.Errorf("insert agent audit event: %w", err)
	}

	return nil
}

//nolint:gocritic // Generic replay returns the decoded value plus the distinct found state.
func postgresPolicyReplay[T any](
	ctx context.Context,
	queries *sqlcgen.Queries,
	mutation policytx.Mutation,
	expectedAction authz.Action,
	expectedTenantID, expectedResourceID string,
) (T, bool, error) {
	var zero T
	if err := validatePostgresPolicy(mutation, expectedAction, expectedTenantID, expectedResourceID); err != nil {
		return zero, false, err
	}

	row, err := queries.GetPolicyIdempotency(ctx, sqlcgen.GetPolicyIdempotencyParams{
		TenantID: mutation.TenantID, PrincipalKind: string(mutation.Actor.Kind),
		PrincipalID: mutation.Actor.ID, Operation: string(mutation.Action),
		IdempotencyKey: mutation.IdempotencyKey, NowNs: mutation.Audit.CreatedAt.UnixNano(),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, false, nil
	}

	if err != nil {
		return zero, false, fmt.Errorf("read policy idempotency result: %w", err)
	}

	if len(row.RequestHash) != len(mutation.RequestHash) ||
		subtle.ConstantTimeCompare(row.RequestHash, mutation.RequestHash[:]) != 1 {
		return zero, false, errors.Join(agent.ErrIdempotencyConflict, quota.ErrIdempotencyConflict)
	}

	if err := json.Unmarshal(row.ResponseJson, &zero); err != nil {
		return zero, false, fmt.Errorf("decode policy idempotency result: %w", err)
	}

	return zero, true, nil
}

func finishPostgresPolicy[T any](
	ctx context.Context,
	tx postgresPolicyTransaction,
	mutation policytx.Mutation,
	result T,
) error {
	if err := securityaudit.AppendTx(ctx, tx, mutation.Audit); err != nil {
		return fmt.Errorf("append agent policy audit: %w", err)
	}

	response, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode policy idempotency result: %w", err)
	}

	err = tx.queries.InsertPolicyIdempotency(ctx, sqlcgen.InsertPolicyIdempotencyParams{
		TenantID: mutation.TenantID, PrincipalKind: string(mutation.Actor.Kind),
		PrincipalID: mutation.Actor.ID, Operation: string(mutation.Action),
		IdempotencyKey: mutation.IdempotencyKey, RequestHash: mutation.RequestHash[:],
		ResponseJson: response, CreatedAtNs: mutation.Audit.CreatedAt.UnixNano(),
		ExpiresAtNs: mutation.Audit.CreatedAt.Add(policyIdempotencyTTL).UnixNano(),
	})
	if err != nil {
		return classifyWrite("insert policy idempotency result", err)
	}

	return nil
}

func validatePostgresPolicy(
	mutation policytx.Mutation,
	expectedAction authz.Action,
	expectedTenantID, expectedResourceID string,
) error {
	if err := mutation.Validate(); err != nil {
		return fmt.Errorf("validate policy mutation: %w", err)
	}

	if mutation.Action != expectedAction || mutation.TenantID != expectedTenantID ||
		mutation.Resource.ID != expectedResourceID {
		return errors.New("policy mutation does not match registry operation")
	}

	return nil
}

func postgresPolicyInt64(value uint64, field string) (int64, error) {
	if value > math.MaxInt64 {
		return 0, fmt.Errorf("%s exceeds database range", field)
	}

	return int64(value), nil
}
