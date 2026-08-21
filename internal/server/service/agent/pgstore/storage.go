package pgstore

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/marsolab/plainq/internal/server/authz"
	agentv1 "github.com/marsolab/plainq/internal/server/schema/agent/v1"
	"github.com/marsolab/plainq/internal/server/service/agent"
	"github.com/marsolab/plainq/internal/server/service/agent/pgstore/sqlcgen"
	"github.com/marsolab/plainq/internal/server/service/quota"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

var _ agent.RegistryStore = (*Storage)(nil)
var _ agent.PrincipalStore = (*Storage)(nil)
var _ agent.CredentialStore = (*Storage)(nil)
var _ agent.AuthorizationStore = (*Storage)(nil)

const (
	pgForeignKeyViolation          = "23503"
	pgUniqueViolation              = "23505"
	pgSerializationFailure         = "40001"
	maxCredentialRegistrationTries = 8
)

// Storage is the PostgreSQL-backed agent registry.
type Storage struct {
	pool    *pgxpool.Pool
	queries *sqlcgen.Queries
}

// NewStorage creates a PostgreSQL agent registry.
func NewStorage(pool *pgxpool.Pool) (*Storage, error) {
	if pool == nil {
		return nil, errors.New("pool is nil")
	}

	return &Storage{pool: pool, queries: sqlcgen.New(pool)}, nil
}

func (s *Storage) withinTx(ctx context.Context, fn func(pgx.Tx) error) (sErr error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			sErr = errors.Join(sErr, fmt.Errorf("rollback transaction: %w", err))
		}
	}()

	if err := fn(tx); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

//nolint:cyclop,funlen,gocognit,gocyclo // Registry creation keeps all policy, projection, and ledger writes in one visible transaction.
func (s *Storage) CreateAgent(ctx context.Context, input agent.CreateAgentInput) (agent.AgentRecord, error) {
	status, err := storedAgentStatus(input.Status)
	if err != nil {
		return agent.AgentRecord{}, err
	}

	authVersion, err := storedAuthVersion(input.AuthVersion)
	if err != nil {
		return agent.AgentRecord{}, err
	}

	var created agent.AgentRecord

	err = s.withinTx(ctx, func(tx pgx.Tx) error {
		queries := sqlcgen.New(tx)
		policyTx := postgresPolicyTransaction{queries: queries, now: input.UpdatedAt.UTC()}

		replayed, found, err := postgresPolicyReplay[agent.AgentRecord](
			ctx, queries, input.Policy, authz.ActionAgentCreate, input.TenantID, input.AgentID,
		)
		if err != nil {
			return err
		}

		if input.Policy.Actor != input.CreatedBy {
			return errors.New("policy actor does not match agent creator")
		}

		if found {
			created = replayed

			return nil
		}

		if _, err := quota.ReserveRateTx(
			ctx, policyTx, input.TenantID, input.Policy.Action, input.Policy.RateUnits, input.Policy.Audit.CreatedAt,
		); err != nil {
			return fmt.Errorf("reserve create agent rate: %w", err)
		}

		capacity, err := queries.GetTenantAgentCapacity(ctx, input.TenantID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return agent.ErrNotFound
			}

			return fmt.Errorf("read tenant agent capacity: %w", err)
		}

		if capacity.AgentCount < 0 || capacity.MaxAgents <= 0 {
			return errors.New("invalid tenant agent capacity ledger")
		}

		if capacity.AgentCount >= capacity.MaxAgents {
			return errors.Join(agent.ErrFailedPrecondition, quota.ErrExhausted)
		}

		if err := queries.CreateAgent(ctx, sqlcgen.CreateAgentParams{
			AgentID:       input.AgentID,
			TenantID:      input.TenantID,
			AgentName:     input.Name,
			Status:        status,
			AuthVersion:   authVersion,
			CreatedByKind: string(input.CreatedBy.Kind),
			CreatedByID:   input.CreatedBy.ID,
			CreatedAtNs:   input.CreatedAt.UnixNano(),
			UpdatedAtNs:   input.UpdatedAt.UnixNano(),
		}); err != nil {
			return classifyWrite("create agent", err)
		}

		if err := queries.CreateAgentPrincipal(ctx, sqlcgen.CreateAgentPrincipalParams{
			TenantID:    input.TenantID,
			PrincipalID: input.AgentID,
			AuthVersion: authVersion,
			UpdatedAtNs: input.UpdatedAt.UnixNano(),
		}); err != nil {
			return classifyWrite("create agent principal", err)
		}

		if err := queries.CreateAgentResourceUsage(ctx, sqlcgen.CreateAgentResourceUsageParams{
			TenantID: input.TenantID, AgentID: input.AgentID, UpdatedAtNs: input.UpdatedAt.UnixNano(),
		}); err != nil {
			return classifyWrite("create agent resource usage", err)
		}

		if err := quota.ApplyActualUsageTx(ctx, policyTx, quota.UsageDelta{
			TenantID: input.TenantID, AgentCountAdded: 1,
		}); err != nil {
			return fmt.Errorf("apply created agent usage: %w", err)
		}

		row, err := queries.GetAgent(ctx, sqlcgen.GetAgentParams{
			TenantID: input.TenantID, AgentID: input.AgentID,
		})
		if err != nil {
			return fmt.Errorf("read created agent: %w", err)
		}

		created, err = postgresRecord(
			row.AgentID, row.TenantID, row.AgentName, row.Status, row.AuthVersion,
			row.CreatedAtNs, row.UpdatedAtNs, row.DisabledAtNs,
		)
		if err != nil {
			return err
		}

		return finishPostgresPolicy(ctx, policyTx, input.Policy, created)
	})
	if err != nil {
		return agent.AgentRecord{}, err
	}

	return created, nil
}

func (s *Storage) GetAgent(ctx context.Context, tenantID, agentID string) (agent.AgentRecord, error) {
	row, err := s.queries.GetAgent(ctx, sqlcgen.GetAgentParams{TenantID: tenantID, AgentID: agentID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return agent.AgentRecord{}, agent.ErrNotFound
		}

		return agent.AgentRecord{}, fmt.Errorf("get agent: %w", err)
	}

	record, err := postgresRecord(
		row.AgentID, row.TenantID, row.AgentName, row.Status, row.AuthVersion,
		row.CreatedAtNs, row.UpdatedAtNs, row.DisabledAtNs,
	)
	if err != nil {
		return agent.AgentRecord{}, fmt.Errorf("decode agent: %w", err)
	}

	return record, nil
}

func (s *Storage) GetAgentPrincipal(
	ctx context.Context,
	tenantID string,
	agentID string,
) (agent.AgentPrincipalRecord, error) {
	row, err := s.queries.GetAgentPrincipal(ctx, sqlcgen.GetAgentPrincipalParams{
		TenantID: tenantID, PrincipalID: agentID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return agent.AgentPrincipalRecord{}, agent.ErrNotFound
		}

		return agent.AgentPrincipalRecord{}, fmt.Errorf("get agent principal: %w", err)
	}

	record, err := postgresPrincipalRecord(row.TenantID, row.PrincipalID, row.Status, row.AuthVersion)
	if err != nil {
		return agent.AgentPrincipalRecord{}, fmt.Errorf("decode agent principal: %w", err)
	}

	return record, nil
}

func (s *Storage) GetAgentByName(ctx context.Context, tenantID, name string) (agent.AgentRecord, error) {
	row, err := s.queries.GetAgentByName(ctx, sqlcgen.GetAgentByNameParams{
		TenantID: tenantID, AgentName: name,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return agent.AgentRecord{}, agent.ErrNotFound
		}

		return agent.AgentRecord{}, fmt.Errorf("get agent by name: %w", err)
	}

	record, err := postgresRecord(
		row.AgentID, row.TenantID, row.AgentName, row.Status, row.AuthVersion,
		row.CreatedAtNs, row.UpdatedAtNs, row.DisabledAtNs,
	)
	if err != nil {
		return agent.AgentRecord{}, fmt.Errorf("decode agent by name: %w", err)
	}

	return record, nil
}

// ResolveAuthorizationResource performs the tenant predicate in SQL. Topic
// and subscription projections remain fail-closed until their tenant-owned
// stores land.
func (s *Storage) ResolveAuthorizationResource(
	ctx context.Context,
	tenantID string,
	selector agent.AuthorizationResourceSelector,
) (agent.AuthorizationResource, error) {
	if selector.Kind != agent.AuthorizationResourceAgent || tenantID == "" ||
		(selector.ID == "") == (selector.Name == "") {
		return agent.AuthorizationResource{}, agent.ErrNotFound
	}

	var agentID string

	if selector.ID != "" {
		row, err := s.queries.GetAgent(ctx, sqlcgen.GetAgentParams{TenantID: tenantID, AgentID: selector.ID})
		if err != nil {
			return agent.AuthorizationResource{}, mapAuthorizationResourceError(err)
		}

		agentID = row.AgentID
	} else {
		row, err := s.queries.GetAgentByName(ctx, sqlcgen.GetAgentByNameParams{
			TenantID: tenantID, AgentName: selector.Name,
		})
		if err != nil {
			return agent.AuthorizationResource{}, mapAuthorizationResourceError(err)
		}

		agentID = row.AgentID
	}

	return agent.AuthorizationResource{ID: agentID, OwnerAgentID: agentID}, nil
}

// HasResourceGrant checks the complete unique grant key, including tenant.
func (s *Storage) HasResourceGrant(ctx context.Context, check agent.ResourceGrantCheck) (bool, error) {
	exists, err := s.queries.HasResourceGrant(ctx, sqlcgen.HasResourceGrantParams{
		TenantID: check.TenantID, SubjectKind: string(check.SubjectKind), SubjectID: check.SubjectID,
		ResourceKind: string(check.ResourceKind), ResourceID: check.ResourceID, Action: check.Action,
	})
	if err != nil {
		return false, fmt.Errorf("check agent resource grant: %w", err)
	}

	return exists, nil
}

func mapAuthorizationResourceError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return agent.ErrNotFound
	}

	return fmt.Errorf("resolve authorization agent: %w", err)
}

func (s *Storage) ListAgents(ctx context.Context, input agent.ListAgentsInput) (agent.ListAgentsResult, error) {
	result := agent.ListAgentsResult{Agents: []agent.AgentRecord{}}

	err := s.withinTx(ctx, func(tx pgx.Tx) error {
		queries := sqlcgen.New(tx)

		rows, err := queries.ListAgents(ctx, sqlcgen.ListAgentsParams{
			TenantID:   input.TenantID,
			NamePrefix: input.NamePrefix,
			AfterName:  input.AfterName,
			AfterID:    input.AfterID,
			PageLimit:  int64(input.Limit) + 1,
		})
		if err != nil {
			return fmt.Errorf("list agents: %w", err)
		}

		total, err := queries.CountAgents(ctx, sqlcgen.CountAgentsParams{
			TenantID: input.TenantID, NamePrefix: input.NamePrefix,
		})
		if err != nil {
			return fmt.Errorf("count agents: %w", err)
		}

		if total < 0 {
			return fmt.Errorf("count agents returned negative value %d", total)
		}

		result.TotalCount = uint64(total)
		if len(rows) > int(input.Limit) {
			result.HasMore = true
			rows = rows[:input.Limit]
		}

		result.Agents = make([]agent.AgentRecord, 0, len(rows))
		for _, row := range rows {
			record, err := postgresRecord(
				row.AgentID, row.TenantID, row.AgentName, row.Status, row.AuthVersion,
				row.CreatedAtNs, row.UpdatedAtNs, row.DisabledAtNs,
			)
			if err != nil {
				return fmt.Errorf("decode listed agent: %w", err)
			}

			result.Agents = append(result.Agents, record)
		}

		if result.HasMore && len(result.Agents) > 0 {
			last := result.Agents[len(result.Agents)-1]
			result.NextCursor = last.Name + "\x00" + last.AgentID
		}

		return nil
	})
	if err != nil {
		return agent.ListAgentsResult{}, err
	}

	return result, nil
}

//nolint:cyclop // Status projection, authentication version, audit, and idempotency update atomically.
func (s *Storage) SetAgentStatus(ctx context.Context, input agent.SetAgentStatusInput) (agent.AgentRecord, error) {
	status, err := storedAgentStatus(input.Status)
	if err != nil {
		return agent.AgentRecord{}, err
	}

	var updated agent.AgentRecord

	err = s.withinTx(ctx, func(tx pgx.Tx) error {
		queries := sqlcgen.New(tx)
		policyTx := postgresPolicyTransaction{queries: queries, now: input.UpdatedAt.UTC()}

		replayed, found, err := postgresPolicyReplay[agent.AgentRecord](
			ctx, queries, input.Policy, authz.ActionAgentStatusSet, input.TenantID, input.AgentID,
		)
		if err != nil {
			return err
		}

		if found {
			updated = replayed

			return nil
		}

		if _, err := quota.ReserveRateTx(
			ctx, policyTx, input.TenantID, input.Policy.Action, input.Policy.RateUnits, input.Policy.Audit.CreatedAt,
		); err != nil {
			return fmt.Errorf("reserve status mutation rate: %w", err)
		}

		params := sqlcgen.UpdateAgentStatusParams{
			Status:      status,
			UpdatedAtNs: input.UpdatedAt.UnixNano(),
			TenantID:    input.TenantID,
			AgentID:     input.AgentID,
		}

		rows, err := queries.UpdateAgentStatus(ctx, params)
		if err != nil {
			return fmt.Errorf("update agent status: %w", err)
		}

		if rows == 0 {
			return agent.ErrNotFound
		}

		principalRows, err := queries.UpdateAgentPrincipalStatus(ctx, sqlcgen.UpdateAgentPrincipalStatusParams(params))
		if err != nil {
			return fmt.Errorf("update agent principal status: %w", err)
		}

		if principalRows == 0 {
			return fmt.Errorf("agent principal projection missing: %w", agent.ErrNotFound)
		}

		row, err := queries.GetAgent(ctx, sqlcgen.GetAgentParams{
			TenantID: input.TenantID, AgentID: input.AgentID,
		})
		if err != nil {
			return fmt.Errorf("read updated agent: %w", err)
		}

		updated, err = postgresRecord(
			row.AgentID, row.TenantID, row.AgentName, row.Status, row.AuthVersion,
			row.CreatedAtNs, row.UpdatedAtNs, row.DisabledAtNs,
		)
		if err != nil {
			return err
		}

		return finishPostgresPolicy(ctx, policyTx, input.Policy, updated)
	})
	if err != nil {
		return agent.AgentRecord{}, err
	}

	return updated, nil
}

func postgresRecord(
	agentID, tenantID, name string,
	status int16,
	authVersion, createdAt, updatedAt int64,
	disabledAt pgtype.Int8,
) (agent.AgentRecord, error) {
	var decodedStatus agentv1.AgentStatus

	switch status {
	case int16(agentv1.AgentStatus_AGENT_STATUS_ACTIVE):
		decodedStatus = agentv1.AgentStatus_AGENT_STATUS_ACTIVE
	case int16(agentv1.AgentStatus_AGENT_STATUS_DISABLED):
		decodedStatus = agentv1.AgentStatus_AGENT_STATUS_DISABLED
	default:
		return agent.AgentRecord{}, fmt.Errorf("unknown stored agent status %d", status)
	}

	if authVersion < 0 {
		return agent.AgentRecord{}, fmt.Errorf("negative stored auth version %d", authVersion)
	}

	record := agent.AgentRecord{
		AgentID:     agentID,
		TenantID:    tenantID,
		Name:        name,
		Status:      decodedStatus,
		AuthVersion: uint64(authVersion),
		CreatedAt:   time.Unix(0, createdAt).UTC(),
		UpdatedAt:   time.Unix(0, updatedAt).UTC(),
	}
	if disabledAt.Valid {
		value := time.Unix(0, disabledAt.Int64).UTC()
		record.DisabledAt = &value
	}

	return record, nil
}

func postgresPrincipalRecord(
	tenantID string,
	agentID string,
	status string,
	authVersion int64,
) (agent.AgentPrincipalRecord, error) {
	decodedStatus, err := decodedPrincipalStatus(status)
	if err != nil {
		return agent.AgentPrincipalRecord{}, err
	}

	if authVersion < 0 {
		return agent.AgentPrincipalRecord{}, fmt.Errorf("negative stored principal auth version %d", authVersion)
	}

	return agent.AgentPrincipalRecord{
		AgentID: agentID, TenantID: tenantID, Status: decodedStatus, AuthVersion: uint64(authVersion),
	}, nil
}

func decodedPrincipalStatus(status string) (agentv1.AgentStatus, error) {
	switch status {
	case "active":
		return agentv1.AgentStatus_AGENT_STATUS_ACTIVE, nil
	case "disabled":
		return agentv1.AgentStatus_AGENT_STATUS_DISABLED, nil
	default:
		return agentv1.AgentStatus_AGENT_STATUS_UNSPECIFIED, fmt.Errorf("unknown stored principal status %q", status)
	}
}

func storedAgentStatus(status agentv1.AgentStatus) (int16, error) {
	switch status {
	case agentv1.AgentStatus_AGENT_STATUS_ACTIVE:
		return 1, nil
	case agentv1.AgentStatus_AGENT_STATUS_DISABLED:
		return 2, nil
	case agentv1.AgentStatus_AGENT_STATUS_UNSPECIFIED:
		return 0, fmt.Errorf("unsupported agent status %d: %w", status, pqerr.ErrInvalidInput)
	default:
		return 0, fmt.Errorf("unsupported agent status %d: %w", status, pqerr.ErrInvalidInput)
	}
}

func storedAuthVersion(version uint64) (int64, error) {
	const maxInt64AsUint = uint64(1<<63 - 1)

	if version > maxInt64AsUint {
		return 0, fmt.Errorf("auth version exceeds database range: %w", pqerr.ErrInvalidInput)
	}

	return int64(version), nil
}

func classifyWrite(operation string, err error) error {
	if err == nil {
		return nil
	}

	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return fmt.Errorf("%s: %w", operation, err)
	}

	switch pgErr.Code {
	case pgUniqueViolation:
		return fmt.Errorf("%s: %w", operation, agent.ErrAlreadyExists)
	case pgForeignKeyViolation:
		return fmt.Errorf("%s: tenant not found: %w", operation, agent.ErrNotFound)
	default:
		return fmt.Errorf("%s: %w", operation, err)
	}
}

func (s *Storage) CreateCredential(
	ctx context.Context,
	input agent.CreateCredentialInput,
) (agent.CredentialRecord, error) {
	var created agent.CredentialRecord

	err := s.withinTx(ctx, func(tx pgx.Tx) error {
		queries := sqlcgen.New(tx)
		policyTx := postgresPolicyTransaction{queries: queries, now: input.CreatedAt.UTC()}

		replayed, found, err := postgresPolicyReplay[agent.CredentialRecord](
			ctx, queries, input.Policy, authz.ActionCredentialCreate, input.TenantID, input.AgentID,
		)
		if err != nil {
			return err
		}

		if found {
			created = replayed

			return nil
		}

		if _, err := quota.ReserveRateTx(
			ctx, policyTx, input.TenantID, input.Policy.Action, input.Policy.RateUnits, input.Policy.Audit.CreatedAt,
		); err != nil {
			return fmt.Errorf("reserve create credential rate: %w", err)
		}

		if err := postgresCredentialCapacity(ctx, policyTx, input.TenantID, input.AgentID, input.CreatedAt); err != nil {
			return err
		}

		if err := queries.CreateCredential(ctx, postgresCreateCredentialParams(
			input.CredentialID, input.TenantID, input.AgentID, input.Name, input.Prefix,
			input.SecretHash, input.CreatedAt, input.ExpiresAt,
		)); err != nil {
			return classifyWrite("create credential", err)
		}

		if err := quota.ApplyActualUsageTx(ctx, policyTx, quota.UsageDelta{
			TenantID: input.TenantID, AgentID: input.AgentID, ActiveCredentialsAdded: 1,
		}); err != nil {
			return fmt.Errorf("apply created credential usage: %w", err)
		}

		row, err := queries.GetCredentialByID(ctx, input.CredentialID)
		if err != nil {
			return fmt.Errorf("read created credential: %w", err)
		}

		created, err = postgresCredentialRecord(row)
		if err != nil {
			return err
		}

		return finishPostgresPolicy(ctx, policyTx, input.Policy, created)
	})
	if err != nil {
		return agent.CredentialRecord{}, err
	}

	return created, nil
}

func (s *Storage) RegisterCredential(
	ctx context.Context,
	input agent.RegisterCredentialInput,
) (agent.RegisterCredentialResult, error) {
	var lastErr error

	for range maxCredentialRegistrationTries {
		result, err := s.registerCredentialOnce(ctx, input)
		if err == nil {
			return result, nil
		}

		if !credentialRegistrationConflict(err) {
			return agent.RegisterCredentialResult{}, err
		}

		lastErr = err

		canonical, found, err := s.reconcileRegisteredCredential(ctx, input)
		if err != nil {
			return agent.RegisterCredentialResult{}, err
		}

		if found {
			return canonical, nil
		}

		if errors.Is(lastErr, agent.ErrAlreadyExists) {
			return agent.RegisterCredentialResult{}, lastErr
		}

		if err := ctx.Err(); err != nil {
			return agent.RegisterCredentialResult{}, fmt.Errorf("register credential retry: %w", err)
		}
	}

	return agent.RegisterCredentialResult{}, fmt.Errorf(
		"register credential conflicts exhausted: %w",
		errors.Join(pqerr.ErrUnavailable, lastErr),
	)
}

//nolint:cyclop // Registration handles replay, canonical rows, expiry accounting, and atomic policy writes.
func (s *Storage) registerCredentialOnce(
	ctx context.Context,
	input agent.RegisterCredentialInput,
) (agent.RegisterCredentialResult, error) {
	var result agent.RegisterCredentialResult

	err := s.withinTx(ctx, func(tx pgx.Tx) error {
		queries := sqlcgen.New(tx)
		policyTx := postgresPolicyTransaction{queries: queries, now: input.CreatedAt.UTC()}

		replayed, found, err := postgresPolicyReplay[agent.RegisterCredentialResult](
			ctx, queries, input.Policy, authz.ActionCredentialRegister, input.TenantID, input.AgentID,
		)
		if err != nil {
			return err
		}

		if found {
			result = replayed
			result.AlreadyExisted = true

			return nil
		}

		existing, err := queries.GetCredentialByID(ctx, input.CredentialID)
		if err == nil {
			record, decodeErr := postgresCredentialRecord(existing)
			if decodeErr != nil {
				return decodeErr
			}

			if !sameRegisteredCredential(record, input) {
				return agent.ErrAlreadyExists
			}

			result = agent.RegisterCredentialResult{Credential: record, AlreadyExisted: true}

			return nil
		}

		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("get registered credential: %w", err)
		}

		if _, err := quota.ReserveRateTx(
			ctx, policyTx, input.TenantID, input.Policy.Action, input.Policy.RateUnits, input.Policy.Audit.CreatedAt,
		); err != nil {
			return fmt.Errorf("reserve register credential rate: %w", err)
		}

		if err := postgresCredentialCapacity(ctx, policyTx, input.TenantID, input.AgentID, input.CreatedAt); err != nil {
			return err
		}

		if err := queries.CreateCredential(ctx, postgresCreateCredentialParams(
			input.CredentialID, input.TenantID, input.AgentID, input.Name, input.Prefix,
			input.SecretHash, input.CreatedAt, input.ExpiresAt,
		)); err != nil {
			return classifyWrite("register credential", err)
		}

		if err := quota.ApplyActualUsageTx(ctx, policyTx, quota.UsageDelta{
			TenantID: input.TenantID, AgentID: input.AgentID, ActiveCredentialsAdded: 1,
		}); err != nil {
			return fmt.Errorf("apply registered credential usage: %w", err)
		}

		row, err := queries.GetCredentialByID(ctx, input.CredentialID)
		if err != nil {
			return fmt.Errorf("read registered credential: %w", err)
		}

		record, err := postgresCredentialRecord(row)
		if err != nil {
			return err
		}

		result = agent.RegisterCredentialResult{Credential: record}

		return finishPostgresPolicy(ctx, policyTx, input.Policy, result)
	})
	if err != nil {
		return agent.RegisterCredentialResult{}, err
	}

	return result, nil
}

func (s *Storage) reconcileRegisteredCredential(
	ctx context.Context,
	input agent.RegisterCredentialInput,
) (agent.RegisterCredentialResult, bool, error) {
	row, err := s.queries.GetCredentialByID(ctx, input.CredentialID)
	if errors.Is(err, pgx.ErrNoRows) {
		return agent.RegisterCredentialResult{}, false, nil
	}

	if err != nil {
		return agent.RegisterCredentialResult{}, false, fmt.Errorf("reconcile registered credential: %w", err)
	}

	record, err := postgresCredentialRecord(row)
	if err != nil {
		return agent.RegisterCredentialResult{}, false, fmt.Errorf("decode reconciled credential: %w", err)
	}

	if !sameRegisteredCredential(record, input) {
		return agent.RegisterCredentialResult{}, false, fmt.Errorf(
			"registered credential differs from canonical record: %w",
			agent.ErrAlreadyExists,
		)
	}

	return agent.RegisterCredentialResult{Credential: record, AlreadyExisted: true}, true, nil
}

func credentialRegistrationConflict(err error) bool {
	if errors.Is(err, agent.ErrAlreadyExists) {
		return true
	}

	var pgErr *pgconn.PgError

	return errors.As(err, &pgErr) && pgErr.Code == pgSerializationFailure
}

func (s *Storage) ListCredentials(
	ctx context.Context,
	input agent.ListCredentialsInput,
) (agent.ListCredentialsResult, error) {
	rows, err := s.queries.ListCredentials(ctx, sqlcgen.ListCredentialsParams{
		TenantID: input.TenantID, AgentID: input.AgentID, AfterID: input.AfterID,
		PageLimit: int64(input.Limit) + 1,
	})
	if err != nil {
		return agent.ListCredentialsResult{}, fmt.Errorf("list credentials: %w", err)
	}

	result := agent.ListCredentialsResult{Credentials: make([]agent.CredentialRecord, 0, len(rows))}
	if len(rows) > int(input.Limit) {
		result.HasMore = true
		rows = rows[:input.Limit]
	}

	for _, row := range rows {
		record, err := postgresCredentialRecord(row)
		if err != nil {
			return agent.ListCredentialsResult{}, fmt.Errorf("decode listed credential: %w", err)
		}

		result.Credentials = append(result.Credentials, record)
	}

	if result.HasMore && len(result.Credentials) > 0 {
		result.NextCursor = result.Credentials[len(result.Credentials)-1].CredentialID
	}

	return result, nil
}

func (s *Storage) GetCredentialByPrefix(ctx context.Context, prefix string) (agent.CredentialRecord, error) {
	row, err := s.queries.GetCredentialByPrefix(ctx, prefix)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return agent.CredentialRecord{}, agent.ErrNotFound
		}

		return agent.CredentialRecord{}, fmt.Errorf("get credential by prefix: %w", err)
	}

	record, err := postgresCredentialRecord(row)
	if err != nil {
		return agent.CredentialRecord{}, fmt.Errorf("decode credential by prefix: %w", err)
	}

	return record, nil
}

//nolint:cyclop // Revocation accounts expiry, principal version, audit, and replay in one transaction.
func (s *Storage) RevokeCredential(ctx context.Context, input agent.RevokeCredentialInput) error {
	return s.withinTx(ctx, func(tx pgx.Tx) error {
		queries := sqlcgen.New(tx)
		policyTx := postgresPolicyTransaction{queries: queries, now: input.RevokedAt.UTC()}

		_, found, err := postgresPolicyReplay[struct{}](
			ctx, queries, input.Policy, authz.ActionCredentialRevoke, input.TenantID, input.AgentID,
		)
		if err != nil {
			return err
		}

		if found {
			return nil
		}

		if _, err := quota.ReserveRateTx(
			ctx, policyTx, input.TenantID, input.Policy.Action, input.Policy.RateUnits, input.Policy.Audit.CreatedAt,
		); err != nil {
			return fmt.Errorf("reserve revoke credential rate: %w", err)
		}

		if err := postgresAccountExpiredCredentials(ctx, policyTx, input.TenantID, input.AgentID, input.RevokedAt); err != nil {
			return err
		}

		rows, err := queries.RevokeCredential(ctx, sqlcgen.RevokeCredentialParams{
			RevokedAtNs: input.RevokedAt.UnixNano(), TenantID: input.TenantID,
			AgentID: input.AgentID, CredentialID: input.CredentialID,
		})
		if err != nil {
			return fmt.Errorf("revoke credential: %w", err)
		}

		if rows > 0 {
			if err := quota.ApplyActualUsageTx(ctx, policyTx, quota.UsageDelta{
				TenantID: input.TenantID, AgentID: input.AgentID, ActiveCredentialsRemoved: 1,
			}); err != nil {
				return fmt.Errorf("apply revoked credential usage: %w", err)
			}

			return finishPostgresPolicy(ctx, policyTx, input.Policy, struct{}{})
		}

		existing, err := queries.GetCredentialByID(ctx, input.CredentialID)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil &&
			(existing.TenantID != input.TenantID || existing.AgentID != input.AgentID)) {
			return agent.ErrNotFound
		}

		if err != nil {
			return fmt.Errorf("check revoked credential: %w", err)
		}

		return finishPostgresPolicy(ctx, policyTx, input.Policy, struct{}{})
	})
}

func (s *Storage) TouchCredential(ctx context.Context, input agent.TouchCredentialInput) error {
	return s.withinTx(ctx, func(tx pgx.Tx) error {
		queries := sqlcgen.New(tx)
		policyTx := postgresPolicyTransaction{queries: queries, now: input.UsedAt.UTC()}

		_, found, err := postgresPolicyReplay[struct{}](
			ctx, queries, input.Policy, authz.ActionCredentialExchange, input.TenantID, input.AgentID,
		)
		if err != nil {
			return err
		}

		if found {
			return nil
		}

		if _, err := quota.ReserveRateTx(
			ctx, policyTx, input.TenantID, input.Policy.Action, input.Policy.RateUnits, input.Policy.Audit.CreatedAt,
		); err != nil {
			return fmt.Errorf("reserve credential exchange rate: %w", err)
		}

		rows, err := queries.TouchCredential(ctx, sqlcgen.TouchCredentialParams{
			UsedAtNs: input.UsedAt.UnixNano(), TenantID: input.TenantID,
			AgentID: input.AgentID, CredentialID: input.CredentialID,
		})
		if err != nil {
			return fmt.Errorf("touch credential: %w", err)
		}

		if rows == 0 {
			return agent.ErrUnauthenticated
		}

		return finishPostgresPolicy(ctx, policyTx, input.Policy, struct{}{})
	})
}

func postgresCredentialCapacity(
	ctx context.Context,
	policyTx postgresPolicyTransaction,
	tenantID, agentID string,
	now time.Time,
) error {
	capacity, err := policyTx.queries.GetAgentCredentialCapacity(ctx, sqlcgen.GetAgentCredentialCapacityParams{
		TenantID: tenantID, AgentID: agentID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return agent.ErrNotFound
		}

		return fmt.Errorf("read agent credential capacity: %w", err)
	}

	removed, err := policyTx.queries.AccountExpiredCredentials(ctx, sqlcgen.AccountExpiredCredentialsParams{
		AccountedAtNs: now.UnixNano(), TenantID: tenantID, AgentID: agentID,
	})
	if err != nil {
		return fmt.Errorf("account expired credentials: %w", err)
	}

	if len(removed) > 0 {
		if err := quota.ApplyActualUsageTx(ctx, policyTx, quota.UsageDelta{
			TenantID: tenantID, AgentID: agentID, ActiveCredentialsRemoved: uint64(len(removed)),
		}); err != nil {
			return fmt.Errorf("apply expired credential usage: %w", err)
		}
	}

	active := capacity.ActiveCredentialCount - int64(len(removed))
	if active < 0 || capacity.MaxCredentialsPerAgent <= 0 {
		return errors.New("invalid agent credential capacity ledger")
	}

	if active >= capacity.MaxCredentialsPerAgent {
		return errors.Join(agent.ErrFailedPrecondition, quota.ErrExhausted)
	}

	return nil
}

func postgresAccountExpiredCredentials(
	ctx context.Context,
	policyTx postgresPolicyTransaction,
	tenantID, agentID string,
	now time.Time,
) error {
	if _, err := policyTx.queries.GetAgentCredentialCapacity(ctx, sqlcgen.GetAgentCredentialCapacityParams{
		TenantID: tenantID, AgentID: agentID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return agent.ErrNotFound
		}

		return fmt.Errorf("read agent credential capacity: %w", err)
	}

	removed, err := policyTx.queries.AccountExpiredCredentials(ctx, sqlcgen.AccountExpiredCredentialsParams{
		AccountedAtNs: now.UnixNano(), TenantID: tenantID, AgentID: agentID,
	})
	if err != nil {
		return fmt.Errorf("account expired credentials: %w", err)
	}

	if len(removed) == 0 {
		return nil
	}

	if err := quota.ApplyActualUsageTx(ctx, policyTx, quota.UsageDelta{
		TenantID: tenantID, AgentID: agentID, ActiveCredentialsRemoved: uint64(len(removed)),
	}); err != nil {
		return fmt.Errorf("apply accounted credential usage: %w", err)
	}

	return nil
}

func postgresCreateCredentialParams(
	credentialID, tenantID, agentID, name, prefix string,
	hash [32]byte,
	createdAt time.Time,
	expiresAt *time.Time,
) sqlcgen.CreateCredentialParams {
	return sqlcgen.CreateCredentialParams{
		CredentialID: credentialID, TenantID: tenantID, AgentID: agentID,
		CredentialName: name, CredentialPrefix: prefix, SecretHash: append([]byte(nil), hash[:]...),
		CreatedAtNs: createdAt.UnixNano(), ExpiresAtNs: postgresNullableTime(expiresAt),
	}
}

func postgresCredentialRecord(row sqlcgen.AgentCredential) (agent.CredentialRecord, error) {
	if len(row.SecretHash) != 32 {
		return agent.CredentialRecord{}, fmt.Errorf("credential hash length %d", len(row.SecretHash))
	}

	return agent.CredentialRecord{
		CredentialID: row.CredentialID, TenantID: row.TenantID, AgentID: row.AgentID,
		Name: row.CredentialName, Prefix: row.CredentialPrefix,
		SecretHash: append([]byte(nil), row.SecretHash...), CreatedAt: time.Unix(0, row.CreatedAtNs).UTC(),
		ExpiresAt: postgresTimePointer(row.ExpiresAtNs), ExpiredAccountedAt: postgresTimePointer(row.ExpiredAccountedAtNs),
		RevokedAt: postgresTimePointer(row.RevokedAtNs), LastUsedAt: postgresTimePointer(row.LastUsedAtNs),
	}, nil
}

func postgresNullableTime(value *time.Time) pgtype.Int8 {
	if value == nil {
		return pgtype.Int8{}
	}

	return pgtype.Int8{Int64: value.UnixNano(), Valid: true}
}

func postgresTimePointer(value pgtype.Int8) *time.Time {
	if !value.Valid {
		return nil
	}

	decoded := time.Unix(0, value.Int64).UTC()

	return &decoded
}

func sameRegisteredCredential(record agent.CredentialRecord, input agent.RegisterCredentialInput) bool {
	return record.CredentialID == input.CredentialID && record.TenantID == input.TenantID &&
		record.AgentID == input.AgentID && record.Name == input.Name && record.Prefix == input.Prefix &&
		len(record.SecretHash) == len(input.SecretHash) && subtle.ConstantTimeCompare(record.SecretHash, input.SecretHash[:]) == 1 &&
		sameOptionalTime(record.ExpiresAt, input.ExpiresAt)
}

func sameOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}

	return left.Equal(*right)
}
