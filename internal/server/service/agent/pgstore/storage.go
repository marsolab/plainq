package pgstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	agentv1 "github.com/marsolab/plainq/internal/server/schema/agent/v1"
	"github.com/marsolab/plainq/internal/server/service/agent"
	"github.com/marsolab/plainq/internal/server/service/agent/pgstore/sqlcgen"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

var _ agent.RegistryStore = (*Storage)(nil)

const (
	pgForeignKeyViolation = "23503"
	pgUniqueViolation     = "23505"
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

		return err
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

func (s *Storage) SetAgentStatus(ctx context.Context, input agent.SetAgentStatusInput) (agent.AgentRecord, error) {
	status, err := storedAgentStatus(input.Status)
	if err != nil {
		return agent.AgentRecord{}, err
	}

	var updated agent.AgentRecord

	err = s.withinTx(ctx, func(tx pgx.Tx) error {
		queries := sqlcgen.New(tx)
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

		return err
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
