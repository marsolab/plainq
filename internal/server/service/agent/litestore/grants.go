package litestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/plainq/internal/server/service/agent"
	"github.com/marsolab/plainq/internal/server/service/agent/litestore/sqlcgen"
	"github.com/marsolab/plainq/internal/server/service/quota"
	"github.com/marsolab/plainq/internal/shared/pqlite"
)

var (
	_ agent.GrantStore  = (*Storage)(nil)
	_ authz.PolicyStore = (*Storage)(nil)
)

//nolint:cyclop // Subject/resource checks stay inside the atomic grant, audit, and idempotency transaction.
func (s *Storage) CreateGrant(ctx context.Context, input agent.CreateGrantInput) (agent.GrantRecord, error) {
	if err := validateGrantInput(input.SubjectKind, input.ResourceKind, input.Action); err != nil {
		return agent.GrantRecord{}, err
	}

	var created agent.GrantRecord

	err := s.withinTx(ctx, func(tx pqlite.Tx) error {
		queries := sqlcgen.New(tx)
		policyTx := sqlitePolicyTransaction{queries: queries, now: input.CreatedAt.UTC()}

		replayed, found, err := sqlitePolicyReplay[agent.GrantRecord](
			ctx, queries, input.Policy, authz.ActionGrantManage, input.TenantID, input.TenantID,
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
			return fmt.Errorf("reserve create grant rate: %w", err)
		}

		exists, err := queries.PolicySubjectExists(ctx, sqlcgen.PolicySubjectExistsParams{
			TenantID: input.TenantID, SubjectKind: string(input.SubjectKind), SubjectID: input.SubjectID,
		})
		if err != nil {
			return fmt.Errorf("resolve grant subject: %w", err)
		}

		if !exists {
			return agent.ErrNotFound
		}

		if input.ResourceID != "*" {
			resourceExists, resourceErr := queries.PolicyResourceExists(ctx, sqlcgen.PolicyResourceExistsParams{
				ResourceKind: string(input.ResourceKind), TenantID: input.TenantID, ResourceID: input.ResourceID,
			})
			if resourceErr != nil {
				return fmt.Errorf("resolve grant resource: %w", resourceErr)
			}

			if resourceExists == 0 {
				return agent.ErrNotFound
			}
		}

		if err := queries.InsertResourceGrant(ctx, sqlcgen.InsertResourceGrantParams{
			GrantID: input.GrantID, TenantID: input.TenantID, SubjectKind: string(input.SubjectKind),
			SubjectID: input.SubjectID, ResourceKind: string(input.ResourceKind),
			ResourceID: input.ResourceID, Action: input.Action, CreatedAtNs: input.CreatedAt.UnixNano(),
		}); err != nil {
			return classifyWrite("create resource grant", err)
		}

		row, err := queries.GetResourceGrant(ctx, sqlcgen.GetResourceGrantParams{
			TenantID: input.TenantID, GrantID: input.GrantID,
		})
		if err != nil {
			return fmt.Errorf("read created resource grant: %w", err)
		}

		created, err = sqliteGrantRecord(row)
		if err != nil {
			return err
		}

		return finishSQLitePolicy(ctx, policyTx, input.Policy, created)
	})
	if err != nil {
		return agent.GrantRecord{}, err
	}

	return created, nil
}

func (s *Storage) ListGrants(ctx context.Context, input agent.ListGrantsInput) (agent.GrantPage, error) {
	limit := input.Limit
	if limit == 0 {
		limit = 100
	}

	if limit > 1000 {
		return agent.GrantPage{}, errors.New("grant page limit exceeds 1000")
	}

	rows, err := s.queries.ListResourceGrants(ctx, sqlcgen.ListResourceGrantsParams{
		TenantID: input.TenantID, SubjectKind: string(input.SubjectKind), SubjectID: input.SubjectID,
		ResourceKind: string(input.ResourceKind), ResourceID: input.ResourceID,
		AfterID: input.AfterID, PageLimit: int64(limit) + 1,
	})
	if err != nil {
		return agent.GrantPage{}, fmt.Errorf("list resource grants: %w", err)
	}

	page := agent.GrantPage{Grants: make([]agent.GrantRecord, 0, min(len(rows), int(limit)))}
	if len(rows) > int(limit) {
		page.HasMore = true
		rows = rows[:limit]
	}

	for _, row := range rows {
		record, err := sqliteGrantRecord(row)
		if err != nil {
			return agent.GrantPage{}, err
		}

		page.Grants = append(page.Grants, record)
	}

	if page.HasMore {
		page.NextCursor = page.Grants[len(page.Grants)-1].GrantID
	}

	return page, nil
}

func (s *Storage) DeleteGrant(ctx context.Context, input agent.DeleteGrantInput) error {
	return s.withinTx(ctx, func(tx pqlite.Tx) error {
		queries := sqlcgen.New(tx)
		policyTx := sqlitePolicyTransaction{queries: queries, now: input.Policy.Audit.CreatedAt.UTC()}

		_, found, err := sqlitePolicyReplay[struct{}](
			ctx, queries, input.Policy, authz.ActionGrantManage, input.TenantID, input.TenantID,
		)
		if err != nil {
			return err
		}

		if found {
			return nil
		}

		_, err = queries.GetResourceGrant(ctx, sqlcgen.GetResourceGrantParams{
			TenantID: input.TenantID, GrantID: input.GrantID,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return agent.ErrNotFound
		}

		if err != nil {
			return fmt.Errorf("read deleted resource grant: %w", err)
		}

		if _, err := quota.ReserveRateTx(
			ctx, policyTx, input.TenantID, input.Policy.Action, input.Policy.RateUnits, input.Policy.Audit.CreatedAt,
		); err != nil {
			return fmt.Errorf("reserve delete grant rate: %w", err)
		}

		rows, err := queries.DeleteResourceGrant(ctx, sqlcgen.DeleteResourceGrantParams{
			TenantID: input.TenantID, GrantID: input.GrantID,
		})
		if err != nil {
			return fmt.Errorf("delete resource grant: %w", err)
		}

		if rows != 1 {
			return agent.ErrNotFound
		}

		return finishSQLitePolicy(ctx, policyTx, input.Policy, struct{}{})
	})
}

func (s *Storage) HasGrant(
	ctx context.Context,
	p principal.Principal,
	action authz.Action,
	resource authz.Resource,
) (bool, error) {
	if p.TenantID != resource.TenantID {
		return false, nil
	}

	exists, err := s.queries.HasPolicyGrant(ctx, sqlcgen.HasPolicyGrantParams{
		TenantID: p.TenantID, SubjectKind: string(p.Kind), SubjectID: p.ID,
		ResourceKind: string(resource.Type), ResourceID: resource.ID, Action: string(action),
	})
	if err != nil {
		return false, fmt.Errorf("check direct policy grant: %w", err)
	}

	return exists, nil
}

func (s *Storage) HasLegacyPermission(
	ctx context.Context,
	p principal.Principal,
	action authz.Action,
	resource authz.Resource,
) (bool, error) {
	if p.Kind != principal.KindHuman || p.TenantID != resource.TenantID {
		return false, nil
	}

	exists, err := s.queries.HasLegacyPolicyPermission(ctx, sqlcgen.HasLegacyPolicyPermissionParams{
		SubjectID: p.ID, TenantID: p.TenantID, ResourceID: resource.ID,
		ResourceKind: string(resource.Type), Action: string(action),
	})
	if err != nil {
		return false, fmt.Errorf("check retained policy permission: %w", err)
	}

	return exists, nil
}

func sqliteGrantRecord(row sqlcgen.AgentResourceGrant) (agent.GrantRecord, error) {
	subjectKind := principal.Kind(row.SubjectKind)
	if subjectKind != principal.KindHuman && subjectKind != principal.KindAgent {
		return agent.GrantRecord{}, fmt.Errorf("unknown grant subject kind %q", row.SubjectKind)
	}

	resourceKind := authz.ResourceType(row.ResourceKind)
	if !authz.ValidResourceType(resourceKind) {
		return agent.GrantRecord{}, fmt.Errorf("unknown grant resource kind %q", row.ResourceKind)
	}

	if !authz.ActionSupportsResource(authz.Action(row.Action), resourceKind) {
		return agent.GrantRecord{}, fmt.Errorf("invalid stored grant action %q for %q", row.Action, row.ResourceKind)
	}

	return agent.GrantRecord{
		GrantID: row.GrantID, TenantID: row.TenantID, SubjectKind: subjectKind, SubjectID: row.SubjectID,
		ResourceKind: resourceKind, ResourceID: row.ResourceID, Action: row.Action,
		CreatedAt: time.Unix(0, row.CreatedAtNs).UTC(),
	}, nil
}

func validateGrantInput(subjectKind principal.Kind, resourceKind authz.ResourceType, action string) error {
	if subjectKind != principal.KindHuman && subjectKind != principal.KindAgent {
		return errors.New("grant subject must be a human or agent")
	}

	if !authz.ActionSupportsResource(authz.Action(action), resourceKind) {
		return fmt.Errorf("grant action %q is invalid for resource %q", action, resourceKind)
	}

	return nil
}
