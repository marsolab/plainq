package agent

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/principal"
	agentv1 "github.com/marsolab/plainq/internal/server/schema/agent/v1"
	"github.com/marsolab/plainq/internal/server/service/securityaudit"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

// CreateGrant creates one tenant-scoped fixed-vocabulary direct grant.
//
//nolint:cyclop // Grant validation intentionally enumerates every security-sensitive input.
func (s *Service) CreateGrant(
	ctx context.Context,
	req *agentv1.CreateGrantRequest,
) (*agentv1.CreateGrantResponse, error) {
	p, err := requireTenantAdmin(ctx)
	if err != nil {
		return nil, err
	}

	if s.grants == nil {
		return nil, fmt.Errorf("grant store is unavailable: %w", pqerr.ErrUnavailable)
	}

	if req == nil {
		return nil, invalidInput("create grant request is required")
	}

	subjectKind, err := grantSubjectKind(req.GetSubjectKind(), false)
	if err != nil {
		return nil, err
	}

	resourceKind, err := grantResourceKind(req.GetResourceKind(), false)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(req.GetSubjectId()) == "" {
		return nil, invalidInput("grant subject ID is required")
	}

	if strings.TrimSpace(req.GetResourceId()) == "" {
		return nil, invalidInput("grant resource ID is required")
	}

	action := authz.Action(req.GetAction())
	if !authz.ActionSupportsResource(action, resourceKind) {
		return nil, invalidInput("grant action is invalid for resource kind")
	}

	grantID := s.nextID()
	if err := validateULID(grantID, "generated grant ID"); err != nil {
		return nil, fmt.Errorf("generate grant ID: %w", err)
	}

	now := s.clock().UTC()

	policy, err := s.mutationFor(ctx, p, authz.ActionGrantManage, authz.Resource{
		Type: authz.ResourceTenant, TenantID: p.TenantID, ID: p.TenantID,
	}, req, now, nil)
	if err != nil {
		return nil, fmt.Errorf("build create grant policy: %w", err)
	}

	record, err := s.grants.CreateGrant(ctx, CreateGrantInput{
		GrantID: grantID, TenantID: p.TenantID, SubjectKind: subjectKind, SubjectID: req.GetSubjectId(),
		ResourceKind: resourceKind, ResourceID: req.GetResourceId(), Action: string(action),
		CreatedAt: now, Policy: policy,
	})
	if err != nil {
		return nil, fmt.Errorf("create grant: %w", err)
	}

	return &agentv1.CreateGrantResponse{Grant: toProtoGrant(record)}, nil
}

// ListGrants lists direct grants through an opaque grant-ID cursor.
//
//nolint:cyclop // Optional grant filters are validated independently before the tenant-scoped query.
func (s *Service) ListGrants(
	ctx context.Context,
	req *agentv1.ListGrantsRequest,
) (*agentv1.ListGrantsResponse, error) {
	p, err := requireTenantAdmin(ctx)
	if err != nil {
		return nil, err
	}

	if s.grants == nil {
		return nil, fmt.Errorf("grant store is unavailable: %w", pqerr.ErrUnavailable)
	}

	if req == nil {
		return nil, invalidInput("list grants request is required")
	}

	subjectKind, err := grantSubjectKind(req.GetSubjectKind(), true)
	if err != nil {
		return nil, err
	}

	resourceKind, err := grantResourceKind(req.GetResourceKind(), true)
	if err != nil {
		return nil, err
	}

	if req.GetSubjectId() != "" && subjectKind == "" {
		return nil, invalidInput("grant subject kind is required with subject ID")
	}

	if req.GetResourceId() != "" && resourceKind == "" {
		return nil, invalidInput("grant resource kind is required with resource ID")
	}

	limit, err := pageSize(req.GetLimit())
	if err != nil {
		return nil, err
	}

	afterID, err := decodeGrantCursor(req.GetCursor())
	if err != nil {
		return nil, err
	}

	page, err := s.grants.ListGrants(ctx, ListGrantsInput{
		TenantID: p.TenantID, SubjectKind: subjectKind, SubjectID: req.GetSubjectId(),
		ResourceKind: resourceKind, ResourceID: req.GetResourceId(), AfterID: afterID, Limit: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}

	grants := make([]*agentv1.ResourceGrant, 0, len(page.Grants))
	for _, record := range page.Grants {
		grants = append(grants, toProtoGrant(record))
	}

	nextCursor := ""
	if page.HasMore {
		nextCursor = encodeGrantCursor(page.NextCursor)
	}

	s.auditGrantRead(ctx, p, "list")

	return &agentv1.ListGrantsResponse{Grants: grants, NextCursor: nextCursor, HasMore: page.HasMore}, nil
}

// DeleteGrant removes one tenant-owned direct grant atomically with its audit.
func (s *Service) DeleteGrant(
	ctx context.Context,
	req *agentv1.DeleteGrantRequest,
) (*agentv1.DeleteGrantResponse, error) {
	p, err := requireTenantAdmin(ctx)
	if err != nil {
		return nil, err
	}

	if s.grants == nil {
		return nil, fmt.Errorf("grant store is unavailable: %w", pqerr.ErrUnavailable)
	}

	if req == nil {
		return nil, invalidInput("delete grant request is required")
	}

	if err := validateULID(req.GetGrantId(), "grant ID"); err != nil {
		return nil, err
	}

	now := s.clock().UTC()

	policy, err := s.mutationFor(ctx, p, authz.ActionGrantManage, authz.Resource{
		Type: authz.ResourceTenant, TenantID: p.TenantID, ID: p.TenantID,
	}, req, now, nil)
	if err != nil {
		return nil, fmt.Errorf("build delete grant policy: %w", err)
	}

	if err := s.grants.DeleteGrant(ctx, DeleteGrantInput{
		TenantID: p.TenantID, GrantID: req.GetGrantId(), Policy: policy,
	}); err != nil {
		return nil, fmt.Errorf("delete grant: %w", err)
	}

	return &agentv1.DeleteGrantResponse{}, nil
}

func grantSubjectKind(kind agentv1.PrincipalKind, allowUnspecified bool) (principal.Kind, error) {
	switch kind {
	case agentv1.PrincipalKind_PRINCIPAL_KIND_HUMAN:
		return principal.KindHuman, nil
	case agentv1.PrincipalKind_PRINCIPAL_KIND_AGENT:
		return principal.KindAgent, nil
	case agentv1.PrincipalKind_PRINCIPAL_KIND_UNSPECIFIED:
		if allowUnspecified {
			return "", nil
		}
	}

	return "", invalidInput("grant subject kind must be human or agent")
}

func grantResourceKind(kind agentv1.ResourceKind, allowUnspecified bool) (authz.ResourceType, error) {
	switch kind {
	case agentv1.ResourceKind_RESOURCE_KIND_TENANT:
		return authz.ResourceTenant, nil
	case agentv1.ResourceKind_RESOURCE_KIND_AGENT:
		return authz.ResourceAgent, nil
	case agentv1.ResourceKind_RESOURCE_KIND_QUEUE:
		return authz.ResourceQueue, nil
	case agentv1.ResourceKind_RESOURCE_KIND_TOPIC:
		return authz.ResourceTopic, nil
	case agentv1.ResourceKind_RESOURCE_KIND_SUBSCRIPTION:
		return authz.ResourceSubscription, nil
	case agentv1.ResourceKind_RESOURCE_KIND_UNSPECIFIED:
		if allowUnspecified {
			return "", nil
		}
	}

	return "", invalidInput("grant resource kind is invalid")
}

func toProtoGrant(record GrantRecord) *agentv1.ResourceGrant {
	return &agentv1.ResourceGrant{
		GrantId: record.GrantID, SubjectKind: protoGrantSubjectKind(record.SubjectKind),
		SubjectId: record.SubjectID, ResourceKind: protoGrantResourceKind(record.ResourceKind),
		ResourceId: record.ResourceID, Action: record.Action, CreatedAt: timestamppb.New(record.CreatedAt),
	}
}

func protoGrantSubjectKind(kind principal.Kind) agentv1.PrincipalKind {
	if kind == principal.KindHuman {
		return agentv1.PrincipalKind_PRINCIPAL_KIND_HUMAN
	}

	return agentv1.PrincipalKind_PRINCIPAL_KIND_AGENT
}

func protoGrantResourceKind(kind authz.ResourceType) agentv1.ResourceKind {
	switch kind {
	case authz.ResourceTenant:
		return agentv1.ResourceKind_RESOURCE_KIND_TENANT
	case authz.ResourceAgent:
		return agentv1.ResourceKind_RESOURCE_KIND_AGENT
	case authz.ResourceQueue:
		return agentv1.ResourceKind_RESOURCE_KIND_QUEUE
	case authz.ResourceTopic:
		return agentv1.ResourceKind_RESOURCE_KIND_TOPIC
	case authz.ResourceSubscription:
		return agentv1.ResourceKind_RESOURCE_KIND_SUBSCRIPTION
	default:
		return agentv1.ResourceKind_RESOURCE_KIND_UNSPECIFIED
	}
}

func encodeGrantCursor(grantID string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(grantID))
}

func decodeGrantCursor(cursor string) (string, error) {
	if cursor == "" {
		return "", nil
	}

	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", invalidInput("grant cursor is invalid")
	}

	grantID := string(decoded)
	if err := validateULID(grantID, "grant cursor"); err != nil {
		return "", invalidInput("grant cursor is invalid")
	}

	return grantID, nil
}

func (s *Service) auditGrantRead(ctx context.Context, p principal.Principal, mode string) {
	if s.auditor == nil {
		return
	}

	eventID := s.nextMutationID()
	if eventID == "" {
		return
	}

	requestID, userAgent := policyRequestMetadata(ctx)
	if err := s.auditor.Append(ctx, securityaudit.Event{
		EventID: eventID, TenantID: p.TenantID, ActorKind: p.Kind, ActorID: p.ID,
		Action: string(authz.ActionGrantManage), ResourceType: string(authz.ResourceTenant), ResourceID: p.TenantID,
		Outcome: "success", RequestID: requestID, SourceIP: sourceIP(ctx), UserAgent: userAgent,
		Metadata: map[string]string{"mode": mode}, CreatedAt: s.clock().UTC(),
	}); err != nil {
		return
	}
}
