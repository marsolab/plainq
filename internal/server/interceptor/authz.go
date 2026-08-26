package interceptor

import (
	"context"
	"errors"
	"sync"

	"github.com/marsolab/plainq/internal/server/principal"
	agentv1 "github.com/marsolab/plainq/internal/server/schema/agent/v1"
	legacyv1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

type authenticationPolicy uint8

const (
	authenticationProtected authenticationPolicy = iota + 1
	authenticationPublic
	authenticationLegacyCompatibility
)

const adminRole = "admin"

type routePolicy struct {
	authentication authenticationPolicy
}

var methodRoles = map[string][]string{
	agentv1.AgentService_CreateAgent_FullMethodName:             {adminRole},
	agentv1.AgentService_ListAgents_FullMethodName:              {adminRole},
	agentv1.AgentService_SetAgentStatus_FullMethodName:          {adminRole},
	agentv1.AgentService_CreateAgentCredential_FullMethodName:   {adminRole},
	agentv1.AgentService_ListAgentCredentials_FullMethodName:    {adminRole},
	agentv1.AgentService_RegisterAgentCredential_FullMethodName: {adminRole},
	agentv1.AgentService_RevokeAgentCredential_FullMethodName:   {adminRole},
	agentv1.AgentService_CreateGrant_FullMethodName:             {adminRole},
	agentv1.AgentService_ListGrants_FullMethodName:              {adminRole},
	agentv1.AgentService_DeleteGrant_FullMethodName:             {adminRole},
	agentv1.PubSubService_CreateTopic_FullMethodName:            {adminRole},
	agentv1.PubSubService_DeleteTopic_FullMethodName:            {adminRole},
}

var routePolicies = map[string]routePolicy{
	agentv1.AgentService_CreateAgent_FullMethodName:              {authentication: authenticationProtected},
	agentv1.AgentService_GetAgent_FullMethodName:                 {authentication: authenticationProtected},
	agentv1.AgentService_ListAgents_FullMethodName:               {authentication: authenticationProtected},
	agentv1.AgentService_SetAgentStatus_FullMethodName:           {authentication: authenticationProtected},
	agentv1.AgentService_CreateAgentCredential_FullMethodName:    {authentication: authenticationProtected},
	agentv1.AgentService_ListAgentCredentials_FullMethodName:     {authentication: authenticationProtected},
	agentv1.AgentService_RegisterAgentCredential_FullMethodName:  {authentication: authenticationProtected},
	agentv1.AgentService_RevokeAgentCredential_FullMethodName:    {authentication: authenticationProtected},
	agentv1.AgentService_ExchangeAgentCredential_FullMethodName:  {authentication: authenticationPublic},
	agentv1.AgentService_CreateGrant_FullMethodName:              {authentication: authenticationProtected},
	agentv1.AgentService_ListGrants_FullMethodName:               {authentication: authenticationProtected},
	agentv1.AgentService_DeleteGrant_FullMethodName:              {authentication: authenticationProtected},
	agentv1.AgentService_SendToAgent_FullMethodName:              {authentication: authenticationProtected},
	agentv1.AgentService_ReceiveInbox_FullMethodName:             {authentication: authenticationProtected},
	agentv1.AgentService_ListenInbox_FullMethodName:              {authentication: authenticationProtected},
	agentv1.AgentService_AckInbox_FullMethodName:                 {authentication: authenticationProtected},
	agentv1.AgentService_NackInbox_FullMethodName:                {authentication: authenticationProtected},
	agentv1.AgentService_ExtendInboxLease_FullMethodName:         {authentication: authenticationProtected},
	agentv1.AgentService_SubscribeAgent_FullMethodName:           {authentication: authenticationProtected},
	agentv1.AgentService_UnsubscribeAgent_FullMethodName:         {authentication: authenticationProtected},
	agentv1.AgentService_ListAgentSubscriptions_FullMethodName:   {authentication: authenticationProtected},
	agentv1.AgentService_ListAgentDeadLetters_FullMethodName:     {authentication: authenticationProtected},
	agentv1.AgentService_ReplayAgentDeadLetter_FullMethodName:    {authentication: authenticationProtected},
	agentv1.PubSubService_CreateTopic_FullMethodName:             {authentication: authenticationProtected},
	agentv1.PubSubService_GetTopic_FullMethodName:                {authentication: authenticationProtected},
	agentv1.PubSubService_ListTopics_FullMethodName:              {authentication: authenticationProtected},
	agentv1.PubSubService_DeleteTopic_FullMethodName:             {authentication: authenticationProtected},
	agentv1.PubSubService_Publish_FullMethodName:                 {authentication: authenticationProtected},
	agentv1.PubSubService_CreateSubscription_FullMethodName:      {authentication: authenticationProtected},
	agentv1.PubSubService_GetSubscription_FullMethodName:         {authentication: authenticationProtected},
	agentv1.PubSubService_ListSubscriptions_FullMethodName:       {authentication: authenticationProtected},
	agentv1.PubSubService_DeleteSubscription_FullMethodName:      {authentication: authenticationProtected},
	agentv1.PubSubService_SeekSubscription_FullMethodName:        {authentication: authenticationProtected},
	agentv1.PubSubService_PullSubscription_FullMethodName:        {authentication: authenticationProtected},
	agentv1.PubSubService_ListenSubscription_FullMethodName:      {authentication: authenticationProtected},
	agentv1.PubSubService_AckSubscription_FullMethodName:         {authentication: authenticationProtected},
	agentv1.PubSubService_NackSubscription_FullMethodName:        {authentication: authenticationProtected},
	agentv1.PubSubService_ExtendSubscriptionLease_FullMethodName: {authentication: authenticationProtected},
	agentv1.SystemService_GetCapabilities_FullMethodName:         {authentication: authenticationPublic},
	healthv1.Health_Check_FullMethodName:                         {authentication: authenticationPublic},
	healthv1.Health_List_FullMethodName:                          {authentication: authenticationPublic},
	healthv1.Health_Watch_FullMethodName:                         {authentication: authenticationPublic},
	legacyv1.PlainQService_ListQueues_FullMethodName:             {authentication: authenticationLegacyCompatibility},
	legacyv1.PlainQService_DescribeQueue_FullMethodName:          {authentication: authenticationLegacyCompatibility},
	legacyv1.PlainQService_CreateQueue_FullMethodName:            {authentication: authenticationLegacyCompatibility},
	legacyv1.PlainQService_PurgeQueue_FullMethodName:             {authentication: authenticationLegacyCompatibility},
	legacyv1.PlainQService_DeleteQueue_FullMethodName:            {authentication: authenticationLegacyCompatibility},
	legacyv1.PlainQService_Send_FullMethodName:                   {authentication: authenticationLegacyCompatibility},
	legacyv1.PlainQService_Receive_FullMethodName:                {authentication: authenticationLegacyCompatibility},
	legacyv1.PlainQService_Delete_FullMethodName:                 {authentication: authenticationLegacyCompatibility},
	legacyv1.PlainQService_ListTopics_FullMethodName:             {authentication: authenticationLegacyCompatibility},
	legacyv1.PlainQService_CreateTopic_FullMethodName:            {authentication: authenticationLegacyCompatibility},
	legacyv1.PlainQService_DeleteTopic_FullMethodName:            {authentication: authenticationLegacyCompatibility},
	legacyv1.PlainQService_Subscribe_FullMethodName:              {authentication: authenticationLegacyCompatibility},
	legacyv1.PlainQService_Unsubscribe_FullMethodName:            {authentication: authenticationLegacyCompatibility},
	legacyv1.PlainQService_Publish_FullMethodName:                {authentication: authenticationLegacyCompatibility},
}

// PublicMethods returns the only explicitly public gRPC methods.
func PublicMethods() map[string]struct{} {
	methods := make(map[string]struct{})

	for method, policy := range routePolicies {
		if policy.authentication == authenticationPublic {
			methods[method] = struct{}{}
		}
	}

	return methods
}

func isLegacyCompatibilityMethod(method string) bool {
	policy, ok := routePolicies[method]

	return ok && policy.authentication == authenticationLegacyCompatibility
}

func authorizeMethod(method string, p principal.Principal) codes.Code {
	policy, known := routePolicies[method]
	if !known {
		return codes.PermissionDenied
	}

	if policy.authentication != authenticationProtected {
		return codes.OK
	}

	roles, restricted := methodRoles[method]
	if !restricted {
		return codes.OK
	}

	for _, role := range roles {
		if p.HasRole(role) {
			return codes.OK
		}
	}

	return codes.PermissionDenied
}

// ResourceKind identifies an authorization resource without importing its
// persistence representation.
type ResourceKind string

const (
	// ResourceAgent is a tenant-owned agent and its direct inbox.
	ResourceAgent ResourceKind = "agent"
	// ResourceTopic is an append-log topic.
	ResourceTopic ResourceKind = "topic"
	// ResourceSubscription is an agent-owned topic subscription.
	ResourceSubscription ResourceKind = "subscription"
)

// ResourceSelector resolves exactly one tenant-scoped ID or name.
type ResourceSelector struct {
	Kind ResourceKind
	ID   string
	Name string
}

// Resource is the minimum policy projection returned by persistence.
type Resource struct {
	ID           string
	OwnerAgentID string
}

// GrantCheck identifies one direct subject-resource-action permission.
type GrantCheck struct {
	TenantID     string
	SubjectKind  principal.Kind
	SubjectID    string
	ResourceKind ResourceKind
	ResourceID   string
	Action       string
}

// ResourceAuthorizer is the persistence-backed tenant resource policy seam.
// Every lookup receives the authenticated tenant and the resource selector;
// callers never resolve an unscoped ID and compare the tenant afterward.
type ResourceAuthorizer interface {
	ResolveResource(ctx context.Context, tenantID string, selector ResourceSelector) (Resource, error)
	HasGrant(ctx context.Context, check GrantCheck) (bool, error)
}

// UnaryAuthorize enforces method roles, tenant ownership, resource ownership,
// and direct grants after UnaryAuth has injected a principal.
func UnaryAuthorize(resources ResourceAuthorizer) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if methodAllowsAnonymous(info.FullMethod, PublicMethods()) {
			return handler(ctx, req)
		}

		p, ok := principal.From(ctx)
		if !ok || p.ID == "" || p.TenantID == "" {
			return nil, status.Error(codes.Unauthenticated, "authenticated principal is required")
		}

		if code := authorizeMethod(info.FullMethod, p); code != codes.OK {
			return nil, status.Error(code, "method is not permitted")
		}

		if err := authorizeRequest(ctx, resources, info.FullMethod, p, req); err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

// StreamAuthorize performs method checks before invoking the generated stream
// handler and resource checks as soon as that handler decodes its first request.
func StreamAuthorize(resources ResourceAuthorizer) grpc.StreamServerInterceptor {
	return func(
		srv any,
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if methodAllowsAnonymous(info.FullMethod, PublicMethods()) {
			return handler(srv, stream)
		}

		p, ok := principal.From(stream.Context())
		if !ok || p.ID == "" || p.TenantID == "" {
			return status.Error(codes.Unauthenticated, "authenticated principal is required")
		}

		if code := authorizeMethod(info.FullMethod, p); code != codes.OK {
			return status.Error(code, "method is not permitted")
		}

		wrapped := &authorizationStream{
			ServerStream: stream,
			method:       info.FullMethod,
			principal:    p,
			resources:    resources,
		}

		return handler(srv, wrapped)
	}
}

type authorizationStream struct {
	grpc.ServerStream
	method    string
	principal principal.Principal
	resources ResourceAuthorizer
	once      sync.Once
	err       error
}

func (s *authorizationStream) RecvMsg(message any) error {
	if err := s.ServerStream.RecvMsg(message); err != nil {
		return err //nolint:wrapcheck // EOF and transport statuses must cross byte-for-byte.
	}

	s.once.Do(func() {
		s.err = authorizeRequest(s.Context(), s.resources, s.method, s.principal, message)
	})

	return s.err
}

//nolint:cyclop,gocyclo,gocognit,funlen // the switch is the explicit policy inventory for every agent route.
func authorizeRequest(
	ctx context.Context,
	resources ResourceAuthorizer,
	method string,
	p principal.Principal,
	req any,
) error {
	switch method {
	case agentv1.AgentService_GetAgent_FullMethodName:
		request, ok := req.(*agentv1.GetAgentRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		return authorizeSelectedAgent(ctx, resources, p, request.GetAgentId(), request.GetAgentName(), false)

	case agentv1.AgentService_SendToAgent_FullMethodName:
		request, ok := req.(*agentv1.SendToAgentRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		return authorizeGrantedResource(ctx, resources, p, ResourceSelector{
			Kind: ResourceAgent, ID: request.GetTargetAgentId(), Name: request.GetTargetAgentName(),
		}, "send")

	case agentv1.AgentService_ReceiveInbox_FullMethodName,
		agentv1.AgentService_ListenInbox_FullMethodName:
		return requireAgentPrincipal(p)

	case agentv1.AgentService_AckInbox_FullMethodName:
		request, ok := req.(*agentv1.AckInboxRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		if err := requireAgentPrincipal(p); err != nil {
			return err
		}

		for _, receipt := range request.GetReceipts() {
			if receipt != nil && receipt.GetSubscriptionId() != "" {
				if err := authorizeOwnedSubscription(ctx, resources, p, receipt.GetSubscriptionId()); err != nil {
					return err
				}
			}
		}

		return nil

	case agentv1.AgentService_NackInbox_FullMethodName:
		request, ok := req.(*agentv1.NackInboxRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		if err := requireAgentPrincipal(p); err != nil {
			return err
		}

		for _, delivery := range request.GetDeliveries() {
			if delivery != nil && delivery.GetReceipt() != nil && delivery.GetReceipt().GetSubscriptionId() != "" {
				if err := authorizeOwnedSubscription(
					ctx, resources, p, delivery.GetReceipt().GetSubscriptionId(),
				); err != nil {
					return err
				}
			}
		}

		return nil

	case agentv1.AgentService_ExtendInboxLease_FullMethodName:
		request, ok := req.(*agentv1.ExtendInboxLeaseRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		if err := requireAgentPrincipal(p); err != nil {
			return err
		}

		for _, delivery := range request.GetDeliveries() {
			if delivery != nil && delivery.GetReceipt() != nil && delivery.GetReceipt().GetSubscriptionId() != "" {
				if err := authorizeOwnedSubscription(
					ctx, resources, p, delivery.GetReceipt().GetSubscriptionId(),
				); err != nil {
					return err
				}
			}
		}

		return nil

	case agentv1.AgentService_SubscribeAgent_FullMethodName:
		request, ok := req.(*agentv1.SubscribeAgentRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		if err := authorizeSubscriptionOwner(ctx, resources, p, request.GetOwnerAgentId()); err != nil {
			return err
		}

		return authorizeGrantedResource(ctx, resources, p, ResourceSelector{
			Kind: ResourceTopic, ID: request.GetTopicId(),
		}, "subscribe")

	case agentv1.AgentService_UnsubscribeAgent_FullMethodName:
		request, ok := req.(*agentv1.UnsubscribeAgentRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		return authorizeOwnedSubscription(ctx, resources, p, request.GetSubscriptionId())

	case agentv1.AgentService_ListAgentSubscriptions_FullMethodName:
		request, ok := req.(*agentv1.ListAgentSubscriptionsRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		return authorizeSelectedAgent(ctx, resources, p, request.GetAgentId(), "", true)

	case agentv1.AgentService_ListAgentDeadLetters_FullMethodName:
		request, ok := req.(*agentv1.ListAgentDeadLettersRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		return authorizeSelectedAgent(ctx, resources, p, request.GetAgentId(), "", true)

	case agentv1.AgentService_ReplayAgentDeadLetter_FullMethodName:
		request, ok := req.(*agentv1.ReplayAgentDeadLetterRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		return authorizeSelectedAgent(ctx, resources, p, request.GetAgentId(), "", true)

	case agentv1.PubSubService_GetTopic_FullMethodName:
		request, ok := req.(*agentv1.GetTopicRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		_, err := resolveResource(ctx, resources, p.TenantID, ResourceSelector{
			Kind: ResourceTopic, ID: request.GetTopicId(), Name: request.GetTopicName(),
		})

		return err

	case agentv1.PubSubService_DeleteTopic_FullMethodName:
		request, ok := req.(*agentv1.DeleteTopicRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		_, err := resolveResource(ctx, resources, p.TenantID, ResourceSelector{
			Kind: ResourceTopic, ID: request.GetTopicId(),
		})

		return err

	case agentv1.PubSubService_Publish_FullMethodName:
		request, ok := req.(*agentv1.PublishRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		return authorizeGrantedResource(ctx, resources, p, ResourceSelector{
			Kind: ResourceTopic, ID: request.GetTopicId(), Name: request.GetTopicName(),
		}, "publish")

	case agentv1.PubSubService_CreateSubscription_FullMethodName:
		request, ok := req.(*agentv1.CreateSubscriptionRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		if err := authorizeSubscriptionOwner(ctx, resources, p, request.GetOwnerAgentId()); err != nil {
			return err
		}

		return authorizeGrantedResource(ctx, resources, p, ResourceSelector{
			Kind: ResourceTopic, ID: request.GetTopicId(),
		}, "subscribe")

	case agentv1.PubSubService_GetSubscription_FullMethodName:
		request, ok := req.(*agentv1.GetSubscriptionRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		return authorizeOwnedSubscription(ctx, resources, p, request.GetSubscriptionId())

	case agentv1.PubSubService_ListSubscriptions_FullMethodName:
		request, ok := req.(*agentv1.ListSubscriptionsRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		if request.GetTopicId() != "" {
			if _, err := resolveResource(ctx, resources, p.TenantID, ResourceSelector{
				Kind: ResourceTopic, ID: request.GetTopicId(),
			}); err != nil {
				return err
			}
		}

		return authorizeSubscriptionOwner(ctx, resources, p, request.GetOwnerAgentId())

	case agentv1.PubSubService_DeleteSubscription_FullMethodName:
		request, ok := req.(*agentv1.DeleteSubscriptionRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		return authorizeOwnedSubscription(ctx, resources, p, request.GetSubscriptionId())

	case agentv1.PubSubService_SeekSubscription_FullMethodName:
		request, ok := req.(*agentv1.SeekSubscriptionRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		return authorizeOwnedSubscription(ctx, resources, p, request.GetSubscriptionId())

	case agentv1.PubSubService_PullSubscription_FullMethodName:
		request, ok := req.(*agentv1.PullSubscriptionRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		return authorizeOwnedSubscription(ctx, resources, p, request.GetSubscriptionId())

	case agentv1.PubSubService_ListenSubscription_FullMethodName:
		request, ok := req.(*agentv1.ListenSubscriptionRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		return authorizeOwnedSubscription(ctx, resources, p, request.GetSubscriptionId())

	case agentv1.PubSubService_AckSubscription_FullMethodName:
		request, ok := req.(*agentv1.AckSubscriptionRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		return authorizeOwnedSubscription(ctx, resources, p, request.GetSubscriptionId())

	case agentv1.PubSubService_NackSubscription_FullMethodName:
		request, ok := req.(*agentv1.NackSubscriptionRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		return authorizeOwnedSubscription(ctx, resources, p, request.GetSubscriptionId())

	case agentv1.PubSubService_ExtendSubscriptionLease_FullMethodName:
		request, ok := req.(*agentv1.ExtendSubscriptionLeaseRequest)
		if !ok {
			return invalidAuthorizationRequest()
		}

		return authorizeOwnedSubscription(ctx, resources, p, request.GetSubscriptionId())

	default:
		return nil
	}
}

func requireAgentPrincipal(p principal.Principal) error {
	if p.Kind != principal.KindAgent {
		return status.Error( //nolint:wrapcheck // gRPC policy boundary.
			codes.PermissionDenied, "an agent principal is required",
		)
	}

	return nil
}

func authorizeSelectedAgent(
	ctx context.Context,
	resources ResourceAuthorizer,
	p principal.Principal,
	agentID string,
	agentName string,
	requireAdminSelection bool,
) error {
	if agentID == "" && agentName == "" {
		if p.Kind == principal.KindAgent && !requireAdminSelection {
			return nil
		}

		if p.Kind == principal.KindAgent {
			return nil
		}

		return status.Error( //nolint:wrapcheck // gRPC policy boundary.
			codes.InvalidArgument, "target agent is required",
		)
	}

	resource, err := resolveResource(ctx, resources, p.TenantID, ResourceSelector{
		Kind: ResourceAgent, ID: agentID, Name: agentName,
	})
	if err != nil {
		return err
	}

	if p.HasRole(adminRole) {
		return nil
	}

	if p.Kind == principal.KindAgent && resource.ID == p.ID {
		return nil
	}

	return status.Error(codes.NotFound, "resource not found") //nolint:wrapcheck // gRPC policy boundary.
}

func authorizeSubscriptionOwner(
	ctx context.Context,
	resources ResourceAuthorizer,
	p principal.Principal,
	ownerAgentID string,
) error {
	if ownerAgentID == "" {
		if p.Kind == principal.KindAgent {
			return nil
		}

		return status.Error(codes.InvalidArgument, "owner agent is required") //nolint:wrapcheck // gRPC policy boundary.
	}

	return authorizeSelectedAgent(ctx, resources, p, ownerAgentID, "", true)
}

func authorizeOwnedSubscription(
	ctx context.Context,
	resources ResourceAuthorizer,
	p principal.Principal,
	subscriptionID string,
) error {
	resource, err := resolveResource(ctx, resources, p.TenantID, ResourceSelector{
		Kind: ResourceSubscription, ID: subscriptionID,
	})
	if err != nil {
		return err
	}

	if p.HasRole(adminRole) {
		return nil
	}

	if p.Kind == principal.KindAgent && resource.OwnerAgentID == p.ID {
		return nil
	}

	return status.Error(codes.NotFound, "resource not found") //nolint:wrapcheck // gRPC policy boundary.
}

func authorizeGrantedResource(
	ctx context.Context,
	resources ResourceAuthorizer,
	p principal.Principal,
	selector ResourceSelector,
	action string,
) error {
	resource, err := resolveResource(ctx, resources, p.TenantID, selector)
	if err != nil {
		return err
	}

	if p.HasRole(adminRole) {
		return nil
	}

	if resources == nil {
		return status.Error( //nolint:wrapcheck // gRPC policy boundary.
			codes.PermissionDenied, "resource authorization is unavailable",
		)
	}

	granted, err := resources.HasGrant(ctx, GrantCheck{
		TenantID: p.TenantID, SubjectKind: p.Kind, SubjectID: p.ID,
		ResourceKind: selector.Kind, ResourceID: resource.ID, Action: action,
	})
	if err != nil {
		return mapResourceError(err)
	}

	if !granted {
		return status.Error(codes.PermissionDenied, "resource grant is required") //nolint:wrapcheck // gRPC policy boundary.
	}

	return nil
}

func resolveResource(
	ctx context.Context,
	resources ResourceAuthorizer,
	tenantID string,
	selector ResourceSelector,
) (Resource, error) {
	if resources == nil {
		return Resource{}, status.Error( //nolint:wrapcheck // gRPC policy boundary.
			codes.PermissionDenied, "resource authorization is unavailable",
		)
	}

	resource, err := resources.ResolveResource(ctx, tenantID, selector)
	if err != nil {
		return Resource{}, mapResourceError(err)
	}

	if resource.ID == "" {
		return Resource{}, status.Error(codes.NotFound, "resource not found") //nolint:wrapcheck // gRPC policy boundary.
	}

	return resource, nil
}

func mapResourceError(err error) error {
	switch {
	case errors.Is(err, pqerr.ErrNotFound):
		return status.Error(codes.NotFound, "resource not found") //nolint:wrapcheck // gRPC policy boundary.

	case errors.Is(err, pqerr.ErrUnavailable):
		return status.Error( //nolint:wrapcheck // gRPC policy boundary.
			codes.Unavailable, "resource authorization is unavailable",
		)

	default:
		return status.Error(codes.Internal, "resource authorization failed") //nolint:wrapcheck // gRPC policy boundary.
	}
}

func invalidAuthorizationRequest() error {
	return status.Error(codes.Internal, "authorization request type mismatch") //nolint:wrapcheck // gRPC policy boundary.
}
