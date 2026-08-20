package interceptor

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/marsolab/plainq/internal/server/principal"
	agentv1 "github.com/marsolab/plainq/internal/server/schema/agent/v1"
	legacyv1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

func TestRoutePolicyInventoryCoversEveryGeneratedMethod(t *testing.T) {
	t.Parallel()

	for _, description := range []grpc.ServiceDesc{
		agentv1.AgentService_ServiceDesc,
		agentv1.PubSubService_ServiceDesc,
		agentv1.SystemService_ServiceDesc,
	} {
		assertGeneratedRoutesHavePolicy(t, description, false)
	}

	assertGeneratedRoutesHavePolicy(t, legacyv1.PlainQService_ServiceDesc, true)
}

func TestPublicMethodInventoryIsExact(t *testing.T) {
	t.Parallel()

	want := map[string]struct{}{
		agentv1.AgentService_ExchangeAgentCredential_FullMethodName: {},
		agentv1.SystemService_GetCapabilities_FullMethodName:        {},
		healthv1.Health_Check_FullMethodName:                        {},
		healthv1.Health_List_FullMethodName:                         {},
		healthv1.Health_Watch_FullMethodName:                        {},
	}

	got := PublicMethods()
	if len(got) != len(want) {
		t.Fatalf("public method count = %d, want %d (%v)", len(got), len(want), got)
	}
	for method := range want {
		if _, ok := got[method]; !ok {
			t.Fatalf("public method %q is missing", method)
		}
	}
}

func TestEveryGeneratedHealthMethodIsPublic(t *testing.T) {
	t.Parallel()

	public := PublicMethods()
	methods := make([]string, 0, len(healthv1.Health_ServiceDesc.Methods)+len(healthv1.Health_ServiceDesc.Streams))

	for _, method := range healthv1.Health_ServiceDesc.Methods {
		methods = append(methods, fmt.Sprintf(
			"/%s/%s", healthv1.Health_ServiceDesc.ServiceName, method.MethodName,
		))
	}
	for _, stream := range healthv1.Health_ServiceDesc.Streams {
		methods = append(methods, fmt.Sprintf(
			"/%s/%s", healthv1.Health_ServiceDesc.ServiceName, stream.StreamName,
		))
	}

	for _, method := range methods {
		if _, ok := public[method]; !ok {
			t.Errorf("generated health route %q is not public", method)
		}
	}
}

func assertGeneratedRoutesHavePolicy(t *testing.T, description grpc.ServiceDesc, legacy bool) {
	t.Helper()

	methods := make([]string, 0, len(description.Methods)+len(description.Streams))
	for _, method := range description.Methods {
		methods = append(methods, fmt.Sprintf("/%s/%s", description.ServiceName, method.MethodName))
	}
	for _, stream := range description.Streams {
		methods = append(methods, fmt.Sprintf("/%s/%s", description.ServiceName, stream.StreamName))
	}

	for _, method := range methods {
		policy, ok := routePolicies[method]
		if !ok || policy.authentication == 0 {
			t.Errorf("generated route %q lacks authentication and authorization policy", method)

			continue
		}

		if legacy && policy.authentication != authenticationLegacyCompatibility {
			t.Errorf("legacy route %q policy = %v, want compatibility", method, policy.authentication)
		}
		if !legacy && policy.authentication == authenticationLegacyCompatibility {
			t.Errorf("agent route %q was incorrectly classified as legacy compatibility", method)
		}
	}
}

func TestMethodPolicyMatrix(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		principal principal.Principal
		want      codes.Code
	}{
		{
			name:   "credential exchange is public",
			method: "/agent.v1.AgentService/ExchangeAgentCredential",
			want:   codes.OK,
		},
		{
			name:      "agent cannot create agents",
			method:    "/agent.v1.AgentService/CreateAgent",
			principal: agentPrincipal("tenant-a", "agent-a"),
			want:      codes.PermissionDenied,
		},
		{
			name:      "tenant admin can create agents",
			method:    "/agent.v1.AgentService/CreateAgent",
			principal: adminPrincipal("tenant-a", "admin-a"),
			want:      codes.OK,
		},
		{
			name:      "agent can receive its inbox",
			method:    "/agent.v1.AgentService/ReceiveInbox",
			principal: agentPrincipal("tenant-a", "agent-a"),
			want:      codes.OK,
		},
		{
			name:      "agent cannot create topics",
			method:    "/agent.v1.PubSubService/CreateTopic",
			principal: agentPrincipal("tenant-a", "agent-a"),
			want:      codes.PermissionDenied,
		},
		{
			name:   "capabilities are public",
			method: "/agent.v1.SystemService/GetCapabilities",
			want:   codes.OK,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := authorizeMethod(test.method, test.principal); got != test.want {
				t.Fatalf("authorizeMethod(%q) = %s, want %s", test.method, got, test.want)
			}
		})
	}
}

func TestCrossTenantTargetIsHiddenAndTenantScopesTheLookup(t *testing.T) {
	resources := &resourceAuthorizerStub{
		resolve: func(_ context.Context, tenantID string, selector ResourceSelector) (Resource, error) {
			if tenantID != "tenant-a" {
				t.Fatalf("ResolveResource tenant = %q, want tenant-a", tenantID)
			}
			if selector.Kind != ResourceAgent || selector.ID != "agent-b" {
				t.Fatalf("ResolveResource selector = %#v", selector)
			}

			return Resource{}, pqerr.ErrNotFound
		},
	}
	ctx := principal.With(context.Background(), agentPrincipal("tenant-a", "agent-a"))
	interceptor := UnaryAuthorize(resources)

	_, err := interceptor(ctx, &agentv1.SendToAgentRequest{TargetAgentId: "agent-b"}, &grpc.UnaryServerInfo{
		FullMethod: agentv1.AgentService_SendToAgent_FullMethodName,
	}, func(context.Context, any) (any, error) {
		t.Fatal("handler ran for cross-tenant target")

		return nil, nil
	})
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("cross-tenant SendToAgent code = %s, want %s (error %v)", got, codes.NotFound, err)
	}
}

func TestSendPublishAndSubscribeRequireExplicitGrant(t *testing.T) {
	tests := []struct {
		name   string
		method string
		req    any
		kind   ResourceKind
		action string
	}{
		{
			name: "send", method: agentv1.AgentService_SendToAgent_FullMethodName,
			req: &agentv1.SendToAgentRequest{TargetAgentId: "agent-b"}, kind: ResourceAgent, action: "send",
		},
		{
			name: "publish", method: agentv1.PubSubService_Publish_FullMethodName,
			req: &agentv1.PublishRequest{TopicId: "topic-a"}, kind: ResourceTopic, action: "publish",
		},
		{
			name: "subscribe", method: agentv1.PubSubService_CreateSubscription_FullMethodName,
			req: &agentv1.CreateSubscriptionRequest{TopicId: "topic-a"}, kind: ResourceTopic, action: "subscribe",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resources := &resourceAuthorizerStub{
				resolve: func(_ context.Context, tenantID string, selector ResourceSelector) (Resource, error) {
					if tenantID != "tenant-a" || selector.Kind != test.kind {
						t.Fatalf("ResolveResource(%q, %#v)", tenantID, selector)
					}

					return Resource{ID: selector.ID, OwnerAgentID: "agent-a"}, nil
				},
				grant: func(_ context.Context, check GrantCheck) (bool, error) {
					if check.TenantID != "tenant-a" || check.SubjectID != "agent-a" || check.Action != test.action {
						t.Fatalf("HasGrant(%#v)", check)
					}

					return false, nil
				},
			}

			ctx := principal.With(context.Background(), agentPrincipal("tenant-a", "agent-a"))
			_, err := UnaryAuthorize(resources)(ctx, test.req, &grpc.UnaryServerInfo{FullMethod: test.method},
				func(context.Context, any) (any, error) {
					t.Fatal("handler ran without grant")

					return nil, nil
				},
			)
			if got := status.Code(err); got != codes.PermissionDenied {
				t.Fatalf("%s code = %s, want %s (error %v)", test.name, got, codes.PermissionDenied, err)
			}
		})
	}
}

func TestAgentCanConsumeOnlyOwnedSubscription(t *testing.T) {
	resources := &resourceAuthorizerStub{
		resolve: func(_ context.Context, tenantID string, selector ResourceSelector) (Resource, error) {
			if tenantID != "tenant-a" || selector.Kind != ResourceSubscription || selector.ID != "subscription-b" {
				t.Fatalf("ResolveResource(%q, %#v)", tenantID, selector)
			}

			return Resource{ID: selector.ID, OwnerAgentID: "agent-b"}, nil
		},
	}
	ctx := principal.With(context.Background(), agentPrincipal("tenant-a", "agent-a"))

	_, err := UnaryAuthorize(resources)(ctx, &agentv1.PullSubscriptionRequest{SubscriptionId: "subscription-b"},
		&grpc.UnaryServerInfo{FullMethod: agentv1.PubSubService_PullSubscription_FullMethodName},
		func(context.Context, any) (any, error) {
			t.Fatal("handler ran for another agent's subscription")

			return nil, nil
		},
	)
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("PullSubscription code = %s, want %s (error %v)", got, codes.NotFound, err)
	}
}

type resourceAuthorizerStub struct {
	resolve func(context.Context, string, ResourceSelector) (Resource, error)
	grant   func(context.Context, GrantCheck) (bool, error)
}

func (s *resourceAuthorizerStub) ResolveResource(
	ctx context.Context,
	tenantID string,
	selector ResourceSelector,
) (Resource, error) {
	if s.resolve == nil {
		return Resource{}, errors.New("unexpected ResolveResource call")
	}

	return s.resolve(ctx, tenantID, selector)
}

func (s *resourceAuthorizerStub) HasGrant(ctx context.Context, check GrantCheck) (bool, error) {
	if s.grant == nil {
		return false, errors.New("unexpected HasGrant call")
	}

	return s.grant(ctx, check)
}

func agentPrincipal(tenantID, agentID string) principal.Principal {
	return principal.Principal{
		Kind: principal.KindAgent, ID: agentID, TenantID: tenantID, Roles: []string{"agent"},
	}
}

func adminPrincipal(tenantID, userID string) principal.Principal {
	return principal.Principal{
		Kind: principal.KindHuman, ID: userID, TenantID: tenantID, Roles: []string{"admin"},
	}
}
