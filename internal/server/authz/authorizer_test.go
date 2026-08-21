package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/marsolab/plainq/internal/server/principal"
)

type policyStoreStub struct {
	direct bool
	legacy bool
	err    error
	checks []Resource
}

func (s *policyStoreStub) HasGrant(
	_ context.Context,
	_ principal.Principal,
	_ Action,
	resource Resource,
) (bool, error) {
	s.checks = append(s.checks, resource)

	return s.direct, s.err
}

func (s *policyStoreStub) HasLegacyPermission(
	_ context.Context,
	_ principal.Principal,
	_ Action,
	_ Resource,
) (bool, error) {
	return s.legacy, s.err
}

func TestCrossTenantResourceIsNotEnumerable(t *testing.T) {
	store := &policyStoreStub{direct: true}
	authorizer, err := NewAuthorizer(store)
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}

	err = authorizer.Authorize(context.Background(), principal.Principal{
		Kind: principal.KindAgent, ID: "agent-a", TenantID: "tenant-a",
	}, ActionAgentSend, Resource{
		Type: ResourceAgent, TenantID: "tenant-b", ID: "agent-b",
		OwnerKind: principal.KindAgent, OwnerID: "agent-b",
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Authorize() error = %v, want ErrNotFound", err)
	}

	if len(store.checks) != 0 {
		t.Fatalf("tenant mismatch performed %d grant lookups, want 0", len(store.checks))
	}
}

func TestAuthorizerUnionsDirectAndRetainedLegacyPermissions(t *testing.T) {
	tests := map[string]policyStoreStub{
		"direct grant":               {direct: true},
		"retained legacy permission": {legacy: true},
		"no grant":                   {},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			authorizer, err := NewAuthorizer(&tc)
			if err != nil {
				t.Fatalf("NewAuthorizer() error = %v", err)
			}

			err = authorizer.Authorize(context.Background(), principal.Principal{
				Kind: principal.KindHuman, ID: "human-a", TenantID: "tenant-a",
			}, ActionQueueSend, Resource{Type: ResourceQueue, TenantID: "tenant-a", ID: "queue-a"})
			if tc.direct || tc.legacy {
				if err != nil {
					t.Fatalf("Authorize() error = %v, want nil", err)
				}

				return
			}

			if !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("Authorize() error = %v, want ErrPermissionDenied", err)
			}
		})
	}
}

func TestAuthorizerFailsClosedOnGrantStorageError(t *testing.T) {
	storageErr := errors.New("storage unavailable")
	authorizer, err := NewAuthorizer(&policyStoreStub{err: storageErr})
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}

	err = authorizer.Authorize(context.Background(), principal.Principal{
		Kind: principal.KindHuman, ID: "human-a", TenantID: "tenant-a",
	}, ActionQueueSend, Resource{Type: ResourceQueue, TenantID: "tenant-a", ID: "queue-a"})
	if !errors.Is(err, storageErr) {
		t.Fatalf("Authorize() error = %v, want wrapped storage error", err)
	}
}

func TestAgentMayUseOnlyItsOwnInboxWithoutGrant(t *testing.T) {
	authorizer, err := NewAuthorizer(&policyStoreStub{})
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}

	p := principal.Principal{Kind: principal.KindAgent, ID: "agent-a", TenantID: "tenant-a"}
	own := Resource{
		Type: ResourceAgent, TenantID: "tenant-a", ID: "agent-a",
		OwnerKind: principal.KindAgent, OwnerID: "agent-a",
	}
	if err := authorizer.Authorize(context.Background(), p, ActionInboxReceive, own); err != nil {
		t.Fatalf("own inbox Authorize() error = %v", err)
	}

	other := own
	other.ID = "agent-b"
	other.OwnerID = "agent-b"
	if err := authorizer.Authorize(context.Background(), p, ActionInboxReceive, other); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("other inbox Authorize() error = %v, want ErrPermissionDenied", err)
	}
}
