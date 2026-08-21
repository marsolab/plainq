package principal

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestRequirePrincipalRejectsMissingContext(t *testing.T) {
	_, err := Require(context.Background())
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Require() error = %v, want ErrUnauthenticated", err)
	}
}

func TestWithAndFromPreservePrincipal(t *testing.T) {
	want := Principal{
		Kind:         KindAgent,
		ID:           "agent-a",
		TenantID:     "tenant-a",
		Roles:        []string{"publisher", "reader"},
		CredentialID: "credential-a",
		AuthVersion:  3,
		TokenID:      "token-a",
		ExpiresAt:    time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC),
	}

	got, ok := From(With(context.Background(), want))
	if !ok {
		t.Fatal("From() found no principal")
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("From() = %#v, want %#v", got, want)
	}

	required, err := Require(With(context.Background(), want))
	if err != nil {
		t.Fatalf("Require() error = %v", err)
	}
	if !reflect.DeepEqual(required, want) {
		t.Fatalf("Require() = %#v, want %#v", required, want)
	}
}

func TestRequirePrincipalRejectsIncompleteIdentity(t *testing.T) {
	tests := []Principal{
		{Kind: KindAgent, TenantID: "tenant-a"},
		{Kind: KindAgent, ID: "agent-a"},
	}

	for _, principal := range tests {
		_, err := Require(With(context.Background(), principal))
		if !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("Require(%#v) error = %v, want ErrUnauthenticated", principal, err)
		}
	}
}

func TestPrincipalRefAndHasRole(t *testing.T) {
	p := Principal{Kind: KindHuman, ID: "human-a", Roles: []string{"admin"}}
	if got, want := p.Ref(), (Ref{Kind: KindHuman, ID: "human-a"}); got != want {
		t.Fatalf("Ref() = %#v, want %#v", got, want)
	}
	if !p.HasRole("admin") {
		t.Fatal("HasRole(admin) = false, want true")
	}
	if p.HasRole("reader") {
		t.Fatal("HasRole(reader) = true, want false")
	}
}
