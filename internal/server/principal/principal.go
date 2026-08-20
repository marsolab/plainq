package principal

import (
	"context"
	"errors"
	"time"
)

type Kind string

const (
	KindHuman  Kind = "human"
	KindAgent  Kind = "agent"
	KindSystem Kind = "system"
)

type Principal struct {
	Kind         Kind
	ID           string
	TenantID     string
	Roles        []string
	CredentialID string
	AuthVersion  uint64
	TokenID      string
	ExpiresAt    time.Time
}

type Ref struct {
	Kind Kind
	ID   string
}

func (p Principal) Ref() Ref {
	return Ref{Kind: p.Kind, ID: p.ID}
}

type contextKey struct{}

func With(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, contextKey{}, p)
}

func From(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(contextKey{}).(Principal)
	return p, ok
}

var ErrUnauthenticated = errors.New("principal is required")

func Require(ctx context.Context) (Principal, error) {
	p, ok := From(ctx)
	if !ok || p.ID == "" || p.TenantID == "" {
		return Principal{}, ErrUnauthenticated
	}
	return p, nil
}

func (p Principal) HasRole(want string) bool {
	for _, role := range p.Roles {
		if role == want {
			return true
		}
	}
	return false
}
