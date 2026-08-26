// Package policytx defines the one policy envelope carried into every durable
// mutation transaction.
package policytx

import (
	"errors"
	"fmt"

	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/plainq/internal/server/service/securityaudit"
)

// Mutation is the caller-supplied policy context. Resource usage deltas are
// intentionally absent: stores derive them from rows actually changed.
type Mutation struct {
	TenantID       string
	Actor          principal.Ref
	Action         authz.Action
	Resource       authz.Resource
	IdempotencyKey string
	RequestHash    [32]byte
	RateUnits      uint64
	Audit          securityaudit.Event
}

// Validate rejects incomplete or internally inconsistent policy envelopes.
//
//nolint:cyclop // Every field in the durable security envelope is deliberately validated here.
func (m Mutation) Validate() error {
	if m.TenantID == "" || m.Actor.ID == "" {
		return errors.New("policy tenant and actor are required")
	}

	if m.Resource.TenantID != m.TenantID {
		return errors.New("policy resource tenant mismatch")
	}

	if !authz.ActionSupportsResource(m.Action, m.Resource.Type) {
		return fmt.Errorf("action %q does not support resource %q", m.Action, m.Resource.Type)
	}

	if m.Resource.ID == "" || m.IdempotencyKey == "" || m.RateUnits == 0 {
		return errors.New("policy resource, idempotency key, and positive rate units are required")
	}

	if m.Audit.TenantID != m.TenantID || m.Audit.ActorID != m.Actor.ID ||
		m.Audit.ActorKind != m.Actor.Kind || m.Audit.Action != string(m.Action) ||
		m.Audit.ResourceType != string(m.Resource.Type) || m.Audit.ResourceID != m.Resource.ID {
		return errors.New("policy audit projection mismatch")
	}

	if err := m.Audit.Validate(); err != nil {
		return fmt.Errorf("validate policy audit event: %w", err)
	}

	return nil
}
