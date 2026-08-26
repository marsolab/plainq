package policytx

import (
	"strings"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/plainq/internal/server/service/securityaudit"
)

func TestMutationValidate(t *testing.T) {
	t.Parallel()

	valid := Mutation{
		TenantID: "tenant-1",
		Actor: principal.Ref{
			Kind: principal.KindAgent,
			ID:   "agent-1",
		},
		Action: authz.ActionQueueSend,
		Resource: authz.Resource{
			Type:     authz.ResourceQueue,
			TenantID: "tenant-1",
			ID:       "queue-1",
		},
		IdempotencyKey: "request-1",
		RateUnits:      1,
		Audit: securityaudit.Event{
			EventID:      "event-1",
			TenantID:     "tenant-1",
			ActorID:      "agent-1",
			ActorKind:    principal.KindAgent,
			Action:       string(authz.ActionQueueSend),
			ResourceType: string(authz.ResourceQueue),
			ResourceID:   "queue-1",
			Outcome:      "allowed",
			CreatedAt:    time.Now().UTC(),
		},
	}

	tests := map[string]struct {
		mutate  func(*Mutation)
		wantErr string
	}{
		"valid": {},
		"missing tenant": {
			mutate:  func(m *Mutation) { m.TenantID = "" },
			wantErr: "tenant and actor",
		},
		"tenant mismatch": {
			mutate:  func(m *Mutation) { m.Resource.TenantID = "tenant-2" },
			wantErr: "tenant mismatch",
		},
		"unsupported action resource": {
			mutate:  func(m *Mutation) { m.Resource.Type = authz.ResourceTopic },
			wantErr: "does not support resource",
		},
		"missing idempotency key": {
			mutate:  func(m *Mutation) { m.IdempotencyKey = "" },
			wantErr: "idempotency key",
		},
		"zero rate units": {
			mutate:  func(m *Mutation) { m.RateUnits = 0 },
			wantErr: "positive rate units",
		},
		"audit projection mismatch": {
			mutate:  func(m *Mutation) { m.Audit.ResourceID = "queue-2" },
			wantErr: "audit projection mismatch",
		},
		"unsafe audit metadata": {
			mutate: func(m *Mutation) {
				m.Audit.Metadata = map[string]string{"payload": "secret"}
			},
			wantErr: "unsupported audit metadata",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mutation := valid
			if test.mutate != nil {
				test.mutate(&mutation)
			}

			err := mutation.Validate()
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v, want nil", err)
				}

				return
			}

			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}
