// Package securityaudit persists metadata-only, append-only security events.
package securityaudit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/marsolab/plainq/internal/server/principal"
)

const (
	defaultPageLimit uint32 = 100
	maxPageLimit     uint32 = 1000
)

// Event is a metadata-only audit record. Request payloads and credentials have
// no representation in this type.
type Event struct {
	EventID      string
	TenantID     string
	ActorID      string
	Action       string
	ResourceType string
	ResourceID   string
	ActorKind    principal.Kind
	Outcome      string
	Reason       string
	RequestID    string
	SourceIP     string
	UserAgent    string
	Metadata     map[string]string
	CreatedAt    time.Time
}

// Query is a tenant-scoped keyset page request.
type Query struct {
	TenantID     string
	Action       string
	ResourceType string
	ResourceID   string
	AfterTime    string
	AfterID      string
	Limit        uint32
}

// Page is one append-order event page.
type Page struct {
	Events     []Event
	NextCursor string
	HasMore    bool
}

// Storage is the append-only persistence contract.
type Storage interface {
	Append(ctx context.Context, event Event) error
	List(ctx context.Context, query Query) (Page, error)
}

// Auditor is the append-only audit contract exposed by the service.
type Auditor = Storage

// Transaction is the minimum append surface implemented by an already-open
// resource transaction. It deliberately has no commit method: the owning
// store alone controls the unit of work.
type Transaction interface {
	AppendAuditEvent(ctx context.Context, event Event) error
}

type service struct {
	storage Storage
}

// New constructs an append-only auditor.
func New(storage Storage) (Auditor, error) {
	if storage == nil {
		return nil, errors.New("security audit storage is required")
	}

	return &service{storage: storage}, nil
}

// Validate rejects any metadata field outside the deliberately small safe list.
func (e Event) Validate() error {
	allowed := map[string]struct{}{
		"batch_size": {}, "message_count": {}, "delivery_count": {},
		"deduplicated_count": {}, "mode": {}, "status": {},
	}

	for key, value := range e.Metadata {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unsupported audit metadata key %q", key)
		}

		if len(value) > 256 {
			return errors.New("audit metadata value is too long")
		}
	}

	return nil
}

func (s *service) Append(ctx context.Context, event Event) error {
	if err := event.Validate(); err != nil {
		return err
	}

	if err := s.storage.Append(ctx, event); err != nil {
		return fmt.Errorf("append security audit event: %w", err)
	}

	return nil
}

func (s *service) List(ctx context.Context, query Query) (Page, error) {
	if query.TenantID == "" {
		return Page{}, errors.New("audit tenant is required")
	}

	if query.Limit == 0 {
		query.Limit = defaultPageLimit
	}

	if query.Limit > maxPageLimit {
		return Page{}, fmt.Errorf("audit limit exceeds %d", maxPageLimit)
	}

	page, err := s.storage.List(ctx, query)
	if err != nil {
		return Page{}, fmt.Errorf("list security audit events: %w", err)
	}

	return page, nil
}

// AppendTx validates and appends an event through an already-open resource
// transaction. It never begins or commits a transaction itself.
//
//nolint:cyclop // Required immutable identity fields are checked together before the transaction append.
func AppendTx(ctx context.Context, tx Transaction, event Event) error {
	if tx == nil {
		return errors.New("security audit transaction is required")
	}

	if err := event.Validate(); err != nil {
		return err
	}

	if event.EventID == "" || event.TenantID == "" || event.ActorID == "" ||
		event.Action == "" || event.ResourceType == "" || event.ResourceID == "" ||
		event.Outcome == "" || event.CreatedAt.IsZero() {
		return errors.New("security audit identity fields are required")
	}

	if err := tx.AppendAuditEvent(ctx, event); err != nil {
		return fmt.Errorf("append security audit event in transaction: %w", err)
	}

	return nil
}
