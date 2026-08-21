package litestore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/plainq/internal/server/service/securityaudit"
	"github.com/marsolab/plainq/internal/server/service/securityaudit/litestore/sqlcgen"
	"github.com/marsolab/plainq/internal/shared/pqlite"
)

var _ securityaudit.Storage = (*Storage)(nil)

// Storage persists append-only audit events in SQLite or libSQL.
type Storage struct {
	queries *sqlcgen.Queries
}

// NewStorage constructs SQLite-dialect audit persistence.
func NewStorage(db pqlite.DB) (*Storage, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	return &Storage{queries: sqlcgen.New(db)}, nil
}

// Append inserts one immutable event.
func (s *Storage) Append(ctx context.Context, event securityaudit.Event) error {
	if err := securityaudit.AppendTx(ctx, auditAppender{s.queries}, event); err != nil {
		return fmt.Errorf("append sqlite security audit: %w", err)
	}

	return nil
}

// List returns one tenant-scoped keyset page.
func (s *Storage) List(ctx context.Context, query securityaudit.Query) (securityaudit.Page, error) {
	afterTime, err := parseAfterTime(query.AfterTime)
	if err != nil {
		return securityaudit.Page{}, err
	}

	rows, err := s.queries.ListAuditEvents(ctx, sqlcgen.ListAuditEventsParams{
		TenantID: query.TenantID, Action: query.Action, ResourceKind: query.ResourceType,
		ResourceID: query.ResourceID, AfterTimeNs: afterTime, AfterID: query.AfterID,
		PageLimit: int64(query.Limit) + 1,
	})
	if err != nil {
		return securityaudit.Page{}, fmt.Errorf("list sqlite audit events: %w", err)
	}

	page := securityaudit.Page{Events: make([]securityaudit.Event, 0, len(rows))}
	if len(rows) > int(query.Limit) {
		page.HasMore = true
		rows = rows[:query.Limit]
	}

	for _, row := range rows {
		event, err := sqliteEvent(row)
		if err != nil {
			return securityaudit.Page{}, err
		}

		page.Events = append(page.Events, event)
	}

	if page.HasMore && len(page.Events) > 0 {
		last := page.Events[len(page.Events)-1]
		page.NextCursor = encodeCursor(last.CreatedAt, last.EventID)
	}

	return page, nil
}

type auditAppender struct {
	queries *sqlcgen.Queries
}

func (a auditAppender) AppendAuditEvent(ctx context.Context, event securityaudit.Event) error {
	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("marshal audit metadata: %w", err)
	}

	if err := a.queries.InsertAuditEvent(ctx, sqlcgen.InsertAuditEventParams{
		AuditID: event.EventID, TenantID: event.TenantID, PrincipalKind: string(event.ActorKind),
		PrincipalID: event.ActorID, Action: event.Action, ResourceKind: event.ResourceType,
		ResourceID: event.ResourceID, Outcome: event.Outcome, RequestID: event.RequestID,
		Reason: event.Reason, SourceIp: event.SourceIP, UserAgent: event.UserAgent,
		MetadataJson: string(metadata), CreatedAtNs: event.CreatedAt.UnixNano(),
	}); err != nil {
		return fmt.Errorf("insert sqlite audit event: %w", err)
	}

	return nil
}

func sqliteEvent(row sqlcgen.SecurityAuditEvent) (securityaudit.Event, error) {
	metadata := map[string]string{}
	if err := json.Unmarshal([]byte(row.MetadataJson), &metadata); err != nil {
		return securityaudit.Event{}, fmt.Errorf("decode sqlite audit metadata: %w", err)
	}

	return securityaudit.Event{
		EventID: row.AuditID, TenantID: row.TenantID, ActorKind: principal.Kind(row.PrincipalKind),
		ActorID: row.PrincipalID, Action: row.Action, ResourceType: row.ResourceKind,
		ResourceID: row.ResourceID, Outcome: row.Outcome, RequestID: row.RequestID,
		Reason: row.Reason, SourceIP: row.SourceIp, UserAgent: row.UserAgent,
		Metadata: metadata, CreatedAt: time.Unix(0, row.CreatedAtNs).UTC(),
	}, nil
}

func parseAfterTime(value string) (int64, error) {
	if value == "" {
		return 0, nil
	}

	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return 0, fmt.Errorf("parse audit after time: %w", err)
	}

	return parsed.UnixNano(), nil
}

func encodeCursor(createdAt time.Time, eventID string) string {
	raw := createdAt.UTC().Format(time.RFC3339Nano) + "\x00" + eventID

	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}
