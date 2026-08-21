package litestore

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/service/quota"
	"github.com/marsolab/plainq/internal/server/service/quota/litestore/sqlcgen"
	"github.com/marsolab/plainq/internal/shared/pqlite"
)

var _ quota.WindowStore = (*Storage)(nil)

// Storage persists fixed-window reservations in SQLite or libSQL.
type Storage struct {
	db pqlite.DB
}

// NewStorage constructs SQLite-dialect quota persistence.
func NewStorage(db pqlite.DB) (*Storage, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	return &Storage{db: db}, nil
}

// Reserve resolves idempotency before conditionally incrementing the window.
//
//nolint:cyclop // Replay, conditional insert/update, and result persistence form one explicit transaction.
func (s *Storage) Reserve(
	ctx context.Context,
	tenantID string,
	action authz.Action,
	limit, units uint64,
	idempotencyKey string,
	window time.Time,
) (quota.ReservationResult, error) {
	limitValue, err := checkedInt64(limit, "limit")
	if err != nil {
		return quota.ReservationResult{}, err
	}

	unitsValue, err := checkedInt64(units, "units")
	if err != nil {
		return quota.ReservationResult{}, err
	}

	requestHash := reservationHash(tenantID, action, limit, units, window)

	var result quota.ReservationResult

	err = pqlite.WithWriteTx(ctx, s.db, pqlite.DefaultWriteRetry(), func(tx pqlite.Tx) error {
		queries := sqlcgen.New(tx)
		operation := reservationOperation(action, window)

		existing, err := queries.GetQuotaIdempotency(ctx, sqlcgen.GetQuotaIdempotencyParams{
			TenantID: tenantID, Operation: operation, IdempotencyKey: idempotencyKey,
			NowNs: window.UnixNano(),
		})
		if err == nil {
			if len(existing.RequestHash) != sha256.Size ||
				subtle.ConstantTimeCompare(existing.RequestHash, requestHash[:]) != 1 {
				return quota.ErrIdempotencyConflict
			}

			if err := json.Unmarshal([]byte(existing.ResponseJson), &result); err != nil {
				return fmt.Errorf("decode quota idempotency result: %w", err)
			}

			result.AlreadyConsumed = true

			return nil
		}

		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read quota idempotency: %w", err)
		}

		used, err := queries.InsertQuotaWindow(ctx, sqlcgen.InsertQuotaWindowParams{
			TenantID: tenantID, Action: string(action), WindowStartedAtNs: window.UnixNano(),
			Units: unitsValue, QuotaLimit: limitValue,
		})
		if errors.Is(err, sql.ErrNoRows) {
			used, err = queries.IncrementQuotaWindow(ctx, sqlcgen.IncrementQuotaWindowParams{
				Units: unitsValue, TenantID: tenantID, Action: string(action),
				WindowStartedAtNs: window.UnixNano(), QuotaLimit: limitValue,
			})
		}

		if errors.Is(err, sql.ErrNoRows) {
			return quota.ErrExhausted
		}

		if err != nil {
			return fmt.Errorf("reserve quota window: %w", err)
		}

		if used < 0 {
			return errors.New("quota window returned negative usage")
		}

		result.Used = uint64(used)

		response, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("encode quota idempotency result: %w", err)
		}

		if err := queries.InsertQuotaIdempotency(ctx, sqlcgen.InsertQuotaIdempotencyParams{
			TenantID: tenantID, Operation: operation, IdempotencyKey: idempotencyKey,
			RequestHash: requestHash[:], ResponseJson: string(response), CreatedAtNs: window.UnixNano(),
			ExpiresAtNs: window.Add(time.Second).UnixNano(),
		}); err != nil {
			return fmt.Errorf("store quota idempotency: %w", err)
		}

		return nil
	})
	if err != nil {
		return quota.ReservationResult{}, fmt.Errorf("reserve sqlite quota: %w", err)
	}

	return result, nil
}

func reservationHash(tenantID string, action authz.Action, limit, units uint64, window time.Time) [sha256.Size]byte {
	value := fmt.Sprintf("%s\x00%s\x00%d\x00%d\x00%d", tenantID, action, limit, units, window.UnixNano())

	return sha256.Sum256([]byte(value))
}

func reservationOperation(action authz.Action, window time.Time) string {
	return fmt.Sprintf("quota.%s.%d", action, window.UnixNano())
}

func checkedInt64(value uint64, name string) (int64, error) {
	if value == 0 || value > math.MaxInt64 {
		return 0, fmt.Errorf("quota %s is outside database range", name)
	}

	return int64(value), nil
}
