package pgstore

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/service/quota"
	"github.com/marsolab/plainq/internal/server/service/quota/pgstore/sqlcgen"
)

var _ quota.WindowStore = (*Storage)(nil)

const maxReservationAttempts = 4

// Storage persists fixed-window reservations in PostgreSQL.
type Storage struct {
	pool *pgxpool.Pool
}

// NewStorage constructs PostgreSQL quota persistence.
func NewStorage(pool *pgxpool.Pool) (*Storage, error) {
	if pool == nil {
		return nil, errors.New("pool is nil")
	}

	return &Storage{pool: pool}, nil
}

// Reserve resolves idempotency before conditionally incrementing the window.
func (s *Storage) Reserve(
	ctx context.Context,
	tenantID string,
	action authz.Action,
	limit, units uint64,
	idempotencyKey string,
	window time.Time,
) (quota.ReservationResult, error) {
	var lastErr error

	for range maxReservationAttempts {
		result, err := s.reserveOnce(ctx, tenantID, action, limit, units, idempotencyKey, window)
		if err == nil || !retryableReservation(err) {
			return result, err
		}

		lastErr = err
		if err := ctx.Err(); err != nil {
			return quota.ReservationResult{}, fmt.Errorf("reserve quota context: %w", err)
		}
	}

	return quota.ReservationResult{}, fmt.Errorf("reserve quota retries exhausted: %w", lastErr)
}

//nolint:cyclop,gocyclo // Replay, conditional insert/update, and result persistence form one explicit transaction.
func (s *Storage) reserveOnce(
	ctx context.Context,
	tenantID string,
	action authz.Action,
	limit, units uint64,
	idempotencyKey string,
	window time.Time,
) (_ quota.ReservationResult, rErr error) {
	limitValue, err := checkedInt64(limit, "limit")
	if err != nil {
		return quota.ReservationResult{}, err
	}

	unitsValue, err := checkedInt64(units, "units")
	if err != nil {
		return quota.ReservationResult{}, err
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return quota.ReservationResult{}, fmt.Errorf("begin quota transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			rErr = errors.Join(rErr, fmt.Errorf("rollback quota transaction: %w", err))
		}
	}()

	queries := sqlcgen.New(tx)
	operation := reservationOperation(action, window)
	requestHash := reservationHash(tenantID, action, limit, units, window)

	existing, err := queries.GetQuotaIdempotency(ctx, sqlcgen.GetQuotaIdempotencyParams{
		TenantID: tenantID, Operation: operation, IdempotencyKey: idempotencyKey,
		NowNs: window.UnixNano(),
	})
	if err == nil {
		if len(existing.RequestHash) != sha256.Size ||
			subtle.ConstantTimeCompare(existing.RequestHash, requestHash[:]) != 1 {
			return quota.ReservationResult{}, quota.ErrIdempotencyConflict
		}

		var result quota.ReservationResult
		if err := json.Unmarshal(existing.ResponseJson, &result); err != nil {
			return quota.ReservationResult{}, fmt.Errorf("decode quota idempotency result: %w", err)
		}

		result.AlreadyConsumed = true

		return result, nil
	}

	if !errors.Is(err, pgx.ErrNoRows) {
		return quota.ReservationResult{}, fmt.Errorf("read quota idempotency: %w", err)
	}

	used, err := queries.InsertQuotaWindow(ctx, sqlcgen.InsertQuotaWindowParams{
		TenantID: tenantID, Action: string(action), WindowStartedAtNs: window.UnixNano(),
		Units: unitsValue, QuotaLimit: limitValue,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		used, err = queries.IncrementQuotaWindow(ctx, sqlcgen.IncrementQuotaWindowParams{
			Units: unitsValue, TenantID: tenantID, Action: string(action),
			WindowStartedAtNs: window.UnixNano(), QuotaLimit: limitValue,
		})
	}

	if errors.Is(err, pgx.ErrNoRows) {
		return quota.ReservationResult{}, quota.ErrExhausted
	}

	if err != nil {
		return quota.ReservationResult{}, fmt.Errorf("reserve quota window: %w", err)
	}

	if used < 0 {
		return quota.ReservationResult{}, errors.New("quota window returned negative usage")
	}

	result := quota.ReservationResult{Used: uint64(used)}

	response, err := json.Marshal(result)
	if err != nil {
		return quota.ReservationResult{}, fmt.Errorf("encode quota idempotency result: %w", err)
	}

	if err := queries.InsertQuotaIdempotency(ctx, sqlcgen.InsertQuotaIdempotencyParams{
		TenantID: tenantID, Operation: operation, IdempotencyKey: idempotencyKey,
		RequestHash: requestHash[:], ResponseJson: response, CreatedAtNs: window.UnixNano(),
		ExpiresAtNs: window.Add(time.Second).UnixNano(),
	}); err != nil {
		return quota.ReservationResult{}, fmt.Errorf("store quota idempotency: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return quota.ReservationResult{}, fmt.Errorf("commit quota transaction: %w", err)
	}

	return result, nil
}

func retryableReservation(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}

	return pgErr.Code == "40001" || pgErr.Code == "23505"
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
