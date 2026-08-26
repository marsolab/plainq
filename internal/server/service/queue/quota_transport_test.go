package queue

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/service/quota"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type exhaustedQuotaStore struct{}

func (exhaustedQuotaStore) Reserve(
	context.Context,
	string,
	authz.Action,
	uint64,
	uint64,
	string,
	time.Time,
) (quota.ReservationResult, error) {
	return quota.ReservationResult{}, quota.ErrExhausted
}

func TestQuotaExhaustionTransportsAttachBoundedRetryTime(t *testing.T) {
	limiter, err := quota.NewLimiter(exhaustedQuotaStore{}, quota.StaticLimits{authz.ActionQueueSend: 1})
	if err != nil {
		t.Fatalf("NewLimiter() error = %v", err)
	}

	exhaustion := limiter.Consume(
		context.Background(), "tenant-a", authz.ActionQueueSend, 1, "key-a", time.Unix(10, int64(250*time.Millisecond)),
	)
	if !errors.Is(exhaustion, quota.ErrExhausted) {
		t.Fatalf("Consume() error = %v, want quota exhaustion", exhaustion)
	}

	t.Run("http", func(t *testing.T) {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/queues", nil)

		queueHTTPError(response, request, exhaustion)

		if response.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusTooManyRequests)
		}
		if retryAfter := response.Header().Get("Retry-After"); retryAfter != "1" {
			t.Fatalf("Retry-After = %q, want %q", retryAfter, "1")
		}
	})

	t.Run("grpc", func(t *testing.T) {
		_, grpcErr := queueGRPCError[struct{}](context.Background(), exhaustion)
		grpcStatus := status.Convert(grpcErr)
		if grpcStatus.Code() != codes.ResourceExhausted {
			t.Fatalf("code = %s, want %s", grpcStatus.Code(), codes.ResourceExhausted)
		}

		for _, detail := range grpcStatus.Details() {
			retryInfo, ok := detail.(*errdetails.RetryInfo)
			if !ok {
				continue
			}

			delay := retryInfo.GetRetryDelay().AsDuration()
			if delay <= 0 || delay > time.Second {
				t.Fatalf("retry delay = %s, want within (0, %s]", delay, time.Second)
			}

			return
		}

		t.Fatal("ResourceExhausted status has no RetryInfo detail")
	})
}
