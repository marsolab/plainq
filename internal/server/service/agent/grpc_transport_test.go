package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/service/quota"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestMapGRPCQuotaExhaustionIncludesBoundedRetryTime(t *testing.T) {
	_, err := mapGRPC(context.Background(), struct{}{}, errors.Join(ErrFailedPrecondition, quota.ErrExhausted))
	grpcStatus := status.Convert(err)
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
}
