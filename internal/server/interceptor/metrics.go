package interceptor

import (
	"context"
	"time"

	"github.com/marsolab/plainq/internal/metrics"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Metrics records every unary gRPC call: its status code, its latency, and
// how many are in flight.
//
// The code label is the gRPC status *name* rather than its number, because
// `code="NotFound"` is a metric an operator can read and `code="5"` is one
// they have to look up.
func Metrics() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()

		metrics.RequestStarted(metrics.ProtocolGRPC)
		defer metrics.RequestFinished(metrics.ProtocolGRPC)

		resp, err := handler(ctx, req)

		metrics.RecordGRPCRequest(info.FullMethod, statusCode(err), start)

		return resp, err
	}
}

// statusCode maps a handler's error to the gRPC status name it will be sent
// as. An error carrying no gRPC status is reported as Unknown, which is
// exactly what the client will see.
func statusCode(err error) string {
	if err == nil {
		return codes.OK.String()
	}

	return status.Code(err).String()
}
