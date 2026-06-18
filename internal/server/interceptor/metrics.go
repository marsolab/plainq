package interceptor

import (
	"context"
	"strconv"
	"time"

	"github.com/VictoriaMetrics/metrics"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

func Metrics() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		code := 0

		resp, err := handler(ctx, req)
		if err != nil {
			if s, ok := status.FromError(err); ok {
				code = int(s.Code())
			}
		}

		statusCode := strconv.Itoa(code)
		httpReqTotal := grpcReqTotalStr(info.FullMethod, statusCode)
		grpcReqDur := grpcReqDurationStr(info.FullMethod, statusCode)

		metrics.GetOrCreateCounter(httpReqTotal).
			Inc()

		metrics.GetOrCreateSummaryExt(grpcReqDur, 5*time.Minute, []float64{0.95, 0.99}).
			UpdateDuration(start)

		return resp, err
	}
}

func grpcReqDurationStr(route, code string) string {
	return `grpc_request_duration{route="` + route + `", code="` + code + `"}`
}

func grpcReqTotalStr(route, code string) string {
	return `grpc_requests_total{route="` + route + `", code="` + code + `"}`
}
