package interceptor

import (
	"context"
	"log/slog"
	"time"

	"github.com/marsolab/servekit/ctxkit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Logging records only transport metadata. Request values, bearer metadata,
// handler error strings, and gRPC status messages are deliberately excluded:
// all four can carry credentials, receipt handles, or message bodies.
func Logging(logger *slog.Logger) grpc.UnaryServerInterceptor {
	logger = nonNilLogger(logger)

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		ctx = ctxkit.SetLogErrHook(ctx, func(error) {})

		response, err := handler(ctx, req)
		logRPC(logger, info.FullMethod, status.Code(err), time.Since(start))

		return response, err
	}
}

// StreamLogging applies the same secret-safe policy to streaming calls.
func StreamLogging(logger *slog.Logger) grpc.StreamServerInterceptor {
	logger = nonNilLogger(logger)

	return func(
		srv any,
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		start := time.Now()
		err := handler(srv, stream)
		logRPC(logger, info.FullMethod, status.Code(err), time.Since(start))

		return err
	}
}

func logRPC(logger *slog.Logger, method string, code codes.Code, duration time.Duration) {
	attributes := []any{
		slog.String("code", code.String()),
		slog.String("method", method),
		slog.Duration("duration", duration),
	}

	if code == codes.OK {
		logger.Info("RPC", attributes...)

		return
	}

	logger.Error("RPC", attributes...)
}

func nonNilLogger(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return slog.Default()
	}

	return logger
}
