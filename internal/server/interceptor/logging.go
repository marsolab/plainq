package interceptor

import (
	"context"
	"log/slog"
	"time"

	"github.com/marsolab/servekit/ctxkit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

func Logging(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		start := time.Now().UTC()

		var reqErr error

		ctx = ctxkit.SetLogErrHook(ctx, func(err error) { reqErr = err })

		resp, err = handler(ctx, req)
		if err != nil {
			if s, ok := status.FromError(err); ok {
				logger.Error("RPC",
					slog.Int("code", int(s.Code())),
					slog.String("message", s.Message()),
					slog.String("method", info.FullMethod),
					slog.String("duration", time.Since(start).String()),
					slog.String("error", reqErr.Error()),
				)

				return resp, err
			}

			logger.Error("RPC",
				slog.String("error", err.Error()),
				slog.String("method", info.FullMethod),
				slog.String("duration", time.Since(start).String()),
				slog.String("error", reqErr.Error()),
			)

			return resp, err
		}

		logger.Info("RPC",
			slog.String("method", info.FullMethod),
			slog.String("duration", time.Since(start).String()),
		)

		return resp, err
	}
}
