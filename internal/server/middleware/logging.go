package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/marsolab/servekit/ctxkit"
)

// Logging represents logging middleware.
func Logging(logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			start := time.Now().UTC()

			var reqErr error

			ctx := ctxkit.SetLogErrHook(r.Context(), func(err error) { reqErr = err })

			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r.WithContext(ctx))
			status := ww.Status()

			if status >= http.StatusInternalServerError {
				if reqErr != nil {
					logger.Error("HTTP",
						slog.String("method", r.Method),
						slog.Int("status", status),
						slog.String("uri", r.RequestURI),
						slog.String("remote", r.RemoteAddr),
						slog.String("duration", time.Since(start).String()),
						slog.String("error", reqErr.Error()),
					)
					return
				}

				logger.Error("HTTP",
					slog.String("method", r.Method),
					slog.Int("status", status),
					slog.String("uri", r.RequestURI),
					slog.String("remote", r.RemoteAddr),
					slog.String("duration", time.Since(start).String()),
				)
			} else {
				logger.Info("HTTP",
					slog.String("method", r.Method),
					slog.Int("status", status),
					slog.String("uri", r.RequestURI),
					slog.String("remote", r.RemoteAddr),
					slog.String("duration", time.Since(start).String()),
				)
			}
		}

		return http.HandlerFunc(fn)
	}
}
