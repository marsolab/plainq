package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/marsolab/plainq/internal/metrics"
)

// routeUnmatched labels requests that never matched a route, so a 404 flood
// is visible without minting a series per bad path.
const routeUnmatched = "unmatched"

// Metrics records every HTTP request: its outcome, its latency, and the sizes
// on both sides.
//
// The route label is chi's route *pattern*, not the request path — `/queues/
// {id}` rather than `/queues/01J9…`. A metric labeled with the path would
// mint a new series per queue and, on a busy server, would be the largest
// consumer of memory in the process.
func Metrics() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			metrics.RequestStarted(metrics.ProtocolHTTP)

			// Recording from a defer is what keeps the in-flight gauge and the
			// request counter consistent when a handler panics. Leaking a
			// permanent +1 on every crash would make the one metric that says
			// "the server is saturated" say it forever.
			defer func() {
				metrics.RequestFinished(metrics.ProtocolHTTP)

				if recovered := recover(); recovered != nil {
					metrics.RecordPanic(metrics.ProtocolHTTP)
					recordRequest(ww, r, start)

					panic(recovered)
				}

				recordRequest(ww, r, start)
			}()

			next.ServeHTTP(ww, r)
		}

		return http.HandlerFunc(fn)
	}
}

// recordRequest emits the metrics for one finished request.
func recordRequest(ww middleware.WrapResponseWriter, r *http.Request, start time.Time) {
	route := routeUnmatched

	if ctx := chi.RouteContext(r.Context()); ctx != nil {
		if pattern := ctx.RoutePattern(); pattern != "" {
			route = pattern
		}
	}

	metrics.RecordHTTPRequest(
		r.Method,
		route,
		strconv.Itoa(ww.Status()),
		start,
		r.ContentLength,
		ww.BytesWritten(),
	)
}
