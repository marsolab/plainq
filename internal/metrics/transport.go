package metrics

import "time"

// Transport label names.
const (
	labelMethod   = "method"
	labelRoute    = "route"
	labelCode     = "code"
	labelProtocol = "protocol"
)

// Protocol label values for the transport-agnostic families.
const (
	ProtocolHTTP = "http"
	ProtocolGRPC = "grpc"
)

// HTTP and gRPC metrics.
var (
	httpRequests = NewCounterVec(Definition{
		Name:   Namespace + "_http_requests_total",
		Help:   "HTTP requests served, by route and status code.",
		Labels: []string{labelMethod, labelRoute, labelCode},
	})

	httpRequestDuration = NewHistogramVec(Definition{
		Name:   Namespace + "_http_request_duration_seconds",
		Help:   "HTTP request latency by route, measured across the whole handler chain.",
		Labels: []string{labelMethod, labelRoute},
	}, LatencyBuckets)

	httpRequestSize = NewHistogramVec(Definition{
		Name:   Namespace + "_http_request_size_bytes",
		Help:   "Distribution of HTTP request body sizes, as declared by Content-Length.",
		Labels: []string{labelMethod, labelRoute},
	}, SizeBuckets)

	httpResponseSize = NewHistogramVec(Definition{
		Name:   Namespace + "_http_response_size_bytes",
		Help:   "Distribution of HTTP response body sizes.",
		Labels: []string{labelMethod, labelRoute},
	}, SizeBuckets)

	grpcRequests = NewCounterVec(Definition{
		Name:   Namespace + "_grpc_requests_total",
		Help:   "gRPC unary calls served, by method and status code.",
		Labels: []string{labelMethod, labelCode},
	})

	grpcRequestDuration = NewHistogramVec(Definition{
		Name:   Namespace + "_grpc_request_duration_seconds",
		Help:   "gRPC unary call latency by method.",
		Labels: []string{labelMethod},
	}, LatencyBuckets)

	requestsInFlight = NewGaugeVec(Definition{
		Name:   Namespace + "_requests_in_flight",
		Help:   "Requests currently being served. Climbing while throughput is flat means the server is the bottleneck.",
		Labels: []string{labelProtocol},
	})

	panicsRecovered = NewCounterVec(Definition{
		Name:   Namespace + "_panics_recovered_total",
		Help:   "Panics caught by a transport's recovery layer. Any value above zero is a bug.",
		Labels: []string{labelProtocol},
	})
)

// RecordHTTPRequest records one served HTTP request.
//
// requestBytes of -1 means the request did not declare a length (a chunked
// upload), which is recorded as no observation rather than as zero.
func RecordHTTPRequest(method, route, code string, start time.Time, requestBytes int64, responseBytes int) {
	httpRequests.With(method, route, code).Inc()
	httpRequestDuration.ObserveSince(start, method, route)

	if requestBytes >= 0 {
		httpRequestSize.Observe(float64(requestBytes), method, route)
	}

	if responseBytes >= 0 {
		httpResponseSize.Observe(float64(responseBytes), method, route)
	}
}

// RecordGRPCRequest records one served gRPC unary call.
func RecordGRPCRequest(method, code string, start time.Time) {
	grpcRequests.With(method, code).Inc()
	grpcRequestDuration.ObserveSince(start, method)
}

// RequestStarted marks a request as in flight.
func RequestStarted(protocol string) { requestsInFlight.Add(1, protocol) }

// RequestFinished marks an in-flight request as done.
func RequestFinished(protocol string) { requestsInFlight.Add(-1, protocol) }

// RecordPanic records a panic a transport had to recover from.
func RecordPanic(protocol string) { panicsRecovered.With(protocol).Inc() }
