//nolint:wrapcheck // A decorator must hand back the provider's error unchanged; wrapping would rewrite it with a layer that adds nothing.
package discovery

import (
	"context"
	"time"

	"github.com/marsolab/plainq/internal/metrics"
)

// Compile-time check that the decorator still satisfies the contract.
var _ Discoverer = (*observed)(nil)

// observed wraps a Discoverer so every query it answers is recorded.
//
// The wrapping happens per provider rather than around the fan-out, because
// the failure worth catching is one provider going dark while the others keep
// answering. A cluster configured with both DNS and Kubernetes discovery goes
// on forming perfectly well while its Kubernetes credentials are expired —
// right up until the day DNS is the one that breaks.
type observed struct {
	inner Discoverer
}

// observe wraps a Discoverer in metrics. It is applied by Parse, so a
// provider is instrumented however it was configured — alone or as one of
// several.
func observe(discoverer Discoverer) Discoverer { return &observed{inner: discoverer} }

// Name implements Discoverer.
func (o *observed) Name() string { return o.inner.Name() }

// Discover implements Discoverer.
func (o *observed) Discover(ctx context.Context) ([]Peer, error) {
	start := time.Now()

	peers, err := o.inner.Discover(ctx)

	// The peer count is recorded next to the outcome, not folded into it: a
	// provider that answers successfully with an empty list is the failure
	// that strands a node outside its own cluster, and it is not an error.
	metrics.RecordDiscovery(o.inner.Name(), start, len(peers), err)

	return peers, err
}

// Close implements Discoverer.
func (o *observed) Close() error { return o.inner.Close() }

// Unwrap returns the provider underneath the instrumentation.
func (o *observed) Unwrap() Discoverer { return o.inner }

// Unwrap returns the provider a Discoverer wraps, or the Discoverer itself if
// it wraps nothing. Callers that need the concrete provider — a test checking
// how a spec was parsed, say — go through here rather than reaching past the
// interface.
func Unwrap(discoverer Discoverer) Discoverer {
	if wrapper, ok := discoverer.(interface{ Unwrap() Discoverer }); ok {
		return wrapper.Unwrap()
	}

	return discoverer
}
