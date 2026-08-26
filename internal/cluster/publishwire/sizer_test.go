package publishwire

import (
	"math"
	"testing"
)

func TestCompactOutcomeUpperBoundUsesAuthoritativeCardinality(t *testing.T) {
	const (
		subscriptions = uint64(3)
		messages      = uint64(2)
	)

	want := uint64(fixedJSONBytes) +
		subscriptions*queueIDJSONBytes +
		subscriptions*messages*messageIDJSONBytes
	got, fits := FitsCompactOutcome(subscriptions, messages, want)
	if !fits || got != want {
		t.Fatalf("FitsCompactOutcome(%d, %d, %d) = %d/%t, want %d/true",
			subscriptions, messages, want, got, fits, want)
	}
}

func TestCompactOutcomeLimitBoundaries(t *testing.T) {
	bound := uint64(fixedJSONBytes) + 3*queueIDJSONBytes + 6*messageIDJSONBytes
	tests := map[string]struct {
		limit uint64
		fits  bool
	}{
		"boundary minus one": {limit: bound - 1, fits: false},
		"exact boundary":     {limit: bound, fits: true},
		"boundary plus one":  {limit: bound + 1, fits: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, fits := FitsCompactOutcome(3, 2, test.limit)
			if got != bound || fits != test.fits {
				t.Fatalf("FitsCompactOutcome(3, 2, %d) = %d/%t, want %d/%t",
					test.limit, got, fits, bound, test.fits)
			}
		})
	}
}

func TestCompactOutcomeUpperBoundRejectsIntegerOverflow(t *testing.T) {
	tests := map[string]struct {
		subscriptions uint64
		messages      uint64
	}{
		"subscription message product": {subscriptions: math.MaxUint64, messages: 2},
		"queue identifier bytes":       {subscriptions: math.MaxUint64, messages: 1},
		"message identifier bytes":     {subscriptions: 1, messages: math.MaxUint64},
		"combined identifier bytes": {
			subscriptions: math.MaxUint64/(queueIDJSONBytes+messageIDJSONBytes) + 1,
			messages:      1,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			bound, fits := FitsCompactOutcome(test.subscriptions, test.messages, math.MaxUint64)
			if fits || bound != math.MaxUint64 {
				t.Fatalf("FitsCompactOutcome(%d, %d, max) = %d/%t, want max/false",
					test.subscriptions, test.messages, bound, fits)
			}
		})
	}
}
