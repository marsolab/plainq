package pqtime

import (
	"math"
	"testing"
	"time"
)

func TestFloat64ToTime(t *testing.T) {
	tests := map[string]struct {
		ts   float64
		want time.Time
	}{
		"Zero":     {0.0, time.Unix(0, 0)},
		"Int":      {1.0, time.Unix(1, 0)},
		"Fraction": {1.5, time.Unix(1, 500000000)},
		"Large":    {1e11, time.Unix(100000000000, 0)},
		"Negative": {-1.0, time.Unix(-1, 0)},
		"MaxInt":   {float64(1<<31 - 1), time.Unix(1<<31-1, 0)},
	}

	t.Parallel()

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := Float64ToTime(tc.ts); !got.Equal(tc.want) {
				t.Errorf("Float64ToTime() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTimeToFloat64(t *testing.T) {
	tests := map[string]struct {
		ts   time.Time
		want float64
	}{
		"MidnightEpoch":       {ts: time.Unix(0, 0), want: 0},
		"HalfPastEpoch":       {ts: time.Unix(0, 500000000), want: 0.5},
		"OneSecondAfterEpoch": {ts: time.Unix(1, 0), want: 1.0},
		"NegativeOneSecond":   {ts: time.Unix(-1, 0), want: -1.0},
		"MaxUnixTimeWithNanoseconds": {
			ts: time.Unix(math.MaxInt64, 999999999), want: float64(math.MaxInt64) + 0.999999999,
		},
	}

	t.Parallel()

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := TimeToFloat64(tc.ts); got != tc.want {
				t.Errorf("TimeToFloat64() = %v, want %v", got, tc.want)
			}
		})
	}
}
