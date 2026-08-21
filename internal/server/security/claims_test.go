package security

import (
	"math"
	"testing"
)

func TestUint64ClaimRejectsLossyAndOutOfRangeValues(t *testing.T) {
	tests := []struct {
		value any
		want  uint64
		ok    bool
	}{
		{value: uint64(7), want: 7, ok: true},
		{value: int64(8), want: 8, ok: true},
		{value: float64(9), want: 9, ok: true},
		{value: -1},
		{value: 1.5},
		{value: math.Inf(1)},
		{value: float64(maxExactJSONInteger + 1)},
		{value: uint64(math.MaxInt64) + 1},
	}

	for _, test := range tests {
		got, ok := Uint64Claim(test.value)
		if got != test.want || ok != test.ok {
			t.Errorf("Uint64Claim(%v) = (%d, %v), want (%d, %v)", test.value, got, ok, test.want, test.ok)
		}
	}
}

func TestAuthVersionInt64RejectsOverflow(t *testing.T) {
	if _, err := AuthVersionInt64(uint64(math.MaxInt64) + 1); err == nil {
		t.Fatal("AuthVersionInt64 accepted an overflowing version")
	}
}

func TestAuthVersionUint64RejectsNegativeValue(t *testing.T) {
	if _, err := AuthVersionUint64(-1); err == nil {
		t.Fatal("AuthVersionUint64 accepted a negative version")
	}
}
