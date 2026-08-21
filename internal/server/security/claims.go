package security

import (
	"errors"
	"math"
)

const maxExactJSONInteger = 1<<53 - 1

// Uint64Claim parses an integer-valued JWT metadata claim without permitting
// negative, fractional, lossy JSON, or database-overflowing values.
//
//nolint:cyclop // Accepted runtime numeric representations are enumerated explicitly.
func Uint64Claim(value any) (uint64, bool) {
	switch number := value.(type) {
	case uint64:
		return boundedUint64(number)
	case uint:
		return boundedUint64(uint64(number))
	case int:
		if number < 0 {
			return 0, false
		}

		return uint64(number), true
	case int64:
		if number < 0 {
			return 0, false
		}

		return uint64(number), true
	case float64:
		if number < 0 || number > maxExactJSONInteger || math.IsNaN(number) || math.IsInf(number, 0) ||
			math.Trunc(number) != number {
			return 0, false
		}

		return uint64(number), true
	default:
		return 0, false
	}
}

func boundedUint64(number uint64) (uint64, bool) {
	if number > math.MaxInt64 {
		return 0, false
	}

	return number, true
}

// AuthVersionInt64 converts the public unsigned version into the signed SQL
// representation, rejecting overflow instead of wrapping it.
func AuthVersionInt64(version uint64) (int64, error) {
	if version > math.MaxInt64 {
		return 0, errors.New("authentication version exceeds database range")
	}

	return int64(version), nil
}

// AuthVersionUint64 converts the signed SQL representation into the public
// unsigned version, rejecting corrupt negative values instead of wrapping.
func AuthVersionUint64(version int64) (uint64, error) {
	if version < 0 {
		return 0, errors.New("authentication version is negative")
	}

	return uint64(version), nil
}
