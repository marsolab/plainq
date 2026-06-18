package pqtime

import (
	"time"
)

const (
	// nanosecondsPerSecond represents the number of nanoseconds in a second.
	nanosecondsPerSecond = 1e9
)

// Float64ToTime converts a float64 value representing a timestamp into a time.Time value.
// The resulting time.Time value represents the timestamp with nanosecond precision.
func Float64ToTime(f float64) time.Time {
	sec := int64(f)
	nano := int64((f - float64(sec)) * nanosecondsPerSecond)

	return time.Unix(sec, nano)
}

// TimeToFloat64 converts a time.Time value into a float64 representation of the timestamp.
// It combines the seconds (Unix epoch time) with the nanoseconds of the supplied time value.
// The resulting float64 value represents the timestamp with nanosecond precision.
func TimeToFloat64(t time.Time) float64 {
	sec, nano := t.Unix(), t.Nanosecond()

	return float64(sec) + float64(nano)/nanosecondsPerSecond
}
