package security

import (
	"testing"
	"time"
)

func TestKeyedLimiterEnforcesEveryKeyWithoutPartialConsumption(t *testing.T) {
	now := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	limiter, err := NewKeyedLimiter(1, 1, 8)
	if err != nil {
		t.Fatalf("NewKeyedLimiter() error = %v", err)
	}
	limiter.clock = func() time.Time { return now }

	if !limiter.Allow("ip:a", "account:a") {
		t.Fatal("first request was rejected")
	}
	if limiter.Allow("ip:b", "account:a") {
		t.Fatal("exhausted account bucket was admitted from another IP")
	}
	if !limiter.Allow("ip:b", "account:b") {
		t.Fatal("denied multi-key request partially consumed the unrelated IP bucket")
	}

	now = now.Add(time.Second)
	if !limiter.Allow("ip:a", "account:a") {
		t.Fatal("refilled request was rejected")
	}
}
