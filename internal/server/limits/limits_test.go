package limits

import (
	"testing"
	"time"
)

func TestDefaultLimitsAreValid(t *testing.T) {
	got := Default()
	if err := got.Validate(); err != nil {
		t.Fatalf("Default().Validate() error = %v", err)
	}
	if got.MaxMessageBytes != 1<<20 {
		t.Fatalf("MaxMessageBytes = %d, want %d", got.MaxMessageBytes, 1<<20)
	}
	if got.MaxLongPoll != 20*time.Second {
		t.Fatalf("MaxLongPoll = %v, want %v", got.MaxLongPoll, 20*time.Second)
	}
}

func TestValidateRejectsInvalidCoreLimits(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing message bytes", func(c *Config) { c.MaxMessageBytes = 0 }},
		{"batch smaller than message", func(c *Config) { c.MaxBatchBytes = c.MaxMessageBytes - 1 }},
		{"missing send batch", func(c *Config) { c.MaxSendBatch = 0 }},
		{"missing receive batch", func(c *Config) { c.MaxReceiveBatch = 0 }},
		{"missing attribute key bytes", func(c *Config) { c.MaxAttributeKeyBytes = 0 }},
		{"missing default lease", func(c *Config) { c.DefaultLease = 0 }},
		{"maximum lease below default", func(c *Config) { c.MaxLease = c.DefaultLease - time.Nanosecond }},
		{"missing nack delay", func(c *Config) { c.MaxNackDelay = 0 }},
		{"missing retention", func(c *Config) { c.MaxRetention = 0 }},
		{"missing idempotency ttl", func(c *Config) { c.IdempotencyTTL = 0 }},
		{"missing direct dead letter retention", func(c *Config) { c.DirectDeadLetterRetention = 0 }},
		{"missing security audit retention", func(c *Config) { c.SecurityAuditRetention = 0 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Default()
			tt.mutate(&got)
			if err := got.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want error")
			}
		})
	}
}
