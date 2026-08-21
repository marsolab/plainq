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

func TestValidateRejectsValuesAboveGlobalSafetyCaps(t *testing.T) {
	maximum := Default()
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"message bytes", func(c *Config) { c.MaxMessageBytes = maximum.MaxMessageBytes + 1 }},
		{"batch bytes", func(c *Config) { c.MaxBatchBytes = maximum.MaxBatchBytes + 1 }},
		{"attribute bytes", func(c *Config) { c.MaxAttributeBytes = maximum.MaxAttributeBytes + 1 }},
		{"attributes", func(c *Config) { c.MaxAttributes = maximum.MaxAttributes + 1 }},
		{"attribute key bytes", func(c *Config) { c.MaxAttributeKeyBytes = maximum.MaxAttributeKeyBytes + 1 }},
		{"attribute value bytes", func(c *Config) { c.MaxAttributeValueBytes = maximum.MaxAttributeValueBytes + 1 }},
		{"envelope field bytes", func(c *Config) { c.MaxEnvelopeFieldBytes = maximum.MaxEnvelopeFieldBytes + 1 }},
		{"content type bytes", func(c *Config) { c.MaxContentTypeBytes = maximum.MaxContentTypeBytes + 1 }},
		{"send batch", func(c *Config) { c.MaxSendBatch = maximum.MaxSendBatch + 1 }},
		{"receive batch", func(c *Config) { c.MaxReceiveBatch = maximum.MaxReceiveBatch + 1 }},
		{"long poll", func(c *Config) { c.MaxLongPoll = maximum.MaxLongPoll + time.Nanosecond }},
		{"default lease", func(c *Config) { c.DefaultLease = maximum.DefaultLease + time.Nanosecond }},
		{"maximum lease", func(c *Config) { c.MaxLease = maximum.MaxLease + time.Nanosecond }},
		{"maximum nack delay", func(c *Config) { c.MaxNackDelay = maximum.MaxNackDelay + time.Nanosecond }},
		{"maximum retention", func(c *Config) { c.MaxRetention = maximum.MaxRetention + time.Nanosecond }},
		{"inflight", func(c *Config) { c.MaxInflight = maximum.MaxInflight + 1 }},
		{"agents per tenant", func(c *Config) { c.MaxAgentsPerTenant = maximum.MaxAgentsPerTenant + 1 }},
		{"topics per tenant", func(c *Config) { c.MaxTopicsPerTenant = maximum.MaxTopicsPerTenant + 1 }},
		{"subscriptions per agent", func(c *Config) { c.MaxSubscriptionsPerAgent = maximum.MaxSubscriptionsPerAgent + 1 }},
		{"active credentials", func(c *Config) { c.MaxActiveCredentials = maximum.MaxActiveCredentials + 1 }},
		{"pending messages", func(c *Config) { c.MaxPendingMessages = maximum.MaxPendingMessages + 1 }},
		{"pending bytes", func(c *Config) { c.MaxPendingBytes = maximum.MaxPendingBytes + 1 }},
		{"stored bytes per tenant", func(c *Config) { c.MaxStoredBytesPerTenant = maximum.MaxStoredBytesPerTenant + 1 }},
		{"direct attempts", func(c *Config) { c.MaxDirectAttempts = maximum.MaxDirectAttempts + 1 }},
		{"message units per second", func(c *Config) { c.MessageUnitsPerSecond = maximum.MessageUnitsPerSecond + 1 }},
		{"idempotency ttl", func(c *Config) { c.IdempotencyTTL = maximum.IdempotencyTTL + time.Nanosecond }},
		{"direct dead letter retention", func(c *Config) { c.DirectDeadLetterRetention = maximum.DirectDeadLetterRetention + time.Nanosecond }},
		{"security audit retention", func(c *Config) { c.SecurityAuditRetention = maximum.SecurityAuditRetention + time.Nanosecond }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Default()
			tt.mutate(&got)
			if err := got.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want error for value above global cap")
			}
		})
	}
}

func TestValidateAcceptsLowerSafetyCapsWithRequiredRelationships(t *testing.T) {
	got := Default()
	got.MaxMessageBytes /= 2
	got.MaxBatchBytes /= 2
	got.MaxAttributeBytes /= 2
	got.MaxAttributes /= 2
	got.MaxAttributeKeyBytes /= 2
	got.MaxAttributeValueBytes /= 2
	got.MaxEnvelopeFieldBytes /= 2
	got.MaxContentTypeBytes /= 2
	got.MaxSendBatch /= 2
	got.MaxReceiveBatch /= 2
	got.MaxLongPoll /= 2
	got.DefaultLease /= 2
	got.MaxLease /= 2
	got.MaxNackDelay /= 2
	got.MaxRetention /= 2
	got.MaxInflight /= 2
	got.MaxAgentsPerTenant /= 2
	got.MaxTopicsPerTenant /= 2
	got.MaxSubscriptionsPerAgent /= 2
	got.MaxActiveCredentials /= 2
	got.MaxPendingMessages /= 2
	got.MaxPendingBytes /= 2
	got.MaxStoredBytesPerTenant /= 2
	got.MaxDirectAttempts /= 2
	got.MessageUnitsPerSecond /= 2
	got.IdempotencyTTL /= 2
	got.DirectDeadLetterRetention /= 2
	got.SecurityAuditRetention /= 2

	if err := got.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want lowered valid caps to pass", err)
	}
}
