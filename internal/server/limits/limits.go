package limits

import (
	"errors"
	"time"
)

type Config struct {
	MaxMessageBytes           int
	MaxBatchBytes             int
	MaxAttributeBytes         int
	MaxAttributes             int
	MaxAttributeKeyBytes      int
	MaxAttributeValueBytes    int
	MaxEnvelopeFieldBytes     int
	MaxContentTypeBytes       int
	MaxSendBatch              int
	MaxReceiveBatch           int
	MaxLongPoll               time.Duration
	DefaultLease              time.Duration
	MaxLease                  time.Duration
	MaxNackDelay              time.Duration
	MaxRetention              time.Duration
	MaxInflight               int
	MaxAgentsPerTenant        int
	MaxTopicsPerTenant        int
	MaxSubscriptionsPerAgent  int
	MaxActiveCredentials      int
	MaxPendingMessages        int
	MaxPendingBytes           int64
	MaxStoredBytesPerTenant   int64
	MaxDirectAttempts         int
	MessageUnitsPerSecond     int
	IdempotencyTTL            time.Duration
	DirectDeadLetterRetention time.Duration
	SecurityAuditRetention    time.Duration
}

func Default() Config {
	return Config{
		MaxMessageBytes: 1 << 20, MaxBatchBytes: 4 << 20,
		MaxAttributeBytes: 16 << 10, MaxAttributes: 64,
		MaxAttributeKeyBytes: 128, MaxAttributeValueBytes: 1 << 10,
		MaxEnvelopeFieldBytes: 128, MaxContentTypeBytes: 255,
		MaxSendBatch: 100, MaxReceiveBatch: 100, MaxLongPoll: 20 * time.Second,
		DefaultLease: 30 * time.Second, MaxLease: 12 * time.Hour,
		MaxNackDelay: 24 * time.Hour, MaxRetention: 30 * 24 * time.Hour, MaxInflight: 1000,
		MaxAgentsPerTenant: 10_000, MaxTopicsPerTenant: 1000,
		MaxSubscriptionsPerAgent: 1000, MaxActiveCredentials: 2,
		MaxPendingMessages: 100_000, MaxPendingBytes: 1 << 30,
		MaxStoredBytesPerTenant: 10 << 30, MaxDirectAttempts: 10,
		MessageUnitsPerSecond: 1000, IdempotencyTTL: 24 * time.Hour,
		DirectDeadLetterRetention: 30 * 24 * time.Hour,
		SecurityAuditRetention:    90 * 24 * time.Hour,
	}
}

//nolint:cyclop,gocyclo // Validation mirrors the explicit hard-limit contract field by field.
func (c Config) Validate() error {
	if c.MaxMessageBytes < 1 || c.MaxBatchBytes < c.MaxMessageBytes ||
		c.MaxSendBatch < 1 || c.MaxReceiveBatch < 1 || c.MaxAttributeKeyBytes < 1 ||
		c.DefaultLease <= 0 || c.MaxLease < c.DefaultLease || c.MaxNackDelay <= 0 ||
		c.MaxRetention <= 0 || c.IdempotencyTTL <= 0 ||
		c.DirectDeadLetterRetention <= 0 || c.SecurityAuditRetention <= 0 {
		return errors.New("agent messaging limits must be positive and max lease must cover default lease")
	}

	maximum := Default()
	if c.MaxMessageBytes > maximum.MaxMessageBytes ||
		c.MaxBatchBytes > maximum.MaxBatchBytes ||
		c.MaxAttributeBytes > maximum.MaxAttributeBytes ||
		c.MaxAttributes > maximum.MaxAttributes ||
		c.MaxAttributeKeyBytes > maximum.MaxAttributeKeyBytes ||
		c.MaxAttributeValueBytes > maximum.MaxAttributeValueBytes ||
		c.MaxEnvelopeFieldBytes > maximum.MaxEnvelopeFieldBytes ||
		c.MaxContentTypeBytes > maximum.MaxContentTypeBytes ||
		c.MaxSendBatch > maximum.MaxSendBatch ||
		c.MaxReceiveBatch > maximum.MaxReceiveBatch ||
		c.MaxLongPoll > maximum.MaxLongPoll ||
		c.DefaultLease > maximum.DefaultLease ||
		c.MaxLease > maximum.MaxLease ||
		c.MaxNackDelay > maximum.MaxNackDelay ||
		c.MaxRetention > maximum.MaxRetention ||
		c.MaxInflight > maximum.MaxInflight ||
		c.MaxAgentsPerTenant > maximum.MaxAgentsPerTenant ||
		c.MaxTopicsPerTenant > maximum.MaxTopicsPerTenant ||
		c.MaxSubscriptionsPerAgent > maximum.MaxSubscriptionsPerAgent ||
		c.MaxActiveCredentials > maximum.MaxActiveCredentials ||
		c.MaxPendingMessages > maximum.MaxPendingMessages ||
		c.MaxPendingBytes > maximum.MaxPendingBytes ||
		c.MaxStoredBytesPerTenant > maximum.MaxStoredBytesPerTenant ||
		c.MaxDirectAttempts > maximum.MaxDirectAttempts ||
		c.MessageUnitsPerSecond > maximum.MessageUnitsPerSecond ||
		c.IdempotencyTTL > maximum.IdempotencyTTL ||
		c.DirectDeadLetterRetention > maximum.DirectDeadLetterRetention ||
		c.SecurityAuditRetention > maximum.SecurityAuditRetention {
		return errors.New("agent messaging limits exceed global safety caps")
	}

	return nil
}
