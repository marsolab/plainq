package pgstore

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

const (
	// ErrQueueEmpty indicates the requested queue is empty.
	ErrQueueEmpty Error = "queue is empty"
)

// Error represents package-level errors.
type Error string

func (e Error) Error() string { return string(e) }

const (
	fmtBeginTxError = "begin transaction: %w"
)

type pubSubErrorContext string

const (
	pubSubListTopics  pubSubErrorContext = "list_topics"
	pubSubCreateTopic pubSubErrorContext = "create_topic"
	pubSubDeleteQueue pubSubErrorContext = "delete_queue"
	pubSubSubscribe   pubSubErrorContext = "subscribe"
	pubSubDeleteTopic pubSubErrorContext = "delete_topic"
	pubSubUnsubscribe pubSubErrorContext = "unsubscribe"
	pubSubPublish     pubSubErrorContext = "publish"
	pubSubInventory   pubSubErrorContext = "topic_inventory"
)

func normalizePubSubError(err error, operation pubSubErrorContext) error {
	if err == nil {
		return nil
	}

	if isUnavailableError(err) {
		return errors.Join(pqerr.ErrUnavailable, err)
	}

	var pgErr *pgconn.PgError

	if !errors.As(err, &pgErr) {
		return err
	}

	return normalizePostgresError(err, pgErr, operation)
}

func isUnavailableError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}

	if errors.Is(err, pgconn.ErrConnClosed) || pgconn.Timeout(err) || pgconn.SafeToRetry(err) {
		return true
	}

	var netErr net.Error

	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	var temporaryErr interface{ Temporary() bool }

	return errors.As(err, &temporaryErr) && temporaryErr.Temporary()
}

func normalizePostgresError(err error, pgErr *pgconn.PgError, operation pubSubErrorContext) error {
	if strings.HasPrefix(pgErr.Code, "08") || pgErr.Code == "57P01" || pgErr.Code == "57P02" || pgErr.Code == "57P03" {
		return errors.Join(pqerr.ErrUnavailable, err)
	}

	switch pgErr.Code {
	case "40001", "40P01":
		return errors.Join(pqerr.ErrUnavailable, err)
	case "23505":
		return normalizeUniqueViolation(err, pgErr.ConstraintName, operation)
	case "23503":
		return normalizeForeignKeyViolation(err, pgErr.ConstraintName, operation)
	default:
		return err
	}
}

func normalizeUniqueViolation(err error, constraint string, operation pubSubErrorContext) error {
	switch operation {
	case pubSubCreateTopic:
		switch constraint {
		case "topic_name_uindex", "topic_tenant_name_uindex", "topic_id_uindex", "topic_pk":
			return errors.Join(pqerr.ErrAlreadyExists, err)
		}
	case pubSubSubscribe:
		switch constraint {
		case "topic_subscriptions_topic_queue_uindex", "topic_subscription_pk":
			return errors.Join(pqerr.ErrAlreadyExists, err)
		}
	case pubSubListTopics,
		pubSubDeleteQueue,
		pubSubDeleteTopic,
		pubSubUnsubscribe,
		pubSubPublish,
		pubSubInventory:
		return err
	default:
		return err
	}

	return err
}

func normalizeForeignKeyViolation(err error, constraint string, operation pubSubErrorContext) error {
	if operation != pubSubSubscribe {
		return err
	}

	switch constraint {
	case "topic_subscription_topic_fk", "topic_subscription_queue_fk":
		return errors.Join(pqerr.ErrNotFound, err)
	default:
		return err
	}
}
