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
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) ||
		errors.Is(err, pgconn.ErrConnClosed) || pgconn.Timeout(err) || pgconn.SafeToRetry(err) {
		return errors.Join(pqerr.ErrUnavailable, err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return errors.Join(pqerr.ErrUnavailable, err)
	}

	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}
	if strings.HasPrefix(pgErr.Code, "08") || pgErr.Code == "57P01" || pgErr.Code == "57P02" || pgErr.Code == "57P03" {
		return errors.Join(pqerr.ErrUnavailable, err)
	}
	if pgErr.Code == "23505" {
		switch operation {
		case pubSubCreateTopic:
			if pgErr.ConstraintName == "topic_name_uindex" || pgErr.ConstraintName == "topic_id_uindex" || pgErr.ConstraintName == "topic_pk" {
				return errors.Join(pqerr.ErrAlreadyExists, err)
			}
		case pubSubSubscribe:
			if pgErr.ConstraintName == "topic_subscriptions_topic_queue_uindex" || pgErr.ConstraintName == "topic_subscription_pk" {
				return errors.Join(pqerr.ErrAlreadyExists, err)
			}
		}
	}
	if pgErr.Code == "23503" && operation == pubSubSubscribe &&
		(pgErr.ConstraintName == "topic_subscription_topic_fk" || pgErr.ConstraintName == "topic_subscription_queue_fk") {
		return errors.Join(pqerr.ErrNotFound, err)
	}
	return err
}
