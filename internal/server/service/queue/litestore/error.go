package litestore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"

	"github.com/marsolab/plainq/internal/shared/pqerr"
)

const (
	// ErrQueueEmpty shows that requested queue is empty.
	ErrQueueEmpty Error = "queue is empty"
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

	if errors.Is(err, driver.ErrBadConn) || errors.Is(err, sql.ErrConnDone) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return errors.Join(pqerr.ErrUnavailable, err)
	}

	return normalizeSQLiteDriverPubSubError(err, operation)
}

// Error represents package level errors related to the storage engine.
type Error string

func (e Error) Error() string { return string(e) }

const (
	fmtBeginTxError  = "begin transaction: %w"
	fmtCommitTxError = "commit transaction: %w"
)
