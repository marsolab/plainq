package litestore

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

// PreviewDeleteTopic returns the exact deterministically ordered effects of a
// topic delete from one read snapshot without changing replicated storage.
func (s *Storage) PreviewDeleteTopic(ctx context.Context, topicID string) (*queue.DeleteTopicResult, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin topic delete preview: %w", normalizePubSubError(err, pubSubDeleteTopic))
	}
	defer func() { _ = tx.Rollback() }()

	topicExists, err := exists(ctx, tx, `SELECT EXISTS(SELECT 1 FROM topic_properties WHERE topic_id = ?);`, topicID)
	if err != nil {
		return nil, fmt.Errorf("check topic delete preview: %w", normalizePubSubError(err, pubSubDeleteTopic))
	}
	if !topicExists {
		return nil, fmt.Errorf("preview topic delete: %w", pqerr.ErrNotFound)
	}

	removed, err := listSubscriptions(ctx, tx, topicID, pubSubDeleteTopic)
	if err != nil {
		return nil, fmt.Errorf("preview topic delete subscriptions: %w", err)
	}

	return &queue.DeleteTopicResult{RemovedSubscriptions: removed}, nil
}

// PreviewDeleteQueue returns the exact deterministically ordered effects of a
// queue delete from one read snapshot without changing replicated storage.
func (s *Storage) PreviewDeleteQueue(ctx context.Context, queueID string) (*queue.DeleteQueueResult, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin queue delete preview: %w", normalizePubSubError(err, pubSubDeleteQueue))
	}
	defer func() { _ = tx.Rollback() }()

	queueExists, err := exists(ctx, tx, `SELECT EXISTS(SELECT 1 FROM queue_properties WHERE queue_id = ?);`, queueID)
	if err != nil {
		return nil, fmt.Errorf("check queue delete preview: %w", normalizePubSubError(err, pubSubDeleteQueue))
	}
	if !queueExists {
		return nil, fmt.Errorf("preview queue delete: %w", pqerr.ErrNotFound)
	}

	removed, err := listSubscriptionsByQueue(ctx, tx, queueID)
	if err != nil {
		return nil, fmt.Errorf("preview queue delete subscriptions: %w", err)
	}

	return &queue.DeleteQueueResult{RemovedSubscriptions: removed}, nil
}
