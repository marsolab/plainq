package plainqapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// EvictionPolicy values as the wire protocol spells them.
const (
	EvictionPolicyUnspecified = "EVICTION_POLICY_UNSPECIFIED"
	EvictionPolicyDrop        = "EVICTION_POLICY_DROP"
	EvictionPolicyDeadLetter  = "EVICTION_POLICY_DEAD_LETTER"
	EvictionPolicyReorder     = "EVICTION_POLICY_REORDER"
)

// Queue is a queue as the server describes it. Field names follow the
// protobuf JSON mapping the REST handlers emit.
type Queue struct {
	QueueID                  string `json:"queueId"`
	QueueName                string `json:"queueName"`
	RetentionPeriodSeconds   uint64 `json:"retentionPeriodSeconds,omitempty"`
	VisibilityTimeoutSeconds uint64 `json:"visibilityTimeoutSeconds,omitempty"`
	MaxReceiveAttempts       uint32 `json:"maxReceiveAttempts,omitempty"`
	EvictionPolicy           string `json:"evictionPolicy,omitempty"`
	DeadLetterQueueID        string `json:"deadLetterQueueId,omitempty"`
}

// CreateQueueRequest creates a queue.
type CreateQueueRequest struct {
	QueueName                string `json:"queueName"`
	RetentionPeriodSeconds   uint64 `json:"retentionPeriodSeconds,omitempty"`
	VisibilityTimeoutSeconds uint64 `json:"visibilityTimeoutSeconds,omitempty"`
	MaxReceiveAttempts       uint32 `json:"maxReceiveAttempts,omitempty"`
	EvictionPolicy           string `json:"evictionPolicy,omitempty"`
	DeadLetterQueueID        string `json:"deadLetterQueueId,omitempty"`
}

// createQueueResponse carries the assigned ID.
type createQueueResponse struct {
	QueueID string `json:"queueId"`
}

// listQueuesResponse is one page of queues.
type listQueuesResponse struct {
	Queues     []Queue `json:"queues"`
	NextCursor string  `json:"nextCursor"`
	HasMore    bool    `json:"hasMore"`
	TotalCount int64   `json:"totalCount"`
}

// purgeQueueResponse reports how many messages were removed.
type purgeQueueResponse struct {
	MessagesCount uint64 `json:"messagesCount"`
}

// listPageSize is how many queues a resolution scan reads at a time. The
// server caps limit at 100.
const listPageSize = 100

// CreateQueue creates a queue and returns its server-assigned ID.
func (c *Client) CreateQueue(ctx context.Context, req CreateQueueRequest) (string, error) {
	var resp createQueueResponse

	if err := c.do(ctx, request{
		method: http.MethodPost,
		path:   "/api/v1/queue",
		body:   req,
		out:    &resp,
	}); err != nil {
		return "", fmt.Errorf("create queue %q: %w", req.QueueName, err)
	}

	return resp.QueueID, nil
}

// DescribeQueue fetches a queue by its server-assigned ID.
func (c *Client) DescribeQueue(ctx context.Context, queueID string) (*Queue, error) {
	var queue Queue

	if err := c.do(ctx, request{
		method: http.MethodGet,
		path:   "/api/v1/queue/" + url.PathEscape(queueID),
		out:    &queue,
	}); err != nil {
		return nil, fmt.Errorf("describe queue %q: %w", queueID, err)
	}

	return &queue, nil
}

// ResolveQueueByName finds a queue by name and returns it, or ErrNotFound.
//
// The REST surface has no name lookup: GET /api/v1/queue/{id} validates its
// path parameter as an ID and only ever builds DescribeQueueRequest{QueueId}.
// The protobuf message has a queue_name field, but no route sets it. So a
// REST-only client scans the list endpoint, narrowed by the prefix filter it
// does support, and matches the name exactly.
//
// Callers cache the resulting ID so this runs once per queue rather than once
// per reconcile.
func (c *Client) ResolveQueueByName(ctx context.Context, name string) (*Queue, error) {
	cursor := ""

	for {
		page, err := c.listQueues(ctx, name, cursor)
		if err != nil {
			return nil, fmt.Errorf("resolve queue %q: %w", name, err)
		}

		for i := range page.Queues {
			// The filter is a prefix, so "orders" also returns
			// "orders-dlq". Only an exact match is this queue.
			if page.Queues[i].QueueName == name {
				return &page.Queues[i], nil
			}
		}

		if !page.HasMore || page.NextCursor == "" || page.NextCursor == cursor {
			return nil, fmt.Errorf("%w: queue %q", ErrNotFound, name)
		}

		cursor = page.NextCursor
	}
}

// ListQueues returns every queue whose name starts with prefix. An empty
// prefix returns all of them.
func (c *Client) ListQueues(ctx context.Context, prefix string) ([]Queue, error) {
	var (
		all    []Queue
		cursor string
	)

	for {
		page, err := c.listQueues(ctx, prefix, cursor)
		if err != nil {
			return nil, err
		}

		all = append(all, page.Queues...)

		if !page.HasMore || page.NextCursor == "" || page.NextCursor == cursor {
			return all, nil
		}

		cursor = page.NextCursor
	}
}

func (c *Client) listQueues(ctx context.Context, prefix, cursor string) (*listQueuesResponse, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(listPageSize))

	if prefix != "" {
		query.Set("prefix", prefix)
	}

	if cursor != "" {
		query.Set("cursor", cursor)
	}

	var resp listQueuesResponse

	if err := c.do(ctx, request{
		method: http.MethodGet,
		path:   "/api/v1/queue",
		query:  query,
		out:    &resp,
	}); err != nil {
		return nil, fmt.Errorf("list queues: %w", err)
	}

	return &resp, nil
}

// DeleteQueue removes a queue and everything in it.
func (c *Client) DeleteQueue(ctx context.Context, queueID string) error {
	err := c.do(ctx, request{
		method: http.MethodDelete,
		path:   "/api/v1/queue/" + url.PathEscape(queueID),
	})
	if err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("delete queue %q: %w", queueID, err)
	}

	return nil
}

// PurgeQueue removes every message from a queue and reports how many went.
func (c *Client) PurgeQueue(ctx context.Context, queueID string) (uint64, error) {
	var resp purgeQueueResponse

	if err := c.do(ctx, request{
		method: http.MethodPost,
		path:   "/api/v1/queue/" + url.PathEscape(queueID) + "/purge",
		out:    &resp,
	}); err != nil {
		return 0, fmt.Errorf("purge queue %q: %w", queueID, err)
	}

	return resp.MessagesCount, nil
}

// QueueMessageCount reports how many messages a queue currently holds. It is
// used to refuse a destructive delete of a queue that is not empty.
func (c *Client) QueueMessageCount(ctx context.Context, queueID string) (int, error) {
	var resp struct {
		Messages []struct {
			ID string `json:"id"`
		} `json:"messages"`
	}

	query := url.Values{}
	query.Set("limit", "1")

	if err := c.do(ctx, request{
		method: http.MethodGet,
		path:   "/api/v1/queue/" + url.PathEscape(queueID) + "/messages",
		query:  query,
		out:    &resp,
	}); err != nil {
		return 0, fmt.Errorf("peek queue %q: %w", queueID, err)
	}

	return len(resp.Messages), nil
}
