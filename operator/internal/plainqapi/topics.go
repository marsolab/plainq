package plainqapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// Topic is a topic and its subscriptions as the server describes it.
type Topic struct {
	TopicID       string         `json:"topicId"`
	TopicName     string         `json:"topicName"`
	Subscriptions []Subscription `json:"subscriptions,omitempty"`
}

// Subscription routes a topic's messages into a queue.
type Subscription struct {
	SubscriptionID string `json:"subscriptionId"`
	TopicID        string `json:"topicId"`
	QueueID        string `json:"queueId"`
	QueueName      string `json:"queueName,omitempty"`
}

type listTopicsResponse struct {
	Topics []Topic `json:"topics"`
}

type createTopicResponse struct {
	TopicID string `json:"topicId"`
}

type subscribeResponse struct {
	SubscriptionID string `json:"subscriptionId"`
}

// ListTopics returns every topic on the instance.
//
// Topics exist only on the REST surface — there is no gRPC equivalent — which
// is one of the reasons the operator speaks REST throughout.
func (c *Client) ListTopics(ctx context.Context) ([]Topic, error) {
	var resp listTopicsResponse

	if err := c.do(ctx, request{
		method: http.MethodGet,
		path:   "/api/v1/queue/topics",
		out:    &resp,
	}); err != nil {
		return nil, fmt.Errorf("list topics: %w", err)
	}

	return resp.Topics, nil
}

// ResolveTopicByName finds a topic by name, or returns ErrNotFound.
//
// The list endpoint returns every topic with its subscriptions in one call
// and takes no filter, so this is a full read rather than the paged prefix
// scan queues need.
func (c *Client) ResolveTopicByName(ctx context.Context, name string) (*Topic, error) {
	topics, err := c.ListTopics(ctx)
	if err != nil {
		return nil, err
	}

	for i := range topics {
		if topics[i].TopicName == name {
			return &topics[i], nil
		}
	}

	return nil, fmt.Errorf("%w: topic %q", ErrNotFound, name)
}

// CreateTopic creates a topic and returns its ID.
func (c *Client) CreateTopic(ctx context.Context, name string) (string, error) {
	var resp createTopicResponse

	if err := c.do(ctx, request{
		method: http.MethodPost,
		path:   "/api/v1/queue/topics",
		body:   map[string]string{"topicName": name},
		out:    &resp,
	}); err != nil {
		return "", fmt.Errorf("create topic %q: %w", name, err)
	}

	return resp.TopicID, nil
}

// DeleteTopic removes a topic and its subscriptions.
func (c *Client) DeleteTopic(ctx context.Context, topicID string) error {
	err := c.do(ctx, request{
		method: http.MethodDelete,
		path:   "/api/v1/queue/topics/" + url.PathEscape(topicID),
	})
	if err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("delete topic %q: %w", topicID, err)
	}

	return nil
}

// Subscribe routes a topic's messages into a queue.
func (c *Client) Subscribe(ctx context.Context, topicID, queueID string) (string, error) {
	var resp subscribeResponse

	if err := c.do(ctx, request{
		method: http.MethodPost,
		path:   "/api/v1/queue/topics/" + url.PathEscape(topicID) + "/subscriptions",
		body:   map[string]string{"queueId": queueID},
		out:    &resp,
	}); err != nil {
		return "", fmt.Errorf("subscribe queue %q to topic %q: %w", queueID, topicID, err)
	}

	return resp.SubscriptionID, nil
}

// Unsubscribe removes a subscription.
func (c *Client) Unsubscribe(ctx context.Context, topicID, subscriptionID string) error {
	err := c.do(ctx, request{
		method: http.MethodDelete,
		path: "/api/v1/queue/topics/" + url.PathEscape(topicID) +
			"/subscriptions/" + url.PathEscape(subscriptionID),
	})
	if err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("unsubscribe %q from topic %q: %w", subscriptionID, topicID, err)
	}

	return nil
}
