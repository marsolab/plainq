package client

import (
	"context"
	"fmt"
	"time"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	dialTimeout = 10 * time.Second
)

// Option configures the Client structs with Options properties.
type Option func(*Options)

// WithDialTimeout is an Option function that sets the dial timeout duration for the Client.
func WithDialTimeout(t time.Duration) Option {
	return func(o *Options) { o.dialTimeout = t }
}

// Options holds a set of properties to configure Client.
type Options struct {
	dialTimeout  time.Duration
	interceptors []grpc.UnaryClientInterceptor
	userAgent    string
}

// Client represents a gRPC client for plainq server.
type Client struct {
	conn   *grpc.ClientConn
	client v1.PlainQServiceClient
}

// New returns a pointer to a new instance of Client.
func New(addr string, options ...Option) (*Client, error) {
	opts := Options{
		dialTimeout:  dialTimeout,
		interceptors: make([]grpc.UnaryClientInterceptor, 0, 10),
	}

	for _, option := range options {
		option(&opts)
	}

	conn, dialErr := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUserAgent(opts.userAgent),
		grpc.WithChainUnaryInterceptor(opts.interceptors...),
	)
	if dialErr != nil {
		return nil, fmt.Errorf("connect to server: %w", dialErr)
	}

	c := Client{
		conn:   conn,
		client: v1.NewPlainQServiceClient(conn),
	}

	return &c, nil
}

func (c *Client) ListQueues(
	ctx context.Context,
	in *v1.ListQueuesRequest,
	opts ...grpc.CallOption,
) (*v1.ListQueuesResponse, error) {
	resp, err := c.client.ListQueues(ctx, in, opts...)
	if err != nil {
		return nil, fmt.Errorf("list queues: %w", err)
	}

	return resp, nil
}

func (c *Client) DescribeQueue(
	ctx context.Context,
	in *v1.DescribeQueueRequest,
	opts ...grpc.CallOption,
) (*v1.DescribeQueueResponse, error) {
	resp, err := c.client.DescribeQueue(ctx, in, opts...)
	if err != nil {
		return nil, fmt.Errorf("describe queue: %w", err)
	}

	return resp, nil
}

func (c *Client) CreateQueue(
	ctx context.Context,
	in *v1.CreateQueueRequest,
	opts ...grpc.CallOption,
) (*v1.CreateQueueResponse, error) {
	resp, err := c.client.CreateQueue(ctx, in, opts...)
	if err != nil {
		return nil, fmt.Errorf("create queue: %w", err)
	}

	return resp, nil
}

func (c *Client) DeleteQueue(ctx context.Context, in *v1.DeleteQueueRequest, opts ...grpc.CallOption) (*v1.DeleteQueueResponse, error) {
	resp, err := c.client.DeleteQueue(ctx, in, opts...)
	if err != nil {
		return nil, fmt.Errorf("delete queue: %w", err)
	}

	return resp, nil
}

func (c *Client) PurgeQueue(ctx context.Context, in *v1.PurgeQueueRequest, opts ...grpc.CallOption) (*v1.PurgeQueueResponse, error) {
	resp, err := c.client.PurgeQueue(ctx, in, opts...)
	if err != nil {
		return nil, fmt.Errorf("purge queue: %w", err)
	}

	return resp, nil
}

func (c *Client) Send(ctx context.Context, in *v1.SendRequest, opts ...grpc.CallOption) (*v1.SendResponse, error) {
	resp, err := c.client.Send(ctx, in, opts...)
	if err != nil {
		return nil, fmt.Errorf("send messages: %w", err)
	}

	return resp, nil
}

func (c *Client) Receive(ctx context.Context, in *v1.ReceiveRequest, opts ...grpc.CallOption) (*v1.ReceiveResponse, error) {
	resp, err := c.client.Receive(ctx, in, opts...)
	if err != nil {
		return nil, fmt.Errorf("receive messages: %w", err)
	}

	return resp, nil
}

func (c *Client) Delete(ctx context.Context, in *v1.DeleteRequest, opts ...grpc.CallOption) (*v1.DeleteResponse, error) {
	resp, err := c.client.Delete(ctx, in, opts...)
	if err != nil {
		return nil, fmt.Errorf("delete messages: %w", err)
	}

	return resp, nil
}
