package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"google.golang.org/grpc"
)

const (
	// requestTimeout bounds every gRPC call made from the TUI.
	requestTimeout = 10 * time.Second

	// queueListLimit is the page size used when listing queues.
	queueListLimit = 100

	// defaultBatchSize is how many messages a receive action pulls.
	defaultBatchSize = 10
)

// Client is the subset of the PlainQ gRPC client used by the TUI. Keeping it
// small makes the model easy to drive from tests with a fake.
type Client interface {
	ListQueues(ctx context.Context, in *v1.ListQueuesRequest, opts ...grpc.CallOption) (*v1.ListQueuesResponse, error)
	DescribeQueue(ctx context.Context, in *v1.DescribeQueueRequest, opts ...grpc.CallOption) (*v1.DescribeQueueResponse, error)
	Receive(ctx context.Context, in *v1.ReceiveRequest, opts ...grpc.CallOption) (*v1.ReceiveResponse, error)
	Send(ctx context.Context, in *v1.SendRequest, opts ...grpc.CallOption) (*v1.SendResponse, error)
	PurgeQueue(ctx context.Context, in *v1.PurgeQueueRequest, opts ...grpc.CallOption) (*v1.PurgeQueueResponse, error)
	DeleteQueue(ctx context.Context, in *v1.DeleteQueueRequest, opts ...grpc.CallOption) (*v1.DeleteQueueResponse, error)
}

// Messages exchanged through the Bubble Tea runtime.
type (
	queuesLoadedMsg     struct{ queues []*v1.DescribeQueueResponse }
	messagesReceivedMsg struct{ messages []*v1.ReceiveMessage }
	sentMsg             struct{ ids []string }
	purgedMsg           struct{ count uint64 }
	deletedMsg          struct{ id string }
	errMsg              struct{ err error }
)

// listQueuesCmd loads the queue list.
func listQueuesCmd(client Client) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		defer cancel()

		resp, err := client.ListQueues(ctx, &v1.ListQueuesRequest{Limit: queueListLimit})
		if err != nil {
			return errMsg{err: fmt.Errorf("list queues: %w", err)}
		}

		return queuesLoadedMsg{queues: resp.GetQueues()}
	}
}

// receiveCmd pulls a batch of messages from the queue.
func receiveCmd(client Client, queueID string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		defer cancel()

		resp, err := client.Receive(ctx, &v1.ReceiveRequest{QueueId: queueID, BatchSize: defaultBatchSize})
		if err != nil {
			return errMsg{err: fmt.Errorf("receive messages: %w", err)}
		}

		return messagesReceivedMsg{messages: resp.GetMessages()}
	}
}

// sendCmd sends a single message body to the queue.
func sendCmd(client Client, queueID, body string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		defer cancel()

		in := &v1.SendRequest{QueueId: queueID, Messages: []*v1.SendMessage{{Body: []byte(body)}}}

		resp, err := client.Send(ctx, in)
		if err != nil {
			return errMsg{err: fmt.Errorf("send message: %w", err)}
		}

		return sentMsg{ids: resp.GetMessageIds()}
	}
}

// purgeCmd removes every message from the queue.
func purgeCmd(client Client, queueID string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		defer cancel()

		resp, err := client.PurgeQueue(ctx, &v1.PurgeQueueRequest{QueueId: queueID})
		if err != nil {
			return errMsg{err: fmt.Errorf("purge queue: %w", err)}
		}

		return purgedMsg{count: resp.GetMessagesCount()}
	}
}

// deleteQueueCmd deletes the queue.
func deleteQueueCmd(client Client, queueID string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		defer cancel()

		if _, err := client.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID, Force: true}); err != nil {
			return errMsg{err: fmt.Errorf("delete queue: %w", err)}
		}

		return deletedMsg{id: queueID}
	}
}
