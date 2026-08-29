package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/heartwilltell/scotty"
	"github.com/marsolab/plainq/internal/client"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/servekit/idkit"
	"google.golang.org/grpc"
)

const (
	argTopicID        = "topic-id"
	argSubscriptionID = "subscription-id"
	topicListName     = "list"
	topicListCommand  = "plainq topic list"

	descTopicID        = `topic identifier printed by "plainq topic create" or "plainq topic list" (20 characters)`
	descSubscriptionID = `subscription identifier printed by "plainq topic subscribe" ` +
		`or embedded in "plainq topic list -json" (20 characters)`
)

// topicClient is the RPC surface needed by the six topic CLI leaves.
type topicClient interface {
	ListTopics(ctx context.Context, in *v1.ListTopicsRequest, opts ...grpc.CallOption) (*v1.ListTopicsResponse, error)
	CreateTopic(ctx context.Context, in *v1.CreateTopicRequest, opts ...grpc.CallOption) (*v1.CreateTopicResponse, error)
	DeleteTopic(ctx context.Context, in *v1.DeleteTopicRequest, opts ...grpc.CallOption) (*v1.DeleteTopicResponse, error)
	Subscribe(ctx context.Context, in *v1.SubscribeRequest, opts ...grpc.CallOption) (*v1.SubscribeResponse, error)
	Unsubscribe(ctx context.Context, in *v1.UnsubscribeRequest, opts ...grpc.CallOption) (*v1.UnsubscribeResponse, error)
	Publish(ctx context.Context, in *v1.PublishRequest, opts ...grpc.CallOption) (*v1.PublishResponse, error)
}

type topicCommandDeps struct {
	open   func(context.Context, string) (topicClient, io.Closer, error)
	stdin  io.Reader
	stdout io.Writer
}

func topicCommand() *commandSpec {
	return newTopicCommand(topicCommandDeps{
		open: func(_ context.Context, addr string) (topicClient, io.Closer, error) {
			cli, err := client.New(addr)
			if err != nil {
				return nil, nil, fmt.Errorf("open topic client: %w", err)
			}

			return cli, cli, nil
		},
		stdin:  os.Stdin,
		stdout: os.Stdout,
	})
}

func newTopicCommand(deps topicCommandDeps) *commandSpec {
	return &commandSpec{
		Name:   "topic",
		Short:  "Publish to topics and manage subscriptions",
		Effect: effectReadOnly,
		Long: "Creates and lists topics, connects queues as subscribers, and publishes a\n" +
			"batch to every subscribed queue. Topic delivery is synchronous and best-effort;\n" +
			"a failed publish may already have retained copies in some queues.",
		Subcommands: []*commandSpec{
			newTopicListCommand(deps),
			newTopicCreateCommand(deps),
			newTopicDeleteCommand(deps),
			newTopicSubscribeCommand(deps),
			newTopicUnsubscribeCommand(deps),
			newTopicPublishCommand(deps),
		},
	}
}

type topicFlags struct {
	addr    string
	jsonOut bool
}

func (f *topicFlags) register(flags *scotty.FlagSet) {
	flags.StringVar(&f.addr, flagGRPCAddr, resolveGRPCAddr(), flagGRPCAddrUsage)
	flags.BoolVar(&f.jsonOut, flagJSON, false, flagJSONUsage)
}

func newTopicListCommand(deps topicCommandDeps) *commandSpec {
	var flags topicFlags

	return &commandSpec{
		Name:   topicListName,
		Short:  "List topics",
		Effect: effectReadOnly,
		Long: "Lists every topic as one \"<topic-id> | <topic-name>\" line. Use -json to\n" +
			"include each topic's complete subscription objects and timestamps.",
		Examples: []exampleSpec{
			{Description: "List every topic.", Command: topicListCommand},
			{
				Description: "Read topic and subscription identifiers programmatically.",
				Command:     "plainq topic list -json | jq '.topics[] | {topicId, subscriptions}'",
			},
		},
		SetFlags: flags.register,
		Run: func(_ *scotty.Command, args []string) (err error) {
			if arityErr := requireTopicArity(topicListName, args, 0); arityErr != nil {
				return arityErr
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			cli, closer, openErr := deps.open(ctx, flags.addr)
			if openErr != nil {
				return fmt.Errorf(fmtCreateClientError, openErr)
			}
			defer func() {
				if closeErr := closer.Close(); closeErr != nil {
					err = errors.Join(err, fmt.Errorf("close topic client: %w", closeErr))
				}
			}()

			response, rpcErr := cli.ListTopics(ctx, &v1.ListTopicsRequest{})
			if rpcErr != nil {
				return grpcErrorWithListHint(flags.addr, "list topics", topicListCommand, rpcErr)
			}

			if flags.jsonOut {
				return encodeJSON(deps.stdout, response)
			}

			for _, topic := range response.GetTopics() {
				if _, writeErr := fmt.Fprintf(
					deps.stdout,
					"%s | %s\n",
					topic.GetTopicId(),
					topic.GetTopicName(),
				); writeErr != nil {
					return fmt.Errorf("write topic list: %w", writeErr)
				}
			}

			return nil
		},
	}
}

func newTopicCreateCommand(deps topicCommandDeps) *commandSpec {
	var flags topicFlags

	return &commandSpec{
		Name:   "create",
		Short:  "Create a topic",
		Effect: effectMutating,
		Long: "Creates a topic and prints its identifier. Topic names are human-readable and\n" +
			"must be unique; later commands address the topic by the returned id.",
		Args: []argSpec{{
			Name:        "topic-name",
			Description: "nonblank human-readable name for the topic",
			Required:    true,
		}},
		Examples: []exampleSpec{{
			Description: "Create a topic and keep its id.",
			Command:     "TID=$(plainq topic create order-events)",
		}},
		SetFlags: flags.register,
		Run: func(_ *scotty.Command, args []string) (err error) {
			if arityErr := requireTopicArity("create", args, 1); arityErr != nil {
				return arityErr
			}

			if strings.TrimSpace(args[0]) == "" {
				return usagef("topic name must not be blank")
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			cli, closer, openErr := deps.open(ctx, flags.addr)
			if openErr != nil {
				return fmt.Errorf(fmtCreateClientError, openErr)
			}
			defer func() {
				if closeErr := closer.Close(); closeErr != nil {
					err = errors.Join(err, fmt.Errorf("close topic client: %w", closeErr))
				}
			}()

			response, rpcErr := cli.CreateTopic(ctx, &v1.CreateTopicRequest{TopicName: args[0]})
			if rpcErr != nil {
				return grpcErrorWithListHint(flags.addr, "create topic", topicListCommand, rpcErr)
			}

			if flags.jsonOut {
				return encodeJSON(deps.stdout, response)
			}

			if _, writeErr := fmt.Fprintln(deps.stdout, response.GetTopicId()); writeErr != nil {
				return fmt.Errorf("write created topic: %w", writeErr)
			}

			return nil
		},
	}
}

func newTopicDeleteCommand(deps topicCommandDeps) *commandSpec {
	var flags topicFlags

	return &commandSpec{
		Name:   commandDelete,
		Short:  "Delete a topic and all subscriptions",
		Effect: effectDestructive,
		Long: "Deletes the topic and every subscription attached to it. Queues and messages\n" +
			"already delivered to them remain; there is no confirmation prompt or undo.",
		Args: []argSpec{{Name: argTopicID, Description: descTopicID, Required: true}},
		Examples: []exampleSpec{{
			Description: "Delete a topic.",
			Command:     "plainq topic delete " + exampleQueueID,
		}},
		SetFlags: flags.register,
		Run: func(_ *scotty.Command, args []string) (err error) {
			if arityErr := requireTopicArity(commandDelete, args, 1); arityErr != nil {
				return arityErr
			}

			topicID, idErr := validateTopicCLIIdentifier("topic", args[0])
			if idErr != nil {
				return idErr
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			cli, closer, openErr := deps.open(ctx, flags.addr)
			if openErr != nil {
				return fmt.Errorf(fmtCreateClientError, openErr)
			}
			defer func() {
				if closeErr := closer.Close(); closeErr != nil {
					err = errors.Join(err, fmt.Errorf("close topic client: %w", closeErr))
				}
			}()

			response, rpcErr := cli.DeleteTopic(ctx, &v1.DeleteTopicRequest{TopicId: topicID})
			if rpcErr != nil {
				return grpcErrorWithListHint(
					flags.addr,
					fmt.Sprintf("delete topic %q", topicID),
					topicListCommand,
					rpcErr,
				)
			}

			if flags.jsonOut {
				return encodeJSON(deps.stdout, response)
			}

			if _, writeErr := fmt.Fprintf(deps.stdout, "deleted\t%s\n", topicID); writeErr != nil {
				return fmt.Errorf("write deleted topic: %w", writeErr)
			}

			return nil
		},
	}
}

func newTopicSubscribeCommand(deps topicCommandDeps) *commandSpec {
	var flags topicFlags

	return &commandSpec{
		Name:   "subscribe",
		Short:  "Subscribe a queue to a topic",
		Effect: effectMutating,
		Long: "Creates a subscription so each later publish fans its complete batch out to\n" +
			"the queue. Prints the subscription id needed to unsubscribe.",
		Args: []argSpec{
			{Name: argTopicID, Description: descTopicID, Required: true},
			{Name: argQueueID, Description: descQueueID, Required: true},
		},
		Examples: []exampleSpec{{
			Description: "Subscribe a queue and keep the subscription id.",
			Command:     "SID=$(plainq topic subscribe " + exampleQueueID + " " + exampleQueueID + ")",
		}},
		SetFlags: flags.register,
		Run: func(_ *scotty.Command, args []string) (err error) {
			if arityErr := requireTopicArity("subscribe", args, 2); arityErr != nil {
				return arityErr
			}

			topicID, topicErr := validateTopicCLIIdentifier("topic", args[0])
			if topicErr != nil {
				return topicErr
			}

			if queueErr := validateQueueID(args[1]); queueErr != nil {
				return queueErr
			}

			queueID := args[1]

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			cli, closer, openErr := deps.open(ctx, flags.addr)
			if openErr != nil {
				return fmt.Errorf(fmtCreateClientError, openErr)
			}
			defer func() {
				if closeErr := closer.Close(); closeErr != nil {
					err = errors.Join(err, fmt.Errorf("close topic client: %w", closeErr))
				}
			}()

			response, rpcErr := cli.Subscribe(ctx, &v1.SubscribeRequest{TopicId: topicID, QueueId: queueID})
			if rpcErr != nil {
				return grpcErrorWithListHint(
					flags.addr,
					fmt.Sprintf("subscribe queue %q to topic %q", queueID, topicID),
					topicListCommand,
					rpcErr,
				)
			}

			if flags.jsonOut {
				return encodeJSON(deps.stdout, response)
			}

			if _, writeErr := fmt.Fprintln(deps.stdout, response.GetSubscriptionId()); writeErr != nil {
				return fmt.Errorf("write created subscription: %w", writeErr)
			}

			return nil
		},
	}
}

func newTopicUnsubscribeCommand(deps topicCommandDeps) *commandSpec {
	var flags topicFlags

	return &commandSpec{
		Name:   "unsubscribe",
		Short:  "Remove a topic subscription",
		Effect: effectDestructive,
		Long: "Stops future publishes from being delivered through this subscription. Messages\n" +
			"already placed in the queue remain available to receive and acknowledge.",
		Args: []argSpec{
			{Name: argTopicID, Description: descTopicID, Required: true},
			{Name: argSubscriptionID, Description: descSubscriptionID, Required: true},
		},
		Examples: []exampleSpec{{
			Description: "Remove one subscription.",
			Command:     "plainq topic unsubscribe " + exampleQueueID + " " + exampleQueueID,
		}},
		SetFlags: flags.register,
		Run: func(_ *scotty.Command, args []string) (err error) {
			if arityErr := requireTopicArity("unsubscribe", args, 2); arityErr != nil {
				return arityErr
			}

			topicID, topicErr := validateTopicCLIIdentifier("topic", args[0])
			if topicErr != nil {
				return topicErr
			}

			subscriptionID, subscriptionErr := validateTopicCLIIdentifier("subscription", args[1])
			if subscriptionErr != nil {
				return subscriptionErr
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			cli, closer, openErr := deps.open(ctx, flags.addr)
			if openErr != nil {
				return fmt.Errorf(fmtCreateClientError, openErr)
			}
			defer func() {
				if closeErr := closer.Close(); closeErr != nil {
					err = errors.Join(err, fmt.Errorf("close topic client: %w", closeErr))
				}
			}()

			response, rpcErr := cli.Unsubscribe(ctx, &v1.UnsubscribeRequest{
				TopicId:        topicID,
				SubscriptionId: subscriptionID,
			})
			if rpcErr != nil {
				return grpcErrorWithListHint(
					flags.addr,
					fmt.Sprintf("unsubscribe %q from topic %q", subscriptionID, topicID),
					topicListCommand,
					rpcErr,
				)
			}

			if flags.jsonOut {
				return encodeJSON(deps.stdout, response)
			}

			if _, writeErr := fmt.Fprintf(deps.stdout, "unsubscribed\t%s\n", subscriptionID); writeErr != nil {
				return fmt.Errorf("write removed subscription: %w", writeErr)
			}

			return nil
		},
	}
}

type topicPublishFlags struct {
	topicFlags
	messages stringSliceFlag
	file     string
}

func (f *topicPublishFlags) register(flags *scotty.FlagSet) {
	f.topicFlags.register(flags)
	flags.Var(&f.messages, "message", "message body to publish")
	flags.StringVar(
		&f.file,
		"file",
		"",
		`read newline-delimited message bodies from this path ("-" reads standard input)`,
	)
}

func newTopicPublishCommand(deps topicCommandDeps) *commandSpec {
	var flags topicPublishFlags

	return &commandSpec{
		Name:   "publish",
		Short:  "Publish messages to every subscribed queue",
		Effect: effectMutating,
		Long: "Publishes one batch to every queue currently subscribed to the topic. Repeat\n" +
			"-message, use newline-delimited -file, or combine both. No implicit stdin read\n" +
			"occurs; use -file=- explicitly. Empty file lines are ignored.\n\n" +
			"A nonzero exit may still mean some queues retained the batch, so retrying can\n" +
			"create duplicates. Receive and acknowledge from each subscribed queue with\n" +
			`"plainq receive" and "plainq delete-message".`,
		Args: []argSpec{{Name: argTopicID, Description: descTopicID, Required: true}},
		Examples: []exampleSpec{
			{
				Description: "Publish one message.",
				Command:     `plainq topic publish -message='{"order_id":42}' ` + exampleQueueID,
			},
			{
				Description: "Publish one message per line from standard input.",
				Command:     "generate-events | plainq topic publish -file=- " + exampleQueueID,
			},
		},
		SetFlags: flags.register,
		Run: func(_ *scotty.Command, args []string) (err error) {
			if arityErr := requireTopicArity("publish", args, 1); arityErr != nil {
				return arityErr
			}

			topicID, idErr := validateTopicCLIIdentifier("topic", args[0])
			if idErr != nil {
				return idErr
			}

			bodies, bodiesErr := collectMessageBodies(flags.messages, flags.file, deps.stdin)
			if bodiesErr != nil {
				return bodiesErr
			}

			messages := make([]*v1.PublishMessage, 0, len(bodies))
			for _, body := range bodies {
				messages = append(messages, &v1.PublishMessage{Body: body})
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			cli, closer, openErr := deps.open(ctx, flags.addr)
			if openErr != nil {
				return fmt.Errorf(fmtCreateClientError, openErr)
			}
			defer func() {
				if closeErr := closer.Close(); closeErr != nil {
					err = errors.Join(err, fmt.Errorf("close topic client: %w", closeErr))
				}
			}()

			response, rpcErr := cli.Publish(ctx, &v1.PublishRequest{TopicId: topicID, Messages: messages})
			if rpcErr != nil {
				return grpcErrorWithListHint(
					flags.addr,
					fmt.Sprintf("publish to topic %q", topicID),
					topicListCommand,
					rpcErr,
				)
			}

			if flags.jsonOut {
				return encodeJSON(deps.stdout, response)
			}

			if _, writeErr := fmt.Fprintf(deps.stdout, "delivered\t%d\n", response.GetDeliveredCount()); writeErr != nil {
				return fmt.Errorf("write publish result: %w", writeErr)
			}

			return nil
		},
	}
}

func requireTopicArity(command string, args []string, want int) error {
	if len(args) == want {
		return nil
	}

	return usagef("plainq topic %s takes exactly %d positional arguments, got %d", command, want, len(args))
}

// validateTopicCLIIdentifier validates a lower-cased copy because the XID
// parser is lower-case only, then returns the caller's original spelling.
func validateTopicCLIIdentifier(kind, id string) (string, error) {
	if err := idkit.ValidateXID(strings.ToLower(id)); err != nil {
		return "", usagef(
			"invalid %s id %q: %w (expected a 20-character id from plainq topic output)",
			kind,
			id,
			err,
		)
	}

	return id, nil
}
