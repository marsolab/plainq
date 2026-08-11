package main

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strings"

	"github.com/heartwilltell/scotty"
	"github.com/marsolab/plainq/internal/client"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
)

const (
	// defaultLimit represents the default limit for listing queues.
	defaultLimit = 500

	// flagGRPCAddr is the flag name for the gRPC address.
	flagGRPCAddr = "grpc.addr"

	// flagGRPCAddrUsage is the usage description for the gRPC address flag.
	flagGRPCAddrUsage = "address of the PlainQ gRPC server (falls back to $" + envGRPCAddr +
		", then to the current context)"

	// flagJSON is the flag name for JSON output.
	flagJSON = "json"

	// flagJSONUsage is the usage description for the JSON output flag.
	flagJSONUsage = "write the raw server response to stdout as JSON"

	// fmtCreateClientError is the error format string for client creation failures.
	fmtCreateClientError = "create client: %w"

	// defaultGRPCAddr is the default gRPC server address.
	defaultGRPCAddr = "localhost:8080"

	// exampleQueueID is a well-formed queue id used in help examples. Showing a
	// realistic id — rather than a placeholder like QUEUE_ID — tells a reader
	// what shape the argument takes without a second lookup.
	exampleQueueID = "D1MHTM0EFR7CBTQ8SL3G"

	// argQueueID names the queue id positional argument.
	argQueueID = "queue-id"

	// descQueueID describes the queue id positional argument.
	descQueueID = `queue identifier printed by "plainq create" or "plainq list" (20 characters)`
)

func listQueueCommand() *commandSpec {
	var (
		addr string

		limit   uint
		jsonOut bool
	)

	return &commandSpec{
		Name:   "list",
		Short:  "List queues",
		Effect: effectReadOnly,
		Long: "Lists the queues on the server, newest first.\n\n" +
			"Text output is one \"<queue-id> | <queue-name>\" line per queue. Use -json\n" +
			"to get the queue objects instead, which is the only way to read a queue's\n" +
			"settings without a follow-up describe call.",
		Examples: []exampleSpec{
			{Description: "List every queue.", Command: "plainq list"},
			{
				Description: "Extract just the queue ids.",
				Command:     "plainq list -json | jq -r '.queues[].queueId'",
			},
			{
				Description: "Talk to a server on another host.",
				Command:     "plainq list -grpc.addr=queue.internal:8080",
			},
		},
		SetFlags: func(flags *scotty.FlagSet) {
			flags.StringVar(&addr, flagGRPCAddr, resolveGRPCAddr(),
				flagGRPCAddrUsage,
			)

			flags.BoolVar(&jsonOut, flagJSON, false,
				flagJSONUsage,
			)

			flags.UintVar(&limit, "limit", defaultLimit,
				"maximum number of queues to return",
			)
		},
		Run: func(_ *scotty.Command, _ []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			if limit > math.MaxInt32 {
				return usagef("limit value too large: %d", limit)
			}

			cli, cliErr := client.New(addr)
			if cliErr != nil {
				return fmt.Errorf(fmtCreateClientError, cliErr)
			}

			in := &v1.ListQueuesRequest{
				Limit: int32(limit),
			}

			list, listErr := cli.ListQueues(ctx, in)
			if listErr != nil {
				return grpcError(addr, "list queues", listErr)
			}

			if jsonOut {
				return encodeJSON(os.Stdout, list)
			}

			for _, q := range list.GetQueues() {
				fmt.Println(q.GetQueueId(), "|", q.GetQueueName())
			}

			//nolint:godox // pagination is intentionally deferred until the CLI gains a paginated UX.
			// TODO: ask for pagination.
			return nil
		},
	}
}

// createQueueFlags is the set of knobs a queue is created with.
type createQueueFlags struct {
	addr    string
	jsonOut bool

	retentionPeriodSeconds   uint
	visibilityTimeoutSeconds uint
	maxReceiveAttempts       uint
	dropPolicy               string
	deadLetterQueueID        string
}

func (c *createQueueFlags) register(flags *scotty.FlagSet) {
	flags.StringVar(&c.addr, flagGRPCAddr, resolveGRPCAddr(),
		flagGRPCAddrUsage,
	)

	flags.BoolVar(&c.jsonOut, flagJSON, false,
		flagJSONUsage,
	)

	flags.UintVar(&c.retentionPeriodSeconds, "retention-period", 0,
		"seconds a message is kept before it expires (0 uses the server default of 7 days)",
	)

	flags.UintVar(&c.visibilityTimeoutSeconds, "visibility-timeout", 30,
		"seconds a received message stays hidden from other consumers before redelivery",
	)

	flags.UintVar(&c.maxReceiveAttempts, "max-receive-attempts", 5,
		"receives a message survives before the eviction policy applies",
	)

	flags.StringVar(&c.dropPolicy, "drop-policy", "drop",
		`what to do with an evicted message: "drop" discards it, "dead-letter" moves it to -dead-letter-queue-id`,
	)

	flags.StringVar(&c.deadLetterQueueID, "dead-letter-queue-id", "",
		`queue id that receives evicted messages; required when -drop-policy=dead-letter`,
	)
}

// request turns the flags into a create request, rejecting values the server
// would only reject later.
func (c *createQueueFlags) request(name string) (*v1.CreateQueueRequest, error) {
	var policy v1.EvictionPolicy

	switch strings.ToLower(c.dropPolicy) {
	case "dead-letter":
		policy = v1.EvictionPolicy_EVICTION_POLICY_DEAD_LETTER

	case "drop":
		policy = v1.EvictionPolicy_EVICTION_POLICY_DROP

	default:
		return nil, usagef(`unknown drop policy: %q, should be one of: ["dead-letter", "drop"]`, c.dropPolicy)
	}

	if c.maxReceiveAttempts > math.MaxUint32 {
		return nil, usagef("max receive attempts value too large: %d", c.maxReceiveAttempts)
	}

	return &v1.CreateQueueRequest{
		QueueName:                name,
		RetentionPeriodSeconds:   uint64(c.retentionPeriodSeconds),
		VisibilityTimeoutSeconds: uint64(c.visibilityTimeoutSeconds),
		MaxReceiveAttempts:       uint32(c.maxReceiveAttempts),
		EvictionPolicy:           policy,
		DeadLetterQueueId:        c.deadLetterQueueID,
	}, nil
}

func createQueueCommand() *commandSpec {
	var flags createQueueFlags

	return &commandSpec{
		Name:   "create",
		Short:  "Create a queue",
		Effect: effectMutating,
		Long: "Creates a queue and prints its id on stdout. Everything else in the CLI\n" +
			"addresses queues by that id, so capture it: QID=$(plainq create orders).\n\n" +
			"Queue names are not unique and are not accepted where an id is expected.",
		Args: []argSpec{
			{
				Name:        "queue-name",
				Description: "human-readable name for the queue",
				Required:    true,
			},
		},
		Examples: []exampleSpec{
			{
				Description: "Create a queue with the defaults and keep its id.",
				Command:     "QID=$(plainq create orders)",
			},
			{
				Description: "Create a queue for slow jobs that dead-letters repeated failures.",
				Command: "DLQ=$(plainq create orders-dlq)\n" +
					"  plainq create orders -visibility-timeout=300 -max-receive-attempts=3 \\\n" +
					`    -drop-policy=dead-letter -dead-letter-queue-id="$DLQ"`,
			},
		},
		SetFlags: flags.register,
		Run: func(_ *scotty.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			if len(args) < 1 {
				return usagef("queue name is required: plainq create [flags] <queue-name>")
			}

			in, inErr := flags.request(args[0])
			if inErr != nil {
				return inErr
			}

			cli, cliErr := client.New(flags.addr)
			if cliErr != nil {
				return fmt.Errorf(fmtCreateClientError, cliErr)
			}

			create, createErr := cli.CreateQueue(ctx, in)
			if createErr != nil {
				return grpcError(flags.addr, "create queue", createErr)
			}

			if flags.jsonOut {
				return encodeJSON(os.Stdout, create)
			}

			fmt.Println(create.GetQueueId())

			return nil
		},
	}
}

func describeQueueCommand() *commandSpec {
	var (
		addr    string
		jsonOut bool
	)

	return &commandSpec{
		Name:   "describe",
		Short:  "Show a queue's settings",
		Effect: effectReadOnly,
		Long: "Prints the queue's retention period, visibility timeout, receive limit,\n" +
			"eviction policy, and dead-letter target.\n\n" +
			"The text rendering is deliberately minimal; use -json to read the fields\n" +
			"programmatically.",
		Args: []argSpec{
			{Name: argQueueID, Description: descQueueID, Required: true},
		},
		Examples: []exampleSpec{
			{
				Description: "Show a queue's settings.",
				Command:     "plainq describe " + exampleQueueID,
			},
			{
				Description: "Read the visibility timeout programmatically.",
				Command:     "plainq describe -json " + exampleQueueID + " | jq -r '.visibilityTimeoutSeconds'",
			},
		},
		SetFlags: func(flags *scotty.FlagSet) {
			flags.StringVar(&addr, flagGRPCAddr, resolveGRPCAddr(),
				flagGRPCAddrUsage,
			)

			flags.BoolVar(&jsonOut, flagJSON, false,
				flagJSONUsage,
			)
		},
		Run: func(_ *scotty.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			id, idErr := queueIDArg("describe", args)
			if idErr != nil {
				return idErr
			}

			cli, cliErr := client.New(addr)
			if cliErr != nil {
				return fmt.Errorf(fmtCreateClientError, cliErr)
			}

			in := &v1.DescribeQueueRequest{
				QueueId: id,
			}

			queue, describeErr := cli.DescribeQueue(ctx, in)
			if describeErr != nil {
				return grpcError(addr, fmt.Sprintf("describe queue %q", id), describeErr)
			}

			if jsonOut {
				return encodeJSON(os.Stdout, queue)
			}

			printQueueText(os.Stdout, queue)

			return nil
		},
	}
}

func purgeQueueCommand() *commandSpec {
	var (
		addr    string
		jsonOut bool
	)

	return &commandSpec{
		Name:   "purge",
		Short:  "Delete every message in a queue",
		Effect: effectDestructive,
		Long: "Deletes all messages in the queue and keeps the queue itself. There is no\n" +
			"confirmation prompt and no undo: purged messages are gone.\n\n" +
			"Prints the number of messages removed.",
		Args: []argSpec{
			{Name: argQueueID, Description: descQueueID, Required: true},
		},
		Examples: []exampleSpec{
			{
				Description: "Empty a queue.",
				Command:     "plainq purge " + exampleQueueID,
			},
		},
		SetFlags: func(flags *scotty.FlagSet) {
			flags.StringVar(&addr, flagGRPCAddr, resolveGRPCAddr(),
				flagGRPCAddrUsage,
			)

			flags.BoolVar(&jsonOut, flagJSON, false,
				flagJSONUsage,
			)
		},
		Run: func(_ *scotty.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			id, idErr := queueIDArg("purge", args)
			if idErr != nil {
				return idErr
			}

			cli, cliErr := client.New(addr)
			if cliErr != nil {
				return fmt.Errorf(fmtCreateClientError, cliErr)
			}

			in := &v1.PurgeQueueRequest{
				QueueId: id,
			}

			purge, purgeErr := cli.PurgeQueue(ctx, in)
			if purgeErr != nil {
				return grpcError(addr, fmt.Sprintf("purge queue %q", id), purgeErr)
			}

			if jsonOut {
				return encodeJSON(os.Stdout, purge)
			}

			fmt.Printf("purged\t%d\n", purge.GetMessagesCount())

			return nil
		},
	}
}

func deleteQueueCommand() *commandSpec {
	var (
		addr string

		force   bool
		jsonOut bool
	)

	return &commandSpec{
		Name:   "delete",
		Short:  "Delete a queue",
		Effect: effectDestructive,
		Long: "Deletes the queue itself. A queue that still holds messages is protected;\n" +
			"pass -force to delete it anyway. There is no confirmation prompt and no undo.\n\n" +
			`To empty a queue without removing it, use "plainq purge".`,
		Args: []argSpec{
			{Name: argQueueID, Description: descQueueID, Required: true},
		},
		Examples: []exampleSpec{
			{
				Description: "Delete an empty queue.",
				Command:     "plainq delete " + exampleQueueID,
			},
			{
				Description: "Delete a queue that still holds messages.",
				Command:     "plainq delete -force " + exampleQueueID,
			},
		},
		SetFlags: func(flags *scotty.FlagSet) {
			flags.StringVar(&addr, flagGRPCAddr, resolveGRPCAddr(),
				flagGRPCAddrUsage,
			)

			flags.BoolVar(&jsonOut, flagJSON, false,
				flagJSONUsage,
			)

			flags.BoolVar(&force, "force", false,
				"delete the queue even if it still holds messages",
			)
		},
		Run: func(_ *scotty.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			id, idErr := queueIDArg("delete", args)
			if idErr != nil {
				return idErr
			}

			cli, cliErr := client.New(addr)
			if cliErr != nil {
				return fmt.Errorf(fmtCreateClientError, cliErr)
			}

			in := &v1.DeleteQueueRequest{
				QueueId: id,
				Force:   force,
			}

			deleteq, deleteqErr := cli.DeleteQueue(ctx, in)
			if deleteqErr != nil {
				return grpcError(addr, fmt.Sprintf("delete queue %q", id), deleteqErr)
			}

			if jsonOut {
				return encodeJSON(os.Stdout, deleteq)
			}

			fmt.Printf("deleted\t%s\n", id)

			return nil
		},
	}
}

func sendCommand() *commandSpec {
	var (
		addr     string
		messages stringSliceFlag
		file     string
		jsonOut  bool
	)

	return &commandSpec{
		Name:   "send",
		Short:  "Send one or more messages to a queue",
		Effect: effectMutating,
		Long: "Sends message bodies to a queue and prints the resulting message ids, one\n" +
			"per line. Bodies are sent verbatim as bytes.\n\n" +
			"At least one of -message or -file is required. Repeat -message, or point\n" +
			"-file at a newline-delimited source, to send a batch in a single call.",
		Args: []argSpec{
			{Name: argQueueID, Description: descQueueID, Required: true},
		},
		Examples: []exampleSpec{
			{
				Description: "Send one message.",
				Command:     `plainq send -message='{"order_id":42}' ` + exampleQueueID,
			},
			{
				Description: "Send a batch by repeating -message.",
				Command:     `plainq send -message='first' -message='second' ` + exampleQueueID,
			},
			{
				Description: "Send one message per line from a file.",
				Command:     "plainq send -file=payloads.ndjson " + exampleQueueID,
			},
			{
				Description: `Send from standard input ("-").`,
				Command:     "generate-events | plainq send -file=- " + exampleQueueID,
			},
		},
		SetFlags: func(flags *scotty.FlagSet) {
			flags.StringVar(&addr, flagGRPCAddr, resolveGRPCAddr(),
				flagGRPCAddrUsage,
			)

			flags.Var(&messages, "message",
				"message body to send",
			)

			flags.StringVar(&file, "file", "",
				`read newline-delimited message bodies from this path ("-" reads standard input)`,
			)

			flags.BoolVar(&jsonOut, flagJSON, false,
				flagJSONUsage,
			)
		},
		Run: func(_ *scotty.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			id, idErr := queueIDArg("send", args)
			if idErr != nil {
				return idErr
			}

			bodies, bodiesErr := collectSendMessages(messages, file)
			if bodiesErr != nil {
				return bodiesErr
			}

			cli, cliErr := client.New(addr)
			if cliErr != nil {
				return fmt.Errorf(fmtCreateClientError, cliErr)
			}

			send, sendErr := cli.Send(ctx, &v1.SendRequest{QueueId: id, Messages: bodies})
			if sendErr != nil {
				return grpcError(addr, "send messages", sendErr)
			}

			if jsonOut {
				return encodeJSON(os.Stdout, send)
			}

			for _, messageID := range send.GetMessageIds() {
				fmt.Println(messageID)
			}

			return nil
		},
	}
}

// receiveFlags is the set every receive shares.
type receiveFlags struct {
	addr    string
	batch   uint
	ack     bool
	jsonOut bool
}

func (r *receiveFlags) register(flags *scotty.FlagSet) {
	flags.StringVar(&r.addr, flagGRPCAddr, resolveGRPCAddr(),
		flagGRPCAddrUsage,
	)

	flags.UintVar(&r.batch, "batch", 1,
		"number of messages to receive at once (the server caps this at 10)",
	)

	flags.BoolVar(&r.ack, "ack", false,
		"delete each received message after printing it",
	)

	flags.BoolVar(&r.jsonOut, flagJSON, false,
		flagJSONUsage,
	)
}

func receiveCommand() *commandSpec {
	var flags receiveFlags

	return &commandSpec{
		Name:   "receive",
		Short:  "Receive messages from a queue",
		Effect: effectMutating,
		Long: "Receives up to -batch messages. Each received message is hidden from other\n" +
			"consumers for the queue's visibility timeout and its receive counter is\n" +
			"incremented; once the counter passes the queue's max-receive-attempts the\n" +
			"message is evicted according to the queue's drop policy.\n\n" +
			"Delivery is at-least-once, so receiving does not delete. Acknowledge either\n" +
			"with -ack, which deletes each message right after it is printed, or by\n" +
			`passing the ids to "plainq delete-message" once the work has succeeded.` + "\n\n" +
			"Text output is one \"<message-id>\\t<body>\" line per message, which assumes\n" +
			"bodies contain no newlines or tabs; use -json for bodies that might. Bodies\n" +
			"are bytes, so -json base64-encodes them:\n\n" +
			"  plainq receive -json <queue-id> | jq -r '.messages[].body | @base64d'\n\n" +
			"Receiving from an empty queue is not an error: it prints nothing and exits 0.",
		Args: []argSpec{
			{Name: argQueueID, Description: descQueueID, Required: true},
		},
		Examples: []exampleSpec{
			{
				Description: "Receive a single message, leaving it in the queue.",
				Command:     "plainq receive " + exampleQueueID,
			},
			{
				Description: "Receive a batch and read the ids programmatically.",
				Command:     "plainq receive -batch=10 -json " + exampleQueueID + " | jq -r '.messages[].id'",
			},
			{
				Description: "Read the message bodies, decoding them from base64.",
				Command:     "plainq receive -batch=10 -json " + exampleQueueID + " | jq -r '.messages[].body | @base64d'",
			},
			{
				Description: "Drain a batch and acknowledge it in one step.",
				Command:     "plainq receive -batch=10 -ack " + exampleQueueID,
			},
		},
		SetFlags: flags.register,
		Run: func(_ *scotty.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			id, idErr := queueIDArg("receive", args)
			if idErr != nil {
				return idErr
			}

			if flags.batch > math.MaxUint32 {
				return usagef("batch size value too large: %d", flags.batch)
			}

			cli, cliErr := client.New(flags.addr)
			if cliErr != nil {
				return fmt.Errorf(fmtCreateClientError, cliErr)
			}

			in := &v1.ReceiveRequest{QueueId: id, BatchSize: uint32(flags.batch)}

			receive, receiveErr := cli.Receive(ctx, in)
			if receiveErr != nil {
				return grpcError(flags.addr, "receive messages", receiveErr)
			}

			// Render output before acknowledging so that a failed write (closed
			// pipe, encoding error) never deletes messages the caller never
			// actually received — this is what -ack's "after printing" means.
			if flags.jsonOut {
				if err := encodeJSON(os.Stdout, receive); err != nil {
					return err
				}
			} else {
				printReceivedText(os.Stdout, receive.GetMessages())
			}

			if flags.ack {
				if err := ackReceived(ctx, cli, id, receive.GetMessages()); err != nil {
					return err
				}
			}

			return nil
		},
	}
}

// queueIDArg reads and validates the queue id positional argument shared by
// most client commands. Both failures are usage errors: the caller has to
// change the command line, not retry it.
func queueIDArg(command string, args []string) (string, error) {
	if len(args) < 1 {
		return "", usagef("queue id is required: plainq %s [flags] <queue-id>", command)
	}

	if err := validateQueueID(args[0]); err != nil {
		return "", err
	}

	return args[0], nil
}

// ackReceived deletes the given received messages from the queue, acknowledging
// them so they are not redelivered.
func ackReceived(ctx context.Context, cli *client.Client, queueID string, messages []*v1.ReceiveMessage) error {
	if len(messages) == 0 {
		return nil
	}

	ids := make([]string, 0, len(messages))
	for _, msg := range messages {
		ids = append(ids, msg.GetId())
	}

	if _, err := cli.Delete(ctx, &v1.DeleteRequest{QueueId: queueID, MessageIds: ids}); err != nil {
		return fmt.Errorf("ack messages: %w", err)
	}

	return nil
}
