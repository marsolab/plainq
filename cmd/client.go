package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strings"

	"github.com/heartwilltell/scotty"
	"github.com/plainq/plainq/internal/client"
	v1 "github.com/plainq/plainq/internal/server/schema/v1"
	"github.com/plainq/servekit/idkit"
)

const (
	// defaultLimit represents the default limit for listing queues.
	defaultLimit = 500

	// flagGRPCAddr is the flag name for the gRPC address.
	flagGRPCAddr = "grpc.addr"

	// flagGRPCAddrUsage is the usage description for the gRPC address flag.
	flagGRPCAddrUsage = "sets PlainQ gRPC address."

	// flagJSON is the flag name for JSON output.
	flagJSON = "json"

	// flagJSONUsage is the usage description for the JSON output flag.
	flagJSONUsage = "enables json output"

	// fmtCreateClientError is the error format string for client creation failures.
	fmtCreateClientError = "create client: %w"

	// fmtEncodeResponseError is the error format string for response encoding failures.
	fmtEncodeResponseError = "encode response: %w"

	// defaultGRPCAddr is the default gRPC server address.
	defaultGRPCAddr = "localhost:8080"
)

func listQueueCommand() *scotty.Command {
	var (
		addr string

		limit   uint
		jsonOut bool
	)

	cmd := scotty.Command{
		Name:  "list",
		Short: "List queues",
		SetFlags: func(flags *scotty.FlagSet) {
			flags.StringVar(&addr, flagGRPCAddr, defaultGRPCAddr,
				flagGRPCAddrUsage,
			)

			flags.BoolVar(&jsonOut, flagJSON, false,
				flagJSONUsage,
			)

			flags.UintVar(&limit, "limit", defaultLimit,
				"sets pages size for pagination",
			)
		},
		Run: func(_ *scotty.Command, _ []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			cli, cliErr := client.New(addr)
			if cliErr != nil {
				return fmt.Errorf(fmtCreateClientError, cliErr)
			}

			if limit > math.MaxInt32 {
				return fmt.Errorf("limit value too large: %d", limit)
			}
			in := &v1.ListQueuesRequest{
				Limit: int32(limit),
			}

			list, listErr := cli.ListQueues(ctx, in)
			if listErr != nil {
				return fmt.Errorf("list queues: %w", listErr)
			}

			if jsonOut {
				if err := json.NewEncoder(os.Stdout).Encode(list); err != nil {
					return fmt.Errorf("encode queue list: %w", err)
				}

				return nil
			}

			for _, q := range list.GetQueues() {
				fmt.Println(q.GetQueueId(), "|", q.GetQueueName())
			}

			// TODO: ask for pagination.

			return nil
		},
	}

	return &cmd
}

func createQueueCommand() *scotty.Command {
	var (
		addr    string
		jsonOut bool

		retentionPeriodSeconds   uint
		visibilityTimeoutSeconds uint
		maxReceiveAttempts       uint
		dropPolicy               string
		deadLetterQueueID        string
	)

	cmd := scotty.Command{
		Name:  "create",
		Short: "Create a queue",
		SetFlags: func(flags *scotty.FlagSet) {
			flags.StringVar(&addr, flagGRPCAddr, defaultGRPCAddr,
				flagGRPCAddrUsage,
			)
			flags.BoolVar(&jsonOut, flagJSON, false,
				flagJSONUsage,
			)
			flags.UintVar(&retentionPeriodSeconds, "retention-period", 0,
				"",
			)
			flags.UintVar(&visibilityTimeoutSeconds, "visibility-timeout", 30,
				"",
			)
			flags.UintVar(&maxReceiveAttempts, "max-receive-attempts", 5,
				"",
			)
			flags.StringVar(&dropPolicy, "drop-policy", "drop",
				"",
			)
			flags.StringVar(&deadLetterQueueID, "dead-letter-queue-id", "",
				"",
			)
		},
		Run: func(_ *scotty.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			if len(args) < 1 {
				return errors.New("queue name should be specified: plainq create [queue name]")
			}

			name := args[0]

			cli, cliErr := client.New(addr)
			if cliErr != nil {
				return fmt.Errorf(fmtCreateClientError, cliErr)
			}

			var queueDropPolicy v1.EvictionPolicy

			switch strings.ToLower(dropPolicy) {
			case "dead-letter":
				queueDropPolicy = v1.EvictionPolicy_EVICTION_POLICY_DEAD_LETTER

			case "drop":
				queueDropPolicy = v1.EvictionPolicy_EVICTION_POLICY_DROP

			default:
				return fmt.Errorf(`unknown drop policy: %q, should be on of: ["dead-letter", "drop"]`, dropPolicy)
			}

			if maxReceiveAttempts > math.MaxUint32 {
				return fmt.Errorf("max receive attempts value too large: %d", maxReceiveAttempts)
			}

			in := &v1.CreateQueueRequest{
				QueueName:                name,
				RetentionPeriodSeconds:   uint64(retentionPeriodSeconds),
				VisibilityTimeoutSeconds: uint64(visibilityTimeoutSeconds),
				MaxReceiveAttempts:       uint32(maxReceiveAttempts),
				EvictionPolicy:           queueDropPolicy,
				DeadLetterQueueId:        deadLetterQueueID,
			}

			create, createErr := cli.CreateQueue(ctx, in)
			if createErr != nil {
				return fmt.Errorf("create queue: %w", createErr)
			}

			if jsonOut {
				if err := json.NewEncoder(os.Stdout).Encode(create); err != nil {
					return fmt.Errorf(fmtEncodeResponseError, err)
				}

				return nil
			}

			fmt.Println(create.GetQueueId())

			return nil
		},
	}

	return &cmd
}

func describeQueueCommand() *scotty.Command {
	var (
		addr    string
		jsonOut bool
	)

	cmd := scotty.Command{
		Name:  "describe",
		Short: "describe a queue",
		SetFlags: func(flags *scotty.FlagSet) {
			flags.StringVar(&addr, flagGRPCAddr, defaultGRPCAddr,
				flagGRPCAddrUsage,
			)

			flags.BoolVar(&jsonOut, flagJSON, false,
				flagJSONUsage,
			)
		},
		Run: func(_ *scotty.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			if len(args) < 1 {
				return errors.New("queue id should be specified: plainq describe [queue id]")
			}

			id := args[0]

			if err := idkit.ValidateXID(id); err != nil {
				return err
			}

			cli, cliErr := client.New(addr)
			if cliErr != nil {
				return fmt.Errorf(fmtCreateClientError, cliErr)
			}

			in := &v1.DescribeQueueRequest{
				QueueId: id,
			}

			purge, purgeErr := cli.DescribeQueue(ctx, in)
			if purgeErr != nil {
				return fmt.Errorf("describe queue (id: %q): %w", id, purgeErr)
			}

			if jsonOut {
				if err := json.NewEncoder(os.Stdout).Encode(purge); err != nil {
					return fmt.Errorf(fmtEncodeResponseError, err)
				}

				return nil
			}

			return nil
		},
	}

	return &cmd
}

func purgeQueueCommand() *scotty.Command {
	var (
		addr    string
		jsonOut bool
	)

	cmd := scotty.Command{
		Name:  "purge",
		Short: "Purge a queue",
		SetFlags: func(flags *scotty.FlagSet) {
			flags.StringVar(&addr, flagGRPCAddr, defaultGRPCAddr,
				flagGRPCAddrUsage,
			)
			flags.BoolVar(&jsonOut, flagJSON, false,
				flagJSONUsage,
			)
		},
		Run: func(_ *scotty.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			if len(args) < 1 {
				return errors.New("queue id should be specified: plainq purge [queue id]")
			}

			id := args[0]

			if err := idkit.ValidateXID(id); err != nil {
				return err
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
				return fmt.Errorf("purge queue: %w", purgeErr)
			}

			if jsonOut {
				if err := json.NewEncoder(os.Stdout).Encode(purge); err != nil {
					return fmt.Errorf(fmtEncodeResponseError, err)
				}

				return nil
			}

			return nil
		},
	}

	return &cmd
}

func deleteQueueCommand() *scotty.Command {
	var (
		addr string

		force   bool
		jsonOut bool
	)

	cmd := scotty.Command{
		Name:  "delete",
		Short: "Delete a queue",
		SetFlags: func(flags *scotty.FlagSet) {
			flags.StringVar(&addr, flagGRPCAddr, defaultGRPCAddr,
				flagGRPCAddrUsage,
			)
			flags.BoolVar(&jsonOut, flagJSON, false,
				flagJSONUsage,
			)
			flags.BoolVar(&force, "force", false,
				"enables force delete",
			)
		},
		Run: func(_ *scotty.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			if len(args) < 1 {
				return errors.New("queue id should be specified: plainq delete [queue id]")
			}

			id := args[0]

			if err := idkit.ValidateXID(id); err != nil {
				return err
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
				return fmt.Errorf("delete queue: %w", deleteqErr)
			}

			if jsonOut {
				if err := json.NewEncoder(os.Stdout).Encode(deleteq); err != nil {
					return fmt.Errorf(fmtEncodeResponseError, err)
				}

				return nil
			}

			return nil
		},
	}

	return &cmd
}

func sendCommand() *scotty.Command {
	var (
		addr    string
		message string
		jsonOut bool
	)

	cmd := scotty.Command{
		Name:  "send",
		Short: "Sent a message to the queue",
		SetFlags: func(flags *scotty.FlagSet) {
			flags.StringVar(&addr, flagGRPCAddr, defaultGRPCAddr,
				flagGRPCAddrUsage,
			)
			flags.StringVar(&message, "message", "",
				"sets message as a string",
			)
			flags.BoolVar(&jsonOut, flagJSON, false,
				flagJSONUsage,
			)
		},
		Run: func(_ *scotty.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			if len(args) < 1 {
				return errors.New("queue id should be specified: plainq send [flags...] [queue id]")
			}

			id := args[0]

			if err := idkit.ValidateXID(id); err != nil {
				return err
			}

			cli, cliErr := client.New(addr)
			if cliErr != nil {
				return fmt.Errorf(fmtCreateClientError, cliErr)
			}

			in := &v1.SendRequest{
				QueueId: id,
				Messages: []*v1.SendMessage{
					{Body: []byte(message)},
				},
			}

			send, sendErr := cli.Send(ctx, in)
			if sendErr != nil {
				return fmt.Errorf("sent message: %w", sendErr)
			}

			if jsonOut {
				if err := json.NewEncoder(os.Stdout).Encode(send); err != nil {
					return fmt.Errorf(fmtEncodeResponseError, err)
				}

				return nil
			}

			fmt.Println(send.GetMessageIds())

			return nil
		},
	}

	return &cmd
}

func receiveCommand() *scotty.Command {
	var (
		addr    string
		batch   uint
		jsonOut bool
	)

	cmd := scotty.Command{
		Name:  "receive",
		Short: "Receive a messages from the queue",
		SetFlags: func(flags *scotty.FlagSet) {
			flags.StringVar(&addr, flagGRPCAddr, defaultGRPCAddr,
				flagGRPCAddrUsage,
			)
			flags.UintVar(&batch, "batch", 1,
				"set receive batch size",
			)
			flags.BoolVar(&jsonOut, flagJSON, false,
				flagJSONUsage,
			)
		},
		Run: func(_ *scotty.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			if len(args) < 1 {
				return errors.New("queue id should be specified: plainq send [flags...] [queue id]")
			}

			id := args[0]

			if err := idkit.ValidateXID(id); err != nil {
				return err
			}

			cli, cliErr := client.New(addr)
			if cliErr != nil {
				return fmt.Errorf(fmtCreateClientError, cliErr)
			}

			if batch > math.MaxUint32 {
				return fmt.Errorf("batch size value too large: %d", batch)
			}
			in := &v1.ReceiveRequest{
				QueueId:   id,
				BatchSize: uint32(batch),
			}

			receive, receiveErr := cli.Receive(ctx, in)
			if receiveErr != nil {
				return fmt.Errorf("receive message: %w", receiveErr)
			}

			if jsonOut {
				if err := json.NewEncoder(os.Stdout).Encode(receive); err != nil {
					return fmt.Errorf(fmtEncodeResponseError, err)
				}

				return nil
			}

			fmt.Println(receive.GetMessages())

			return nil
		},
	}

	return &cmd
}
