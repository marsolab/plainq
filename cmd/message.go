package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/heartwilltell/scotty"
	"github.com/marsolab/plainq/internal/client"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
)

// minDeleteMessageArgs is the queue id plus at least one message id.
const minDeleteMessageArgs = 2

func deleteMessageCommand() *scotty.Command {
	var (
		addr    string
		jsonOut bool
	)

	cmd := scotty.Command{
		Name:  "delete-message",
		Short: "Delete (acknowledge) one or more messages from a queue",
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

			if len(args) < minDeleteMessageArgs {
				return errors.New("usage: plainq delete-message [queue id] [message id...]")
			}

			id := args[0]

			if err := validateQueueID(id); err != nil {
				return err
			}

			cli, cliErr := client.New(addr)
			if cliErr != nil {
				return fmt.Errorf(fmtCreateClientError, cliErr)
			}

			resp, deleteErr := cli.Delete(ctx, &v1.DeleteRequest{QueueId: id, MessageIds: args[1:]})
			if deleteErr != nil {
				return fmt.Errorf("delete messages: %w", deleteErr)
			}

			if jsonOut {
				return encodeJSON(os.Stdout, resp)
			}

			for _, messageID := range resp.GetSuccessful() {
				fmt.Printf("deleted\t%s\n", messageID)
			}

			for _, failure := range resp.GetFailed() {
				fmt.Printf("failed\t%s\t%s\n", failure.GetMessageId(), failure.GetError())
			}

			return nil
		},
	}

	return &cmd
}
