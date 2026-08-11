package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/heartwilltell/scotty"
	"github.com/marsolab/plainq/internal/client"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
)

// minDeleteMessageArgs is the queue id plus at least one message id.
const minDeleteMessageArgs = 2

func deleteMessageCommand() *commandSpec {
	var (
		addr    string
		jsonOut bool
	)

	return &commandSpec{
		Name:   "delete-message",
		Short:  "Acknowledge (delete) messages by id",
		Effect: effectDestructive,
		Long: "Deletes the given messages from the queue so they are not redelivered.\n" +
			"This is how a worker acknowledges the work it has finished.\n\n" +
			"Message ids come from \"plainq send\" or \"plainq receive\". Deleting a message\n" +
			"that does not exist is reported per id rather than failing the command, so\n" +
			"check the output: text mode prints \"deleted\\t<id>\" per success and\n" +
			"\"failed\\t<id>\\t<error>\" per failure.",
		Args: []argSpec{
			{Name: argQueueID, Description: descQueueID, Required: true},
			{
				Name:        "message-id",
				Description: `message identifier printed by "plainq send" or "plainq receive"`,
				Required:    true,
				Variadic:    true,
			},
		},
		Examples: []exampleSpec{
			{
				Description: "Acknowledge one message.",
				Command:     "plainq delete-message " + exampleQueueID + " 9m4e2mr0ui3e8a215n4g",
			},
			{
				Description: "Receive a batch, then acknowledge it after the work succeeds.",
				Command: "IDS=$(plainq receive -batch=10 -json " + exampleQueueID + " | jq -r '.messages[].id')\n" +
					"  plainq delete-message " + exampleQueueID + " $IDS",
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

			if len(args) < minDeleteMessageArgs {
				return usagef("usage: plainq delete-message [flags] <queue-id> <message-id>...")
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
				return grpcError(addr, "delete messages", deleteErr)
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
}
