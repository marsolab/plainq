package main

import (
	"fmt"

	"github.com/heartwilltell/scotty"
	"github.com/marsolab/plainq/internal/client"
	"github.com/marsolab/plainq/internal/tui"
)

func tuiCommand() *commandSpec {
	var addr string

	return &commandSpec{
		Name:     "tui",
		Short:    "Launch the interactive terminal dashboard",
		Effect:   effectMutating,
		Blocking: true,
		Long: "Opens a full-screen dashboard for browsing queues and messages.\n\n" +
			"This command needs an interactive terminal and runs until you quit it, so\n" +
			"it is the one command in the CLI that cannot be scripted. Every operation\n" +
			"it offers is also available as a plain command.",
		Examples: []exampleSpec{
			{Description: "Open the dashboard against a local server.", Command: "plainq tui"},
		},
		SetFlags: func(flags *scotty.FlagSet) {
			flags.StringVar(&addr, flagGRPCAddr, resolveGRPCAddr(),
				flagGRPCAddrUsage,
			)
		},
		Run: func(_ *scotty.Command, _ []string) error {
			cli, cliErr := client.New(addr)
			if cliErr != nil {
				return fmt.Errorf(fmtCreateClientError, cliErr)
			}

			if err := tui.Run(addr, cli); err != nil {
				return fmt.Errorf("run tui: %w", err)
			}

			return nil
		},
	}
}
