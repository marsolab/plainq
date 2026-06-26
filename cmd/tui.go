package main

import (
	"fmt"

	"github.com/heartwilltell/scotty"
	"github.com/marsolab/plainq/internal/client"
	"github.com/marsolab/plainq/internal/tui"
)

func tuiCommand() *scotty.Command {
	var addr string

	cmd := scotty.Command{
		Name:  "tui",
		Short: "Launch the interactive terminal UI",
		SetFlags: func(flags *scotty.FlagSet) {
			flags.StringVar(&addr, flagGRPCAddr, defaultGRPCAddr,
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

	return &cmd
}
