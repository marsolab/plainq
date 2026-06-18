package main

import (
	"fmt"
	"os"
	"time"

	"github.com/heartwilltell/scotty"
)

// Variables which are related to Version command.
// Should be specified by '-ldflags' during the build phase.
// Example:
//
//	GOOS=linux GOARCH=amd64 go build -ldflags=" \
//	-X main.Branch=$BRANCH -X main.Commit=$COMMIT" -o plainq
var (
	// Branch is the branch this binary built from.
	Branch = "local"

	// Commit is the commit this binary built from.
	Commit = "unknown"

	// BuildTime is the time this binary built.
	BuildTime = time.Now().Format(time.RFC822)
)

func main() {
	rootCmd := scotty.Command{
		Name: "plainq",
	}

	rootCmd.AddSubcommands(
		versionCommand(),
		contextCommand(),

		// Serer commands.
		serverCommand(),

		// Client commands.
		listQueueCommand(),
		createQueueCommand(),
		describeQueueCommand(),
		purgeQueueCommand(),
		deleteQueueCommand(),
		sendCommand(),
		receiveCommand(),
	)

	if err := rootCmd.Exec(); err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
}

func versionCommand() *scotty.Command {
	cmd := scotty.Command{
		Name:  "version",
		Short: "Prints the version of the program.",
		Run: func(_ *scotty.Command, _ []string) error {
			fmt.Printf("Built from: %s [%s]\n", Branch, Commit)
			fmt.Printf("Built on: %s\n", BuildTime)
			fmt.Printf("Built time: %v\n", time.Now().UTC())

			return nil
		},
	}

	return &cmd
}
