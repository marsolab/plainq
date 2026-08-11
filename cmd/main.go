package main

import (
	"fmt"
	"os"
	"path/filepath"
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
	rootName = filepath.Base(os.Args[0])

	root := rootCommand()

	// Build the command tree before touching the arguments: normalization has
	// to know which flags each command defines.
	command := root.command()

	os.Args = append(os.Args[:1:1], normalizeArgs(root, os.Args[1:])...)

	if err := command.Exec(); err != nil {
		os.Exit(reportError(os.Stderr, err))
	}
}

// rootCommand assembles the command tree.
func rootCommand() *commandSpec {
	return &commandSpec{
		Name:  "plainq",
		Short: "Truly simple queue service",
		Long: "PlainQ is a queue server and its client in one binary. Every command except\n" +
			`"serve" is a client that talks to a running server over gRPC.` + "\n\n" +
			"A round trip looks like this:\n\n" +
			"  plainq serve &                       # or point -grpc.addr at a server\n" +
			"  QID=$(plainq create orders)          # create a queue, keep its id\n" +
			`  plainq send -message='hello' "$QID"  # enqueue` + "\n" +
			`  plainq receive -ack "$QID"           # dequeue and acknowledge`,
		Subcommands: []*commandSpec{
			// Server.
			serverCommand(),

			// Queues.
			listQueueCommand(),
			createQueueCommand(),
			describeQueueCommand(),
			purgeQueueCommand(),
			deleteQueueCommand(),

			// Messages.
			sendCommand(),
			receiveCommand(),
			deleteMessageCommand(),

			// Cluster administration.
			clusterCommand(),

			// Local configuration, introspection and interactive use.
			contextCommand(),
			schemaCommand(),
			tuiCommand(),
			versionCommand(),
		},
	}
}

func versionCommand() *commandSpec {
	return &commandSpec{
		Name:   "version",
		Short:  "Print the build branch, commit, and time",
		Effect: effectReadOnly,
		Long:   "Prints the build metadata of this binary. Talks to no server.",
		Examples: []exampleSpec{
			{Description: "Show which build this is.", Command: "plainq version"},
		},
		Run: func(_ *scotty.Command, _ []string) error {
			fmt.Printf("Built from: %s [%s]\n", Branch, Commit)
			fmt.Printf("Built on: %s\n", BuildTime)
			fmt.Printf("Built time: %v\n", time.Now().UTC())

			return nil
		},
	}
}
