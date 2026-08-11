package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/heartwilltell/scotty"
	"github.com/marsolab/plainq/internal/cluster"
)

const (
	// flagHTTPAddr names the admin API address the cluster commands talk to.
	// The cluster API is HTTP rather than gRPC because it is an operator
	// surface, not a data-plane one.
	flagHTTPAddr = "http.addr"

	// defaultHTTPAddr is where a local server serves its admin API.
	defaultHTTPAddr = "http://localhost:8081"

	// flagToken names the bearer token flag. Cluster routes are
	// administrator-only, so a server with auth on needs one.
	flagToken = "token"

	// envClusterToken supplies the bearer token when the flag is omitted.
	envClusterToken = "PLAINQ_TOKEN"

	// clusterRequestTimeout bounds a cluster CLI call.
	clusterRequestTimeout = 30 * time.Second
)

// clusterCommand groups the operator-facing cluster subcommands.
func clusterCommand() *commandSpec {
	return &commandSpec{
		Name:   "cluster",
		Short:  "Inspect and administer the cluster",
		Effect: effectReadOnly,
		Long: "Operator commands for a clustered deployment. Unlike the queue commands,\n" +
			"these talk to the admin HTTP API at -" + flagHTTPAddr + " rather than to gRPC,\n" +
			"and they are administrator-only: a server with auth enabled needs -" + flagToken + ".",
		Subcommands: []*commandSpec{
			clusterStatusCommand(),
			clusterMembersCommand(),
			clusterJoinCommand(),
			clusterLeaveCommand(),
			clusterSnapshotCommand(),
		},
	}
}

// clusterFlags is the set every cluster subcommand shares.
type clusterFlags struct {
	addr    string
	token   string
	jsonOut bool
}

func (c *clusterFlags) register(flags *scotty.FlagSet) {
	flags.StringVar(&c.addr, flagHTTPAddr, defaultHTTPAddr,
		"address of the PlainQ admin HTTP API",
	)

	// The default stays empty on purpose: putting the environment's token here
	// would print a live credential in help output and in the schema dump.
	flags.StringVar(&c.token, flagToken, "",
		"bearer token for the admin API (falls back to $"+envClusterToken+")",
	)

	flags.BoolVar(&c.jsonOut, flagJSON, false,
		flagJSONUsage,
	)
}

// bearerToken returns the token to authenticate with, preferring the flag over
// the environment.
func (c *clusterFlags) bearerToken() string {
	if c.token != "" {
		return c.token
	}

	return os.Getenv(envClusterToken)
}

func clusterStatusCommand() *commandSpec {
	var flags clusterFlags

	return &commandSpec{
		Name:   "status",
		Short:  "Show this node's view of the cluster",
		Effect: effectReadOnly,
		Long: "Reports the node's role, the current leader, the consensus term, and the\n" +
			"member list as this node sees it. Answers are per-node: during a partition\n" +
			"two nodes can legitimately disagree.",
		Examples: []exampleSpec{
			{Description: "Check whether this node is the leader.", Command: "plainq cluster status"},
		},
		SetFlags: flags.register,
		Run: func(_ *scotty.Command, _ []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			var status cluster.Status

			if err := clusterCall(ctx, &flags, http.MethodGet, "/api/v1/cluster", nil, &status); err != nil {
				return err
			}

			if flags.jsonOut {
				return encodeJSON(os.Stdout, status)
			}

			printClusterStatus(os.Stdout, status)

			return nil
		},
	}
}

func clusterMembersCommand() *commandSpec {
	var flags clusterFlags

	return &commandSpec{
		Name:   "members",
		Short:  "List cluster members",
		Effect: effectReadOnly,
		Long: "Lists every node in the cluster with its identity, address, and whether it\n" +
			"votes in elections.",
		Examples: []exampleSpec{
			{Description: "List the members.", Command: "plainq cluster members"},
			{
				Description: "Extract the node identities.",
				Command:     "plainq cluster members -json | jq -r '.[].id'",
			},
		},
		SetFlags: flags.register,
		Run: func(_ *scotty.Command, _ []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			var status cluster.Status

			if err := clusterCall(ctx, &flags, http.MethodGet, "/api/v1/cluster", nil, &status); err != nil {
				return err
			}

			if flags.jsonOut {
				return encodeJSON(os.Stdout, status.Members)
			}

			printClusterMembers(os.Stdout, status)

			return nil
		},
	}
}

func clusterJoinCommand() *commandSpec {
	var (
		flags    clusterFlags
		nodeID   string
		addr     string
		nonVoter bool
	)

	return &commandSpec{
		Name:   "join",
		Short:  "Add a node to the cluster",
		Effect: effectMutating,
		Long: "Adds a node to the consensus group. Must be sent to the current leader;\n" +
			`run "plainq cluster status" first if you are not sure which node that is.` + "\n\n" +
			"Both -node-id and -addr are required.",
		Examples: []exampleSpec{
			{
				Description: "Add a voting node.",
				Command:     "plainq cluster join -node-id=node-2 -addr=10.0.0.2:9080",
			},
			{
				Description: "Add a read replica that does not vote in elections.",
				Command:     "plainq cluster join -node-id=node-3 -addr=10.0.0.3:9080 -non-voter",
			},
		},
		SetFlags: func(f *scotty.FlagSet) {
			flags.register(f)

			f.StringVar(&nodeID, "node-id", "",
				"identity of the node to add",
			)

			f.StringVar(&addr, "addr", "",
				"cluster address of the node to add",
			)

			f.BoolVar(&nonVoter, "non-voter", false,
				"add the node as a replica that does not vote",
			)
		},
		Run: func(_ *scotty.Command, _ []string) error {
			if nodeID == "" || addr == "" {
				return usagef("both -node-id and -addr are required")
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			body := map[string]any{"nodeId": nodeID, "address": addr, "nonVoter": nonVoter}

			var status cluster.Status

			if err := clusterCall(ctx, &flags, http.MethodPost, "/api/v1/cluster/members", body, &status); err != nil {
				return err
			}

			if flags.jsonOut {
				return encodeJSON(os.Stdout, status)
			}

			fmt.Fprintf(os.Stdout, "Added %s (%s) to the cluster.\n\n", nodeID, addr)
			printClusterMembers(os.Stdout, status)

			return nil
		},
	}
}

func clusterLeaveCommand() *commandSpec {
	var (
		flags  clusterFlags
		nodeID string
	)

	return &commandSpec{
		Name:   "leave",
		Short:  "Remove a node from the cluster",
		Effect: effectDestructive,
		Long: "Removes a node from the consensus group. Removing enough nodes to lose the\n" +
			"quorum stops the cluster from serving, so check the member count first.\n\n" +
			"-node-id is required.",
		Examples: []exampleSpec{
			{
				Description: "Remove a node that has been decommissioned.",
				Command:     "plainq cluster leave -node-id=node-3",
			},
		},
		SetFlags: func(f *scotty.FlagSet) {
			flags.register(f)

			f.StringVar(&nodeID, "node-id", "",
				"identity of the node to remove",
			)
		},
		Run: func(_ *scotty.Command, _ []string) error {
			if nodeID == "" {
				return usagef("-node-id is required")
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			var status cluster.Status

			path := "/api/v1/cluster/members/" + nodeID

			if err := clusterCall(ctx, &flags, http.MethodDelete, path, nil, &status); err != nil {
				return err
			}

			if flags.jsonOut {
				return encodeJSON(os.Stdout, status)
			}

			fmt.Fprintf(os.Stdout, "Removed %s from the cluster.\n\n", nodeID)
			printClusterMembers(os.Stdout, status)

			return nil
		},
	}
}

func clusterSnapshotCommand() *commandSpec {
	var flags clusterFlags

	return &commandSpec{
		Name:   "snapshot",
		Short:  "Force a state snapshot, compacting the consensus log",
		Effect: effectMutating,
		Long: "Writes a snapshot of the replicated state and truncates the consensus log\n" +
			"up to that point, which shortens recovery for a node that restarts. Queue\n" +
			"data is unaffected.",
		Examples: []exampleSpec{
			{Description: "Compact the log now.", Command: "plainq cluster snapshot"},
		},
		SetFlags: flags.register,
		Run: func(_ *scotty.Command, _ []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()

			if err := clusterCall(ctx, &flags, http.MethodPost, "/api/v1/cluster/snapshot", nil, nil); err != nil {
				return err
			}

			fmt.Fprintln(os.Stdout, "Snapshot written.")

			return nil
		},
	}
}

// clusterCall performs one admin API request.
//
//nolint:cyclop // A request builder is one branch per optional part of the request.
func clusterCall(ctx context.Context, flags *clusterFlags, method, path string, body, out any) error {
	ctx, cancel := context.WithTimeout(ctx, clusterRequestTimeout)
	defer cancel()

	var reader io.Reader

	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}

		reader = bytes.NewReader(encoded)
	}

	req, reqErr := http.NewRequestWithContext(ctx, method, clusterBaseURL(flags.addr)+path, reader)
	if reqErr != nil {
		return fmt.Errorf("build request: %w", reqErr)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if token := flags.bearerToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, doErr := http.DefaultClient.Do(req)
	if doErr != nil {
		return fmt.Errorf("call %s: %w", flags.addr, doErr)
	}

	defer func() {
		//nolint:errcheck // draining is best-effort connection reuse.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	payload, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if readErr != nil {
		return fmt.Errorf("read response: %w", readErr)
	}

	if resp.StatusCode != http.StatusOK {
		return clusterAPIError(resp.StatusCode, payload)
	}

	if out == nil {
		return nil
	}

	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}

// clusterAPIError renders a failed call the way an operator needs to read it.
// A "not the leader" answer carries the leader's address, so the next command
// is obvious rather than a guess.
//
// A 4xx that is not a redirect to the leader is the caller's mistake, so it is
// reported as a usage error. That keeps the admin API consistent with the data
// plane, where a rejected request also exits 2 rather than looking like a
// transient failure worth retrying. "Not the leader" is deliberately excluded:
// retrying it against the address in the message is exactly the right move.
func clusterAPIError(status int, payload []byte) error {
	var body struct {
		Error         string `json:"error"`
		LeaderAddress string `json:"leaderAddress"`
		LeaderID      string `json:"leaderId"`
	}

	if err := json.Unmarshal(payload, &body); err != nil || body.Error == "" {
		message := fmt.Sprintf("cluster API returned %d: %s", status, strings.TrimSpace(string(payload)))

		if isClientError(status) {
			return usagef("%s", message)
		}

		return errors.New(message)
	}

	if body.LeaderID != "" {
		return fmt.Errorf("%s — the leader is %s at %s", body.Error, body.LeaderID, body.LeaderAddress)
	}

	if isClientError(status) {
		return usagef("%s", body.Error)
	}

	return errors.New(body.Error)
}

// isClientError reports whether status blames the request rather than the
// server.
func isClientError(status int) bool {
	return status >= http.StatusBadRequest && status < http.StatusInternalServerError
}

func clusterBaseURL(addr string) string {
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		return strings.TrimSuffix(addr, "/")
	}

	return "http://" + strings.TrimSuffix(addr, "/")
}

func printClusterStatus(w io.Writer, status cluster.Status) {
	if !status.Enabled {
		fmt.Fprintln(w, "Clustering is not enabled on this server.")

		return
	}

	health := "degraded"
	if status.Healthy {
		health = "healthy"
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	fmt.Fprintf(tw, "Node:\t%s (%s)\n", status.NodeID, status.State)
	fmt.Fprintf(tw, "Leader:\t%s\n", orNone(status.LeaderID))
	fmt.Fprintf(tw, "Term:\t%d\n", status.Term)
	fmt.Fprintf(tw, "Log:\tcommit %d, applied %d, last %d\n",
		status.CommitIndex, status.AppliedIndex, status.LastIndex,
	)
	fmt.Fprintf(tw, "Quorum:\t%d of %d voters (%s)\n", status.Quorum, status.Voters, health)

	if status.LastContact != "" {
		fmt.Fprintf(tw, "Last contact:\t%s ago\n", status.LastContact)
	}

	fmt.Fprintf(tw, "Commands:\t%d applied, %d failed\n", status.AppliedCommands, status.FailedCommands)

	_ = tw.Flush()

	fmt.Fprintln(w)

	printClusterMembers(w, status)
}

func printClusterMembers(w io.Writer, status cluster.Status) {
	if len(status.Members) == 0 {
		fmt.Fprintln(w, "No members.")

		return
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	fmt.Fprintln(tw, "ID\tADDRESS\tSUFFRAGE\tREACHABLE\tROLE")

	for _, member := range status.Members {
		role := ""

		switch {
		case member.Leader && member.Self:
			role = "leader, this node"

		case member.Leader:
			role = "leader"

		case member.Self:
			role = "this node"
		}

		suffrage := string(member.Suffrage)
		if suffrage == "" {
			suffrage = "not admitted"
		}

		fmt.Fprintf(tw, "%s\t%s\t%s\t%t\t%s\n",
			member.ID, member.Addr, suffrage, member.Reachable, role,
		)
	}

	_ = tw.Flush()
}

func orNone(value string) string {
	if value == "" {
		return "(none — election in progress)"
	}

	return value
}
