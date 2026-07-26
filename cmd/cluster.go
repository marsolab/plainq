package main

import (
	"bytes"
	"context"
	"encoding/json"
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

	// clusterRequestTimeout bounds a cluster CLI call.
	clusterRequestTimeout = 30 * time.Second
)

// clusterCommand groups the operator-facing cluster subcommands.
func clusterCommand() *scotty.Command {
	cmd := scotty.Command{
		Name:  "cluster",
		Short: "Inspect and administer the cluster",
	}

	cmd.AddSubcommands(
		clusterStatusCommand(),
		clusterMembersCommand(),
		clusterJoinCommand(),
		clusterLeaveCommand(),
		clusterSnapshotCommand(),
	)

	return &cmd
}

// clusterFlags is the set every cluster subcommand shares.
type clusterFlags struct {
	addr    string
	token   string
	jsonOut bool
}

func (c *clusterFlags) register(flags *scotty.FlagSet) {
	flags.StringVar(&c.addr, flagHTTPAddr, defaultHTTPAddr,
		"sets the PlainQ admin API address",
	)

	flags.StringVar(&c.token, flagToken, os.Getenv("PLAINQ_TOKEN"),
		"bearer token for the admin API (defaults to $PLAINQ_TOKEN)",
	)

	flags.BoolVar(&c.jsonOut, flagJSON, false,
		flagJSONUsage,
	)
}

func clusterStatusCommand() *scotty.Command {
	var flags clusterFlags

	cmd := scotty.Command{
		Name:     "status",
		Short:    "Show this node's view of the cluster",
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

	return &cmd
}

func clusterMembersCommand() *scotty.Command {
	var flags clusterFlags

	cmd := scotty.Command{
		Name:     "members",
		Short:    "List cluster members",
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

	return &cmd
}

func clusterJoinCommand() *scotty.Command {
	var (
		flags    clusterFlags
		nodeID   string
		addr     string
		nonVoter bool
	)

	cmd := scotty.Command{
		Name:  "join",
		Short: "Add a node to the cluster",
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
				return fmt.Errorf("both -node-id and -addr are required")
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

	return &cmd
}

func clusterLeaveCommand() *scotty.Command {
	var (
		flags  clusterFlags
		nodeID string
	)

	cmd := scotty.Command{
		Name:  "leave",
		Short: "Remove a node from the cluster",
		SetFlags: func(f *scotty.FlagSet) {
			flags.register(f)

			f.StringVar(&nodeID, "node-id", "",
				"identity of the node to remove",
			)
		},
		Run: func(_ *scotty.Command, _ []string) error {
			if nodeID == "" {
				return fmt.Errorf("-node-id is required")
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

	return &cmd
}

func clusterSnapshotCommand() *scotty.Command {
	var flags clusterFlags

	cmd := scotty.Command{
		Name:     "snapshot",
		Short:    "Force a state snapshot, compacting the consensus log",
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

	return &cmd
}

// clusterCall performs one admin API request.
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

	if flags.token != "" {
		req.Header.Set("Authorization", "Bearer "+flags.token)
	}

	resp, doErr := http.DefaultClient.Do(req)
	if doErr != nil {
		return fmt.Errorf("call %s: %w", flags.addr, doErr)
	}

	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

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
func clusterAPIError(status int, payload []byte) error {
	var body struct {
		Error         string `json:"error"`
		LeaderAddress string `json:"leaderAddress"`
		LeaderID      string `json:"leaderId"`
	}

	if err := json.Unmarshal(payload, &body); err != nil || body.Error == "" {
		return fmt.Errorf("cluster API returned %d: %s", status, strings.TrimSpace(string(payload)))
	}

	if body.LeaderID != "" {
		return fmt.Errorf("%s — the leader is %s at %s", body.Error, body.LeaderID, body.LeaderAddress)
	}

	return fmt.Errorf("%s", body.Error)
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
