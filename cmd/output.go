package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/servekit/idkit"
)

// validateQueueID checks that id is a well-formed queue identifier. PlainQ
// stores queue IDs as upper-cased XIDs (see servekit idkit.XID), while the
// underlying xid parser only accepts the lower-cased form — so we validate the
// normalized value while leaving the caller's original id untouched for the
// request.
func validateQueueID(id string) error {
	if err := idkit.ValidateXID(strings.ToLower(id)); err != nil {
		return fmt.Errorf("validate queue id: %w", err)
	}

	return nil
}

const (
	// initMessageBufBytes is the initial scanner buffer for reading bodies.
	initMessageBufBytes = 64 * 1024

	// maxMessageLineBytes caps a single newline-delimited message body.
	maxMessageLineBytes = 4 * 1024 * 1024
)

// encodeJSON writes v to w as indented JSON. It is the single place the CLI
// renders machine-readable output so that the shape is consistent for AI
// agents and scripts.
func encodeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}

	return nil
}

// stringSliceFlag is a flag.Value that accumulates repeated occurrences of a
// flag into a slice, e.g. -message a -message b => ["a", "b"].
type stringSliceFlag []string

// String implements flag.Value.
func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }

// Set implements flag.Value by appending each provided value.
func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)

	return nil
}

// collectSendMessages builds the message list for a send request from the
// repeated -message flags and/or a -file source ("-" means stdin). It returns
// an error when no message bodies are provided.
func collectSendMessages(messages []string, file string) ([]*v1.SendMessage, error) {
	bodies := make([]*v1.SendMessage, 0, len(messages))

	for _, msg := range messages {
		bodies = append(bodies, &v1.SendMessage{Body: []byte(msg)})
	}

	if file != "" {
		fileBodies, err := readMessageBodies(file)
		if err != nil {
			return nil, err
		}

		bodies = append(bodies, fileBodies...)
	}

	if len(bodies) == 0 {
		return nil, errors.New("no messages: provide -message and/or -file")
	}

	return bodies, nil
}

// readMessageBodies reads newline-delimited message bodies from a file path or
// from stdin when path is "-".
func readMessageBodies(path string) ([]*v1.SendMessage, error) {
	reader := io.Reader(os.Stdin)

	if path != "-" {
		file, openErr := os.Open(path)
		if openErr != nil {
			return nil, fmt.Errorf("open message file: %w", openErr)
		}
		defer file.Close()

		reader = file
	}

	bodies := make([]*v1.SendMessage, 0)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, initMessageBufBytes), maxMessageLineBytes)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		bodies = append(bodies, &v1.SendMessage{Body: bytes.Clone(line)})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read message file: %w", err)
	}

	return bodies, nil
}

// printReceivedText renders received messages as tab-separated id/body lines.
func printReceivedText(w io.Writer, messages []*v1.ReceiveMessage) {
	for _, msg := range messages {
		fmt.Fprintf(w, "%s\t%s\n", msg.GetId(), msg.GetBody())
	}
}

// evictionPolicyString returns a human-readable name for an eviction policy.
func evictionPolicyString(policy v1.EvictionPolicy) string {
	switch policy {
	case v1.EvictionPolicy_EVICTION_POLICY_DROP:
		return "drop"
	case v1.EvictionPolicy_EVICTION_POLICY_DEAD_LETTER:
		return "dead-letter"
	case v1.EvictionPolicy_EVICTION_POLICY_REORDER:
		return "reorder"
	case v1.EvictionPolicy_EVICTION_POLICY_UNSPECIFIED:
		return "unspecified"
	default:
		return "unspecified"
	}
}

// printQueueText renders a single queue description as an aligned key/value
// block for human consumption.
func printQueueText(w io.Writer, queue *v1.DescribeQueueResponse) {
	fmt.Fprintf(w, "ID:                  %s\n", queue.GetQueueId())
	fmt.Fprintf(w, "Name:                %s\n", queue.GetQueueName())

	if created := queue.GetCreatedAt(); created != nil {
		fmt.Fprintf(w, "Created:             %s\n", created.AsTime().Format("2006-01-02 15:04:05 MST"))
	}

	fmt.Fprintf(w, "Retention (s):       %d\n", queue.GetRetentionPeriodSeconds())
	fmt.Fprintf(w, "Visibility (s):      %d\n", queue.GetVisibilityTimeoutSeconds())
	fmt.Fprintf(w, "Max receive:         %d\n", queue.GetMaxReceiveAttempts())
	fmt.Fprintf(w, "Eviction policy:     %s\n", evictionPolicyString(queue.GetEvictionPolicy()))

	if dlq := queue.GetDeadLetterQueueId(); dlq != "" {
		fmt.Fprintf(w, "Dead-letter queue:   %s\n", dlq)
	}
}
