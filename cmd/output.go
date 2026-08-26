package main

import (
	"bufio"
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
		return usagef("invalid queue id %q: %w"+
			` (expected the 20-character id printed by "plainq create" or "plainq list", not a queue name)`,
			id, err,
		)
	}

	return nil
}

const (
	// initMessageBufBytes is the buffered reader size for message bodies.
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

// collectMessageBodies combines repeated -message values with an optional
// newline-delimited file source. Explicit flag values are kept verbatim,
// including an empty string; empty file lines are ignored.
func collectMessageBodies(messages []string, file string, stdin io.Reader) ([][]byte, error) {
	bodies := make([][]byte, 0, len(messages))

	for _, msg := range messages {
		bodies = append(bodies, []byte(msg))
	}

	if file != "" {
		fileBodies, err := readMessageBodyLines(file, stdin)
		if err != nil {
			return nil, err
		}

		bodies = append(bodies, fileBodies...)
	}

	// A send with nothing to send is a mistake in the command line, not a
	// runtime failure: retrying it unchanged can never succeed, so it has to
	// carry the usage exit code that tells a caller to stop retrying.
	if len(bodies) == 0 {
		return nil, usagef("no messages: provide -message and/or -file")
	}

	return bodies, nil
}

// readMessageBodyLines reads newline-delimited message bodies from a file path
// or from stdin when path is "-". One line is capped at maxMessageLineBytes;
// the reader keeps at most one extra byte so oversized input fails without an
// unbounded allocation.
func readMessageBodyLines(path string, stdin io.Reader) (_ [][]byte, err error) {
	reader := stdin

	if path != "-" {
		file, openErr := os.Open(path)
		if openErr != nil {
			return nil, fmt.Errorf("open message file: %w", openErr)
		}
		defer func() {
			if closeErr := file.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close message file: %w", closeErr))
			}
		}()

		reader = file
	}

	if reader == nil {
		return nil, usagef("message input is unavailable")
	}

	bodies := make([][]byte, 0)
	buffered := bufio.NewReaderSize(reader, initMessageBufBytes)

	for {
		line, readErr := readMessageBodyLine(buffered)
		if errors.Is(readErr, io.EOF) {
			return bodies, nil
		}

		if readErr != nil {
			return nil, fmt.Errorf("read message file: %w", readErr)
		}

		if len(line) == 0 {
			continue
		}

		bodies = append(bodies, line)
	}
}

// readMessageBodyLine reads one line without retaining more than the accepted
// maximum plus the single byte needed to prove it is oversized.
func readMessageBodyLine(reader *bufio.Reader) ([]byte, error) {
	line := make([]byte, 0, initMessageBufBytes)

	for {
		fragment, err := reader.ReadSlice('\n')

		fragment, terminated := trimMessageLineDelimiter(fragment, err)

		remaining := maxMessageLineBytes + 1 - len(line)
		if len(fragment) > remaining {
			fragment = fragment[:remaining]
		}

		line = append(line, fragment...)

		if len(line) > maxMessageLineBytes {
			return nil, usagef("message line exceeds %d bytes", maxMessageLineBytes)
		}

		if terminated {
			return line, nil
		}

		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}

		return finishMessageBodyLine(line, err)
	}
}

func finishMessageBodyLine(line []byte, err error) ([]byte, error) {
	switch {
	case errors.Is(err, io.EOF) && len(line) > 0:
		return line, nil
	case errors.Is(err, io.EOF):
		return nil, io.EOF
	case err != nil:
		return nil, fmt.Errorf("read line: %w", err)
	default:
		return line, nil
	}
}

func trimMessageLineDelimiter(fragment []byte, err error) ([]byte, bool) {
	terminated := len(fragment) > 0 && fragment[len(fragment)-1] == '\n'
	if terminated {
		fragment = fragment[:len(fragment)-1]
	}

	if len(fragment) > 0 && fragment[len(fragment)-1] == '\r' &&
		(terminated || errors.Is(err, io.EOF)) {
		fragment = fragment[:len(fragment)-1]
	}

	return fragment, terminated
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
