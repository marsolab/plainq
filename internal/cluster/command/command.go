// Package command defines the entries that go into the consensus log.
//
// A command is a queue write with every ambiguity already resolved. The leader
// decides — once — what the message ids are and what time it is; the log
// carries those decisions; every replica applies them. Nothing downstream of
// this package is allowed to call time.Now or mint an id, because two nodes
// doing that independently is how replicas diverge.
package command

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// magic marks a PlainQ command. It costs two bytes and turns "the cluster is
// behaving strangely" into "this log entry is not one of ours".
var magic = [2]byte{'P', 'Q'}

// Version is the encoding version. A node refuses an entry it does not
// understand rather than guessing at its meaning.
const Version uint8 = 1

// maxFieldLen caps any single length-prefixed field. It exists to turn a
// corrupt length into an error instead of an allocation the process cannot
// satisfy.
const maxFieldLen = 512 << 20

// Errors returned when decoding a malformed entry.
var (
	// ErrShortBuffer means the entry ended in the middle of a field.
	ErrShortBuffer = errors.New("command: truncated entry")

	// ErrBadMagic means the entry is not a PlainQ command.
	ErrBadMagic = errors.New("command: bad magic")

	// ErrVersion means the entry was written by a newer PlainQ.
	ErrVersion = errors.New("command: unsupported encoding version")

	// ErrFieldTooLarge means a length prefix is implausible.
	ErrFieldTooLarge = errors.New("command: field length out of range")
)

// Op identifies what a command does.
type Op uint8

// The operations that can be replicated. Values are wire format: append, never
// renumber.
const (
	// OpUnknown is the zero value and is never valid on the wire.
	OpUnknown Op = 0

	// OpCreateQueue creates a queue. IDs[0] is the queue id.
	OpCreateQueue Op = 1

	// OpDeleteQueue drops a queue.
	OpDeleteQueue Op = 2

	// OpPurgeQueue removes every message from a queue.
	OpPurgeQueue Op = 3

	// OpSend enqueues messages. IDs holds one message id per message, in
	// request order.
	OpSend Op = 4

	// OpReceive claims messages. Timestamp is the instant the visibility
	// predicate is evaluated against.
	OpReceive Op = 5

	// OpDelete acknowledges messages.
	OpDelete Op = 6

	// OpCreateTopic creates a pub/sub topic. IDs[0] is the topic id.
	OpCreateTopic Op = 7

	// OpDeleteTopic drops a topic. Target is the topic id.
	OpDeleteTopic Op = 8

	// OpSubscribe attaches a queue to a topic. Target is the topic id and
	// IDs[0] is the subscription id.
	OpSubscribe Op = 9

	// OpUnsubscribe detaches a subscription. Target is the topic id, IDs[0]
	// the subscription id.
	OpUnsubscribe Op = 10

	// OpPublish fans a message out to a topic's subscribers. Target is the
	// topic id; IDs holds a message id per (subscriber, message) pair, in
	// subscriber-then-message order.
	OpPublish Op = 11

	// OpSweep runs garbage collection for one queue. Target is the queue id
	// and Timestamp is the cutoff. Only the leader proposes these.
	OpSweep Op = 12

	// opMax is one past the last valid op, for validation.
	opMax Op = 13
)

// opNames is the op vocabulary as it appears in logs and metric labels.
var opNames = map[Op]string{
	OpCreateQueue: "create_queue",
	OpDeleteQueue: "delete_queue",
	OpPurgeQueue:  "purge_queue",
	OpSend:        "send",
	OpReceive:     "receive",
	OpDelete:      "delete",
	OpCreateTopic: "create_topic",
	OpDeleteTopic: "delete_topic",
	OpSubscribe:   "subscribe",
	OpUnsubscribe: "unsubscribe",
	OpPublish:     "publish",
	OpSweep:       "sweep",
}

// String renders the op for logs and metrics labels.
func (o Op) String() string {
	if name, known := opNames[o]; known {
		return name
	}

	return "unknown"
}

// Valid reports whether the op is one this build knows how to apply.
func (o Op) Valid() bool { return o > OpUnknown && o < opMax }

// Command is one entry in the consensus log.
type Command struct {
	// Op is what to do.
	Op Op

	// Timestamp is the leader's wall clock at the moment it proposed the
	// command, in Unix nanoseconds. Replicas use it wherever storage would
	// otherwise read its own clock.
	Timestamp int64

	// Target names the object a command acts on when the payload does not —
	// a topic id, a queue id for a sweep.
	Target string

	// IDs are the identifiers the leader generated. Their meaning is per-op
	// and documented on the op.
	IDs []string

	// Payload is the operation's request, encoded by the caller. Queue
	// operations carry a vtproto-marshaled schema message; pub/sub
	// operations carry JSON, because their request types are plain structs.
	Payload []byte
}

// Time returns the command's timestamp as a UTC time.
func (c *Command) Time() time.Time { return time.Unix(0, c.Timestamp).UTC() }

// Encode renders the command for the log.
func (c *Command) Encode() ([]byte, error) {
	if !c.Op.Valid() {
		return nil, fmt.Errorf("command: refusing to encode invalid op %d", c.Op)
	}

	size := len(magic) + 1 + 1 + 8 +
		binary.MaxVarintLen64 + len(c.Target) +
		binary.MaxVarintLen64 +
		binary.MaxVarintLen64 + len(c.Payload)

	for _, id := range c.IDs {
		size += binary.MaxVarintLen64 + len(id)
	}

	buf := make([]byte, 0, size)

	buf = append(buf, magic[0], magic[1], Version, byte(c.Op))
	buf = binary.BigEndian.AppendUint64(buf, uint64(c.Timestamp)) //nolint:gosec // a wall clock before 1970 is not a case we serve.
	buf = appendBytes(buf, []byte(c.Target))

	buf = binary.AppendUvarint(buf, uint64(len(c.IDs)))
	for _, id := range c.IDs {
		buf = appendBytes(buf, []byte(id))
	}

	buf = appendBytes(buf, c.Payload)

	return buf, nil
}

// Decode parses a log entry.
//
//nolint:cyclop // Every branch is one malformed-entry check, and each has its own error.
func Decode(raw []byte) (*Command, error) {
	if len(raw) < len(magic)+2+8 {
		return nil, ErrShortBuffer
	}

	if raw[0] != magic[0] || raw[1] != magic[1] {
		return nil, ErrBadMagic
	}

	if raw[2] != Version {
		return nil, fmt.Errorf("%w: entry is version %d, this node speaks %d", ErrVersion, raw[2], Version)
	}

	cmd := Command{Op: Op(raw[3])}

	if !cmd.Op.Valid() {
		return nil, fmt.Errorf("command: unknown op %d — is this node older than the cluster?", raw[3])
	}

	rest := raw[4:]

	cmd.Timestamp = int64(binary.BigEndian.Uint64(rest[:8])) //nolint:gosec // round-trips the encode above.
	rest = rest[8:]

	target, rest, targetErr := readBytes(rest)
	if targetErr != nil {
		return nil, targetErr
	}

	cmd.Target = string(target)

	count, read := binary.Uvarint(rest)
	if read <= 0 {
		return nil, ErrShortBuffer
	}

	if count > maxFieldLen {
		return nil, ErrFieldTooLarge
	}

	rest = rest[read:]

	if count > 0 {
		cmd.IDs = make([]string, 0, min(count, 1024))

		for range count {
			var (
				id  []byte
				err error
			)

			id, rest, err = readBytes(rest)
			if err != nil {
				return nil, err
			}

			cmd.IDs = append(cmd.IDs, string(id))
		}
	}

	payload, _, payloadErr := readBytes(rest)
	if payloadErr != nil {
		return nil, payloadErr
	}

	// An absent payload decodes back to nil rather than to an empty slice, so
	// a decoded command compares equal to the one that was encoded.
	if len(payload) > 0 {
		cmd.Payload = payload
	}

	return &cmd, nil
}

func appendBytes(buf, value []byte) []byte {
	buf = binary.AppendUvarint(buf, uint64(len(value)))

	return append(buf, value...)
}

//nolint:nonamedreturns // three same-typed results; the names are the documentation.
func readBytes(buf []byte) (value, rest []byte, err error) {
	length, read := binary.Uvarint(buf)
	if read <= 0 {
		return nil, nil, ErrShortBuffer
	}

	if length > maxFieldLen {
		return nil, nil, ErrFieldTooLarge
	}

	buf = buf[read:]

	if uint64(len(buf)) < length {
		return nil, nil, ErrShortBuffer
	}

	return buf[:length], buf[length:], nil
}
