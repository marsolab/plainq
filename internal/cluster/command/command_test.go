package command

import (
	"errors"
	"testing"
	"time"

	"github.com/maxatome/go-testdeep/td"
)

func TestRoundTrip(t *testing.T) {
	cases := map[string]Command{
		"send with ids": {
			Op:        OpSend,
			Timestamp: time.Date(2026, 7, 26, 12, 0, 0, 123456789, time.UTC).UnixNano(),
			IDs:       []string{"01J000000000000000000001", "01J000000000000000000002"},
			Payload:   []byte{0x0a, 0x05, 'h', 'e', 'l', 'l', 'o'},
		},
		"receive with no ids": {
			Op:        OpReceive,
			Timestamp: 1,
			Payload:   []byte{0x01},
		},
		"topic command with a target": {
			Op:        OpUnsubscribe,
			Timestamp: 42,
			Target:    "topic-1",
			IDs:       []string{"sub-1"},
		},
		"sweep carries nothing but a target": {
			Op:        OpSweep,
			Timestamp: 99,
			Target:    "queue-1",
		},
		"empty payload and no ids": {
			Op:        OpPurgeQueue,
			Timestamp: 7,
		},
	}

	for name, cmd := range cases {
		t.Run(name, func(t *testing.T) {
			encoded, err := cmd.Encode()
			td.Require(t).CmpNoError(err)

			decoded, decodeErr := Decode(encoded)
			td.Require(t).CmpNoError(decodeErr)

			td.Cmp(t, decoded.Op, cmd.Op)
			td.Cmp(t, decoded.Timestamp, cmd.Timestamp)
			td.Cmp(t, decoded.Target, cmd.Target)
			td.Cmp(t, decoded.IDs, td.Lax(cmd.IDs))
			td.Cmp(t, decoded.Payload, td.Lax(cmd.Payload))
		})
	}
}

// The timestamp is the whole point of the envelope: it is what every replica
// uses in place of its own clock.
func TestTimeRoundTrips(t *testing.T) {
	stamp := time.Date(2026, 7, 26, 12, 0, 0, 123456789, time.UTC)

	encoded, err := (&Command{Op: OpSend, Timestamp: stamp.UnixNano()}).Encode()
	td.Require(t).CmpNoError(err)

	decoded, decodeErr := Decode(encoded)
	td.Require(t).CmpNoError(decodeErr)

	td.Cmp(t, decoded.Time().Equal(stamp), true)
	td.Cmp(t, decoded.Time().Location(), time.UTC)
}

func TestEncodeRejectsInvalidOp(t *testing.T) {
	_, err := (&Command{Op: OpUnknown}).Encode()
	td.CmpError(t, err)

	_, err = (&Command{Op: Op(200)}).Encode()
	td.CmpError(t, err)
}

func TestDecodeRejectsGarbage(t *testing.T) {
	cases := map[string]struct {
		raw  []byte
		want error
	}{
		"too short":     {raw: []byte{'P'}, want: ErrShortBuffer},
		"bad magic":     {raw: []byte{'X', 'Q', 1, 1, 0, 0, 0, 0, 0, 0, 0, 0}, want: ErrBadMagic},
		"future format": {raw: []byte{'P', 'Q', 99, 1, 0, 0, 0, 0, 0, 0, 0, 0}, want: ErrVersion},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(tc.raw)

			td.Require(t).CmpError(err)
			td.Cmp(t, errors.Is(err, tc.want), true)
		})
	}
}

// An op this build does not know is not skippable: applying the entries around
// it would leave this replica quietly different from the rest of the cluster.
func TestDecodeRejectsUnknownOp(t *testing.T) {
	raw := []byte{'P', 'Q', Version, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	_, err := Decode(raw)

	td.Require(t).CmpError(err)
	td.Cmp(t, err.Error(), td.Contains("unknown op"))
}

// A log entry truncated mid-field must be an error, not a partially populated
// command that gets applied.
func TestDecodeRejectsTruncatedEntries(t *testing.T) {
	cmd := Command{
		Op:        OpSend,
		Timestamp: 1,
		Target:    "queue-1",
		IDs:       []string{"a", "b"},
		Payload:   []byte("payload"),
	}

	encoded, err := cmd.Encode()
	td.Require(t).CmpNoError(err)

	for cut := 1; cut < len(encoded); cut++ {
		_, decodeErr := Decode(encoded[:cut])
		td.Cmp(t, decodeErr, td.Not(nil), "a %d-byte prefix must not decode", cut)
	}
}

func TestOpNames(t *testing.T) {
	// Op names end up in metric labels and log lines, so a new op without a
	// name would silently become "unknown" in an operator's dashboard.
	for op := OpCreateQueue; op < opMax; op++ {
		td.Cmp(t, op.Valid(), true)
		td.Cmp(t, op.String(), td.Not("unknown"), "op %d needs a name", op)
	}

	td.Cmp(t, OpUnknown.Valid(), false)
	td.Cmp(t, OpUnknown.String(), "unknown")
	td.Cmp(t, opMax.Valid(), false)
}

// Encoding has to be a pure function of the command: the same command produces
// the same bytes, because two nodes comparing entries must agree.
func TestEncodingIsStable(t *testing.T) {
	cmd := Command{
		Op:        OpSend,
		Timestamp: 1234567890,
		Target:    "queue-1",
		IDs:       []string{"a", "b", "c"},
		Payload:   []byte("body"),
	}

	first, err := cmd.Encode()
	td.Require(t).CmpNoError(err)

	second, secondErr := cmd.Encode()
	td.Require(t).CmpNoError(secondErr)

	td.Cmp(t, first, second)
}

func TestDecodeRejectsImplausibleLengths(t *testing.T) {
	// A length prefix claiming half a terabyte is corruption, and it must
	// become an error rather than an allocation the process cannot satisfy.
	raw := []byte{'P', 'Q', Version, byte(OpSend), 0, 0, 0, 0, 0, 0, 0, 0}
	raw = append(raw, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f)

	_, err := Decode(raw)

	td.Require(t).CmpError(err)
	td.Cmp(t, errors.Is(err, ErrFieldTooLarge) || errors.Is(err, ErrShortBuffer), true)
}
