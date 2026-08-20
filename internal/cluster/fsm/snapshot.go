package fsm

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	hraft "github.com/hashicorp/raft"
	"github.com/marsolab/plainq/internal/metrics"
	"github.com/marsolab/plainq/internal/server/service/queue"
)

// Snapshot stream framing. The magic and version turn "the restore produced
// nonsense" into "this is not a snapshot I can read", which is the difference
// between a diagnosable node and a mysterious one.
var snapshotMagic = [6]byte{'P', 'Q', 'S', 'N', 'A', 'P'}

// snapshotVersion is the stream format version.
const snapshotVersion uint8 = 1

// recordType tags each record in the stream. Values are wire format: append,
// never renumber.
type recordType uint8

const (
	recordQueue        recordType = 1
	recordMessage      recordType = 2
	recordTopic        recordType = 3
	recordSubscription recordType = 4
)

// restoreBatch is how many messages are installed per statement during a
// restore. It bounds the memory a restore holds regardless of how large the
// snapshot is.
const restoreBatch = 500

// maxRecordLen caps a single field, so a corrupt length is an error rather
// than an allocation the process cannot satisfy.
const maxRecordLen = 512 << 20

// Errors returned when reading a malformed snapshot.
var (
	// ErrBadSnapshot means the stream is not a PlainQ snapshot.
	ErrBadSnapshot = errors.New("fsm: not a PlainQ snapshot")

	// ErrSnapshotVersion means the snapshot was written by a newer PlainQ.
	ErrSnapshotVersion = errors.New("fsm: unsupported snapshot version")
)

// Snapshot implements raft.FSM.
//
// It pins the store's current contents and returns immediately. Raft calls
// this on the goroutine that applies the log, so anything slow here stalls
// replication; the writing out happens later, in Persist, against the pinned
// view.
func (f *FSM) Snapshot() (hraft.FSMSnapshot, error) {
	// The context outlives this call: it belongs to the pinned view, which is
	// read later, in Persist. Scoping it to Snapshot with a deferred cancel
	// hands back a view whose transaction database/sql has already rolled
	// back — the snapshot then streams nothing, and the node that receives it
	// starts empty.
	ctx, cancel := context.WithCancel(context.Background())

	view, err := f.storage.BeginSnapshot(ctx)
	if err != nil {
		cancel()

		return nil, fmt.Errorf("begin state snapshot: %w", err)
	}

	return &snapshot{view: view, cancel: cancel, logger: f.logger}, nil
}

// snapshot is a pinned view of the store, ready to be written out.
type snapshot struct {
	view   queue.StateSnapshot
	cancel context.CancelFunc
	logger *slog.Logger
}

// Persist implements raft.FSMSnapshot.
func (s *snapshot) Persist(sink hraft.SnapshotSink) error {
	started := time.Now()

	writer := newSnapshotWriter(sink)

	var persistErr error
	defer func() {
		metrics.RecordSnapshot(started, int64(writer.written&(1<<63-1)), persistErr)
	}()

	persistErr = func() error {
		if err := writer.header(); err != nil {
			cancelSink(sink, s.logger)

			return err
		}

		// The stream is written with a generous ceiling rather than the caller's
		// deadline: abandoning a half-written snapshot costs the cluster a full
		// log replay later.
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()

		if err := s.view.Stream(ctx, writer); err != nil {
			cancelSink(sink, s.logger)

			return fmt.Errorf("stream state into snapshot: %w", err)
		}

		if err := writer.flush(); err != nil {
			cancelSink(sink, s.logger)

			return err
		}

		if err := sink.Close(); err != nil {
			return fmt.Errorf("close snapshot sink: %w", err)
		}

		metrics.RecordSnapshotRecords(writer.queues, writer.messages, writer.topics, writer.subscriptions)

		s.logger.Info("Wrote cluster state snapshot",
			slog.String("id", sink.ID()),
			slog.Uint64("queues", writer.queues),
			slog.Uint64("messages", writer.messages),
			slog.String("duration", time.Since(started).String()),
		)

		return nil
	}()

	return persistErr
}

// cancelSink discards a half-written snapshot. There is nothing to do about a
// failure here beyond saying so: the snapshot has already failed.
func cancelSink(sink hraft.SnapshotSink, logger *slog.Logger) {
	if err := sink.Cancel(); err != nil {
		logger.Error("Failed to discard an incomplete snapshot",
			slog.String("id", sink.ID()),
			slog.String("error", err.Error()),
		)
	}
}

// Release implements raft.FSMSnapshot. Raft calls it whether Persist succeeded
// or not, so it is the one place guaranteed to give the pinned view back.
func (s *snapshot) Release() {
	defer s.cancel()

	if err := s.view.Release(); err != nil {
		s.logger.Error("Failed to release the snapshot view",
			slog.String("error", err.Error()),
		)
	}
}

// Restore implements raft.FSM.
//
// Raft calls it when this node is too far behind to catch up from the log —
// on a fresh node joining, or one that was down long enough for the leader to
// have compacted past it. It replaces everything the store holds.
func (f *FSM) Restore(reader io.ReadCloser) error {
	defer func() { _ = reader.Close() }()

	started := time.Now()

	var restoreErr error
	defer func() { metrics.RecordRestore(started, restoreErr) }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	restoreErr = func() error {
		if err := f.storage.BeginRestore(ctx); err != nil {
			return fmt.Errorf("begin state restore: %w", err)
		}

		committed := false
		defer func() {
			if committed {
				return
			}

			// A failed restore must leave the previous state intact. A node with
			// stale state can still be caught up; a node holding half a snapshot
			// is holding a state the cluster was never in.
			if err := f.storage.AbortRestore(ctx); err != nil {
				f.logger.Error("Failed to abort a partial state restore",
					slog.String("error", err.Error()),
				)
			}
		}()

		stats, readErr := f.readSnapshot(ctx, reader)
		if readErr != nil {
			return readErr
		}

		if err := f.storage.CommitRestore(ctx); err != nil {
			return fmt.Errorf("commit state restore: %w", err)
		}

		committed = true

		metrics.RecordRestoreRecords(stats.queues, stats.messages, stats.topics, stats.subscriptions)

		f.logger.Info("Restored cluster state from snapshot",
			slog.Uint64("queues", stats.queues),
			slog.Uint64("messages", stats.messages),
			slog.Uint64("topics", stats.topics),
			slog.Uint64("subscriptions", stats.subscriptions),
			slog.String("duration", time.Since(started).String()),
		)

		return nil
	}()

	return restoreErr
}

// snapshotStats counts what a restore installed.
type snapshotStats struct {
	queues        uint64
	messages      uint64
	topics        uint64
	subscriptions uint64
}

//nolint:cyclop,funlen,gocognit,gocyclo // Reading a tagged record stream is one branch per record type.
func (f *FSM) readSnapshot(ctx context.Context, source io.Reader) (snapshotStats, error) {
	var stats snapshotStats

	reader := bufio.NewReaderSize(source, 1<<20)

	var header [len(snapshotMagic) + 1]byte

	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return stats, fmt.Errorf("%w: %w", ErrBadSnapshot, err)
	}

	if [6]byte(header[:len(snapshotMagic)]) != snapshotMagic {
		return stats, ErrBadSnapshot
	}

	if header[len(snapshotMagic)] != snapshotVersion {
		return stats, fmt.Errorf("%w: snapshot is version %d, this node reads %d",
			ErrSnapshotVersion, header[len(snapshotMagic)], snapshotVersion,
		)
	}

	// Messages are buffered per queue so a restore installs them in batches
	// rather than one statement per message.
	pending := make([]queue.MessageState, 0, restoreBatch)

	flush := func() error {
		if len(pending) == 0 {
			return nil
		}

		if err := f.storage.RestoreMessages(ctx, pending); err != nil {
			return fmt.Errorf("restore messages: %w", err)
		}

		pending = pending[:0]

		return nil
	}

	for {
		kind, err := reader.ReadByte()
		if errors.Is(err, io.EOF) {
			if flushErr := flush(); flushErr != nil {
				return stats, flushErr
			}

			return stats, nil
		}

		if err != nil {
			return stats, fmt.Errorf("read snapshot record type: %w", err)
		}

		payload, payloadErr := readFrame(reader)
		if payloadErr != nil {
			return stats, payloadErr
		}

		switch recordType(kind) {
		case recordQueue:
			// A queue boundary flushes: RestoreMessages takes one queue's
			// messages at a time.
			if flushErr := flush(); flushErr != nil {
				return stats, flushErr
			}

			var state queue.QueueState

			if err := json.Unmarshal(payload, &state); err != nil {
				return stats, fmt.Errorf("decode queue record: %w", err)
			}

			if err := f.storage.RestoreQueue(ctx, state); err != nil {
				return stats, fmt.Errorf("restore queue %q: %w", state.ID, err)
			}

			stats.queues++

		case recordMessage:
			state, decodeErr := decodeMessage(payload)
			if decodeErr != nil {
				return stats, decodeErr
			}

			if len(pending) > 0 && pending[0].QueueID != state.QueueID {
				if flushErr := flush(); flushErr != nil {
					return stats, flushErr
				}
			}

			pending = append(pending, state)
			stats.messages++

			if len(pending) == restoreBatch {
				if flushErr := flush(); flushErr != nil {
					return stats, flushErr
				}
			}

		case recordTopic:
			if flushErr := flush(); flushErr != nil {
				return stats, flushErr
			}

			var state queue.TopicState

			if err := json.Unmarshal(payload, &state); err != nil {
				return stats, fmt.Errorf("decode topic record: %w", err)
			}

			if err := f.storage.RestoreTopic(ctx, state); err != nil {
				return stats, fmt.Errorf("restore topic %q: %w", state.ID, err)
			}

			stats.topics++

		case recordSubscription:
			if flushErr := flush(); flushErr != nil {
				return stats, flushErr
			}

			var state queue.SubscriptionState

			if err := json.Unmarshal(payload, &state); err != nil {
				return stats, fmt.Errorf("decode subscription record: %w", err)
			}

			if err := f.storage.RestoreSubscription(ctx, state); err != nil {
				return stats, fmt.Errorf("restore subscription %q: %w", state.ID, err)
			}

			stats.subscriptions++

		default:
			// An unknown record type from a newer PlainQ cannot be skipped
			// safely: the state it describes would silently go missing.
			return stats, fmt.Errorf("snapshot holds an unknown record type %d", kind)
		}
	}
}

// snapshotWriter turns state records into the snapshot stream. It implements
// queue.StateSink.
type snapshotWriter struct {
	out *bufio.Writer

	queues        uint64
	messages      uint64
	topics        uint64
	subscriptions uint64

	// written counts the bytes handed to the sink, which is the size of the
	// snapshot a joining node will have to pull over the network.
	written uint64
}

// Compilation time check that snapshotWriter can receive a snapshot.
var _ queue.StateSink = (*snapshotWriter)(nil)

func newSnapshotWriter(out io.Writer) *snapshotWriter {
	return &snapshotWriter{out: bufio.NewWriterSize(out, 1<<20)}
}

func (w *snapshotWriter) header() error {
	if _, err := w.out.Write(snapshotMagic[:]); err != nil {
		return fmt.Errorf("write snapshot header: %w", err)
	}

	if err := w.out.WriteByte(snapshotVersion); err != nil {
		return fmt.Errorf("write snapshot header: %w", err)
	}

	return nil
}

func (w *snapshotWriter) flush() error {
	if err := w.out.Flush(); err != nil {
		return fmt.Errorf("flush snapshot: %w", err)
	}

	return nil
}

// Queue implements queue.StateSink.
func (w *snapshotWriter) Queue(state queue.QueueState) error {
	w.queues++

	return w.writeJSON(recordQueue, state)
}

// Message implements queue.StateSink.
//
// Messages get a hand-rolled encoding rather than JSON: a body is arbitrary
// bytes, JSON would base64 it, and a queue holding a million messages should
// not pay a third more disk and network for the privilege.
func (w *snapshotWriter) Message(state queue.MessageState) error {
	w.messages++

	buf := make([]byte, 0, len(state.QueueID)+len(state.ID)+len(state.Body)+32)
	buf = appendFrame(buf, []byte(state.QueueID))
	buf = appendFrame(buf, []byte(state.ID))
	buf = appendFrame(buf, state.Body)
	buf = binary.AppendVarint(buf, state.CreatedAt.UnixNano())
	buf = binary.AppendVarint(buf, state.VisibleAt.UnixNano())
	buf = binary.AppendUvarint(buf, uint64(state.Retries))

	return w.writeRecord(recordMessage, buf)
}

// Topic implements queue.StateSink.
func (w *snapshotWriter) Topic(state queue.TopicState) error {
	w.topics++

	return w.writeJSON(recordTopic, state)
}

// Subscription implements queue.StateSink.
func (w *snapshotWriter) Subscription(state queue.SubscriptionState) error {
	w.subscriptions++

	return w.writeJSON(recordSubscription, state)
}

func (w *snapshotWriter) writeJSON(kind recordType, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode snapshot record: %w", err)
	}

	return w.writeRecord(kind, encoded)
}

func (w *snapshotWriter) writeRecord(kind recordType, payload []byte) error {
	if err := w.out.WriteByte(byte(kind)); err != nil {
		return fmt.Errorf("write snapshot record: %w", err)
	}

	var length [binary.MaxVarintLen64]byte

	n := binary.PutUvarint(length[:], uint64(len(payload)))

	//nolint:gosec // a record length is a non-negative int; the sum cannot be negative.
	w.written += uint64(1 + n + len(payload))

	if _, err := w.out.Write(length[:n]); err != nil {
		return fmt.Errorf("write snapshot record: %w", err)
	}

	if _, err := w.out.Write(payload); err != nil {
		return fmt.Errorf("write snapshot record: %w", err)
	}

	return nil
}

func decodeMessage(payload []byte) (queue.MessageState, error) {
	var state queue.MessageState

	queueID, rest, err := readField(payload)
	if err != nil {
		return state, fmt.Errorf("decode message record: %w", err)
	}

	id, rest, err := readField(rest)
	if err != nil {
		return state, fmt.Errorf("decode message record: %w", err)
	}

	body, rest, err := readField(rest)
	if err != nil {
		return state, fmt.Errorf("decode message record: %w", err)
	}

	createdAt, read := binary.Varint(rest)
	if read <= 0 {
		return state, errors.New("decode message record: truncated created_at")
	}

	rest = rest[read:]

	visibleAt, read := binary.Varint(rest)
	if read <= 0 {
		return state, errors.New("decode message record: truncated visible_at")
	}

	rest = rest[read:]

	retries, read := binary.Uvarint(rest)
	if read <= 0 {
		return state, errors.New("decode message record: truncated retries")
	}

	state.QueueID = string(queueID)
	state.ID = string(id)
	state.Body = body
	state.CreatedAt = time.Unix(0, createdAt).UTC()
	state.VisibleAt = time.Unix(0, visibleAt).UTC()
	state.Retries = uint32(retries) //nolint:gosec // a retry count that overflows uint32 is not a case that occurs.

	return state, nil
}

func appendFrame(buf, value []byte) []byte {
	buf = binary.AppendUvarint(buf, uint64(len(value)))

	return append(buf, value...)
}

//nolint:nonamedreturns // three same-typed results; the names are the documentation.
func readField(buf []byte) (value, rest []byte, err error) {
	length, read := binary.Uvarint(buf)
	if read <= 0 {
		return nil, nil, errors.New("truncated field")
	}

	if length > maxRecordLen {
		return nil, nil, fmt.Errorf("field length %d is out of range", length)
	}

	buf = buf[read:]

	if uint64(len(buf)) < length {
		return nil, nil, errors.New("truncated field")
	}

	return buf[:length], buf[length:], nil
}

// readFrame reads one length-prefixed record payload from the stream.
func readFrame(reader io.ByteReader) ([]byte, error) {
	length, err := binary.ReadUvarint(reader)
	if err != nil {
		return nil, fmt.Errorf("read snapshot record length: %w", err)
	}

	if length > maxRecordLen {
		return nil, fmt.Errorf("snapshot record length %d is out of range", length)
	}

	payload := make([]byte, length) //nolint:makezero // ReadFull fills it; appending would be wrong here.

	full, ok := reader.(io.Reader)
	if !ok {
		return nil, errors.New("snapshot reader cannot read record payloads")
	}

	if _, err := io.ReadFull(full, payload); err != nil {
		return nil, fmt.Errorf("read snapshot record payload: %w", err)
	}

	return payload, nil
}
