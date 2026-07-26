package fsm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	hraft "github.com/hashicorp/raft"
	"github.com/marsolab/plainq/internal/cluster/command"
	"github.com/marsolab/plainq/internal/server/mutations"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/server/service/queue/litestore"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/maxatome/go-testdeep/td"
)

// stamp is the instant the leader is pretending to have stamped on every
// command in these tests.
var stamp = time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

// newStore opens a fresh, fully migrated store on disk.
func newStore(t *testing.T) *litestore.Storage {
	t.Helper()

	conn, err := litekit.New(filepath.Join(t.TempDir(), "plainq.db"), litekit.WithJournalMode(litekit.WAL))
	td.Require(t).CmpNoError(err, "open database")

	t.Cleanup(func() { _ = conn.Close() })

	evolver, evolverErr := litekit.NewEvolver(conn, mutations.SqliteStorageMutations())
	td.Require(t).CmpNoError(evolverErr, "create evolver")
	td.Require(t).CmpNoError(evolver.MutateSchema(), "migrate schema")

	storage, storeErr := litestore.New(conn, litestore.WithoutGC())
	td.Require(t).CmpNoError(storeErr, "create storage")

	t.Cleanup(func() { _ = storage.Close() })

	return storage
}

func newFSM(t *testing.T) (*FSM, *litestore.Storage) {
	t.Helper()

	storage := newStore(t)

	return New(storage, nil), storage
}

// apply runs one command through the state machine the way raft would.
func apply(t *testing.T, machine *FSM, index uint64, cmd *command.Command) any {
	t.Helper()

	encoded, err := cmd.Encode()
	td.Require(t).CmpNoError(err, "encode command")

	return machine.Apply(&hraft.Log{Index: index, Type: hraft.LogCommand, Data: encoded})
}

func protoCommand(t *testing.T, op command.Op, msg interface{ MarshalVT() ([]byte, error) }, ids ...string) *command.Command {
	t.Helper()

	payload, err := msg.MarshalVT()
	td.Require(t).CmpNoError(err, "marshal request")

	return &command.Command{Op: op, Timestamp: stamp.UnixNano(), IDs: ids, Payload: payload}
}

func jsonCommand(t *testing.T, op command.Op, target string, value any, ids ...string) *command.Command {
	t.Helper()

	payload, err := json.Marshal(value)
	td.Require(t).CmpNoError(err, "marshal request")

	return &command.Command{Op: op, Timestamp: stamp.UnixNano(), Target: target, IDs: ids, Payload: payload}
}

// This is the property the whole cluster rests on: the same log, applied to
// two independent stores, produces the same state. If it does not hold, every
// other guarantee is decoration.
func TestApplyIsDeterministicAcrossReplicas(t *testing.T) {
	ctx := context.Background()

	first, firstStore := newFSM(t)
	second, secondStore := newFSM(t)

	log := []*command.Command{
		protoCommand(t, command.OpCreateQueue,
			&v1.CreateQueueRequest{QueueName: "orders", VisibilityTimeoutSeconds: 30},
			"queueone",
		),
		protoCommand(t, command.OpSend, &v1.SendRequest{
			QueueId: "queueone",
			Messages: []*v1.SendMessage{
				{Body: []byte("first")},
				{Body: []byte("second")},
				{Body: []byte("third")},
			},
		}, "msg1", "msg2", "msg3"),
		protoCommand(t, command.OpReceive, &v1.ReceiveRequest{QueueId: "queueone", BatchSize: 2}),
		protoCommand(t, command.OpDelete, &v1.DeleteRequest{QueueId: "queueone", MessageIds: []string{"msg1"}}),
	}

	for index, cmd := range log {
		firstResponse := apply(t, first, uint64(index+1), cmd)
		secondResponse := apply(t, second, uint64(index+1), cmd)

		requireApplied(t, firstResponse, "command %d on the first replica", index)
		requireApplied(t, secondResponse, "command %d on the second replica", index)
	}

	// The visible state has to match message for message, including retry
	// counts and visibility deadlines: a replica that hands out a message its
	// peer considers in-flight is a duplicate delivery waiting to happen.
	td.Cmp(t, dumpState(t, ctx, firstStore), dumpState(t, ctx, secondStore))

	td.Cmp(t, first.AppliedIndex(), uint64(4))
	td.Cmp(t, second.AppliedIndex(), uint64(4))
}

// The leader assigns message ids. A replica that minted its own would give the
// same message a different name on every node, and an acknowledgement sent to
// one node would miss on the others.
func TestSendUsesTheLeadersIdentifiers(t *testing.T) {
	ctx := context.Background()

	machine, storage := newFSM(t)

	apply(t, machine, 1, protoCommand(t, command.OpCreateQueue,
		&v1.CreateQueueRequest{QueueName: "orders"}, "queueone",
	))

	response := apply(t, machine, 2, protoCommand(t, command.OpSend, &v1.SendRequest{
		QueueId:  "queueone",
		Messages: []*v1.SendMessage{{Body: []byte("a")}, {Body: []byte("b")}},
	}, "leader-id-1", "leader-id-2"))

	sent, ok := response.(*v1.SendResponse)
	td.Require(t).Cmp(ok, true, "got %T: %v", response, response)
	td.Cmp(t, sent.GetMessageIds(), []string{"leader-id-1", "leader-id-2"})

	peeked, err := storage.Peek(ctx, &queue.PeekRequest{QueueID: "queueone", Limit: 10})
	td.Require(t).CmpNoError(err)

	ids := make([]string, 0, len(peeked.Messages))
	for _, msg := range peeked.Messages {
		ids = append(ids, msg.ID)
	}

	td.Cmp(t, ids, []string{"leader-id-1", "leader-id-2"})
}

// The queue id is the name every client uses afterwards. It cannot be a local
// decision.
func TestCreateQueueUsesTheLeadersIdentifier(t *testing.T) {
	machine, _ := newFSM(t)

	response := apply(t, machine, 1, protoCommand(t, command.OpCreateQueue,
		&v1.CreateQueueRequest{QueueName: "orders"}, "chosenbytheleader",
	))

	created, ok := response.(*v1.CreateQueueResponse)
	td.Require(t).Cmp(ok, true, "got %T: %v", response, response)
	td.Cmp(t, created.GetQueueId(), "chosenbytheleader")
}

// The visibility deadline comes from the command's timestamp, not from each
// node's clock — otherwise replicas disagree about when a message reappears.
func TestReceiveUsesTheCommandTimestamp(t *testing.T) {
	ctx := context.Background()

	machine, storage := newFSM(t)

	apply(t, machine, 1, protoCommand(t, command.OpCreateQueue,
		&v1.CreateQueueRequest{QueueName: "orders", VisibilityTimeoutSeconds: 60}, "queueone",
	))
	apply(t, machine, 2, protoCommand(t, command.OpSend, &v1.SendRequest{
		QueueId: "queueone", Messages: []*v1.SendMessage{{Body: []byte("a")}},
	}, "msg1"))
	apply(t, machine, 3, protoCommand(t, command.OpReceive,
		&v1.ReceiveRequest{QueueId: "queueone", BatchSize: 1},
	))

	peeked, err := storage.Peek(ctx, &queue.PeekRequest{QueueID: "queueone", Limit: 10})
	td.Require(t).CmpNoError(err)
	td.Require(t).Cmp(peeked.Messages, td.Len(1))

	// stamp + 60s, expressed the way storage writes timestamps.
	td.Cmp(t, peeked.Messages[0].VisibleAt, stamp.Add(60*time.Second).Format("2006-01-02 15:04:05.000"))
	td.Cmp(t, peeked.Messages[0].Retries, uint32(1))
}

// A failed command is a legitimate outcome, and every replica has to reach it.
// Raft commits the entry either way; the error travels back to the caller.
func TestApplyReportsCommandFailureWithoutStopping(t *testing.T) {
	machine, _ := newFSM(t)

	response := apply(t, machine, 1, protoCommand(t, command.OpSend, &v1.SendRequest{
		QueueId: "nosuchqueue", Messages: []*v1.SendMessage{{Body: []byte("a")}},
	}, "msg1"))

	_, isErr := response.(error)
	td.Cmp(t, isErr, true, "the failure comes back as an error value")

	applied, failed := machine.Stats()
	td.Cmp(t, applied, uint64(0))
	td.Cmp(t, failed, uint64(1))

	// The machine keeps going: one rejected command does not stop the log.
	td.Cmp(t, machine.AppliedIndex(), uint64(1))

	response = apply(t, machine, 2, protoCommand(t, command.OpCreateQueue,
		&v1.CreateQueueRequest{QueueName: "orders"}, "queueone",
	))
	requireApplied(t, response, "a later command still applies")
}

// An entry this build cannot read must not be skipped: applying the ones
// around it would fork this replica's state from the rest of the cluster.
func TestApplyRefusesUnreadableEntries(t *testing.T) {
	machine, _ := newFSM(t)

	response := machine.Apply(&hraft.Log{Index: 1, Type: hraft.LogCommand, Data: []byte("not a command")})

	_, isErr := response.(error)
	td.Cmp(t, isErr, true)
}

// Raft writes its own bookkeeping entries into the same log. They are not
// commands and must pass through untouched.
func TestApplyIgnoresNonCommandEntries(t *testing.T) {
	machine, _ := newFSM(t)

	td.Cmp(t, machine.Apply(&hraft.Log{Index: 1, Type: hraft.LogNoop}), td.Nil())
	td.Cmp(t, machine.AppliedIndex(), uint64(1))
}

func TestTopicCommands(t *testing.T) {
	ctx := context.Background()

	machine, storage := newFSM(t)

	apply(t, machine, 1, protoCommand(t, command.OpCreateQueue,
		&v1.CreateQueueRequest{QueueName: "orders"}, "queueone",
	))

	response := apply(t, machine, 2, jsonCommand(t, command.OpCreateTopic, "",
		queue.CreateTopicRequest{TopicName: "events"}, "topicone",
	))

	created, ok := response.(*queue.CreateTopicResponse)
	td.Require(t).Cmp(ok, true, "got %T: %v", response, response)
	td.Cmp(t, created.TopicID, "topicone")

	response = apply(t, machine, 3, jsonCommand(t, command.OpSubscribe, "topicone",
		queue.SubscribeRequest{QueueID: "queueone"}, "subone",
	))

	subscribed, ok := response.(*queue.SubscribeResponse)
	td.Require(t).Cmp(ok, true, "got %T: %v", response, response)
	td.Cmp(t, subscribed.SubscriptionID, "subone")

	response = apply(t, machine, 4, jsonCommand(t, command.OpPublish, "topicone",
		queue.PublishRequest{Messages: []queue.PublishMessage{{Body: []byte("hello")}}}, "pubmsg1",
	))

	published, ok := response.(*queue.PublishResponse)
	td.Require(t).Cmp(ok, true, "got %T: %v", response, response)
	td.Cmp(t, published.MessageIDs, []string{"pubmsg1"}, "the fan-out used the leader's identifier")

	peeked, err := storage.Peek(ctx, &queue.PeekRequest{QueueID: "queueone", Limit: 10})
	td.Require(t).CmpNoError(err)
	td.Cmp(t, peeked.Messages, td.Len(1))

	// Unsubscribe and delete carry their target on the envelope, not in a
	// payload.
	td.Cmp(t, apply(t, machine, 5, &command.Command{
		Op: command.OpUnsubscribe, Timestamp: stamp.UnixNano(), Target: "topicone", IDs: []string{"subone"},
	}), td.Nil())

	td.Cmp(t, apply(t, machine, 6, &command.Command{
		Op: command.OpDeleteTopic, Timestamp: stamp.UnixNano(), Target: "topicone",
	}), td.Nil())

	topics, listErr := storage.ListTopics(ctx)
	td.Require(t).CmpNoError(listErr)
	td.Cmp(t, topics.Topics, td.Len(0))
}

// --- Snapshot and restore --------------------------------------------------

// A node joining an established cluster is caught up by snapshot, not by
// replaying history. If the round trip loses anything, that node is quietly
// wrong from the moment it starts.
func TestSnapshotRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()

	source, sourceStore := newFSM(t)

	apply(t, source, 1, protoCommand(t, command.OpCreateQueue,
		&v1.CreateQueueRequest{
			QueueName:                "orders",
			VisibilityTimeoutSeconds: 45,
			RetentionPeriodSeconds:   3600,
			MaxReceiveAttempts:       7,
		}, "queueone",
	))
	apply(t, source, 2, protoCommand(t, command.OpSend, &v1.SendRequest{
		QueueId: "queueone",
		Messages: []*v1.SendMessage{
			{Body: []byte("first")},
			{Body: []byte("second")},
			{Body: []byte{0x00, 0xff, 0x10}}, // binary bodies must survive too.
		},
	}, "msg1", "msg2", "msg3"))
	// Claim one, so a message is mid-flight when the snapshot is taken.
	apply(t, source, 3, protoCommand(t, command.OpReceive,
		&v1.ReceiveRequest{QueueId: "queueone", BatchSize: 1},
	))
	apply(t, source, 4, jsonCommand(t, command.OpCreateTopic, "",
		queue.CreateTopicRequest{TopicName: "events"}, "topicone",
	))
	apply(t, source, 5, jsonCommand(t, command.OpSubscribe, "topicone",
		queue.SubscribeRequest{QueueID: "queueone"}, "subone",
	))

	before := dumpState(t, ctx, sourceStore)

	encoded := persistSnapshot(t, source)

	target, targetStore := newFSM(t)

	// The target already holds unrelated state, which the restore must
	// replace rather than merge with.
	apply(t, target, 1, protoCommand(t, command.OpCreateQueue,
		&v1.CreateQueueRequest{QueueName: "stale"}, "staleque",
	))
	apply(t, target, 2, protoCommand(t, command.OpSend, &v1.SendRequest{
		QueueId: "staleque", Messages: []*v1.SendMessage{{Body: []byte("old")}},
	}, "old1"))

	td.Require(t).CmpNoError(target.Restore(io.NopCloser(bytes.NewReader(encoded))))

	td.Cmp(t, dumpState(t, ctx, targetStore), before,
		"the restored node holds exactly the snapshot's state, and nothing of its own",
	)

	// Retry counts and visibility deadlines are part of the state: losing them
	// would give a poison message a fresh set of attempts after every restore.
	peeked, err := targetStore.Peek(ctx, &queue.PeekRequest{QueueID: "queueone", Limit: 10})
	td.Require(t).CmpNoError(err)

	var claimed *queue.PeekMessage

	for _, msg := range peeked.Messages {
		if msg.Retries > 0 {
			claimed = msg
		}
	}

	td.Require(t).Cmp(claimed, td.Not(td.Nil()), "the in-flight message survived")
	td.Cmp(t, claimed.Retries, uint32(1))
	td.Cmp(t, claimed.VisibleAt, stamp.Add(45*time.Second).Format("2006-01-02 15:04:05.000"))
}

// The state machine has to keep working after a restore — the caches it reads
// from describe the state that was just replaced.
func TestRestoreLeavesTheStoreUsable(t *testing.T) {
	ctx := context.Background()

	source, _ := newFSM(t)

	apply(t, source, 1, protoCommand(t, command.OpCreateQueue,
		&v1.CreateQueueRequest{QueueName: "orders", VisibilityTimeoutSeconds: 30}, "queueone",
	))

	encoded := persistSnapshot(t, source)

	target, targetStore := newFSM(t)

	apply(t, target, 1, protoCommand(t, command.OpCreateQueue,
		&v1.CreateQueueRequest{QueueName: "stale"}, "staleque",
	))

	td.Require(t).CmpNoError(target.Restore(io.NopCloser(bytes.NewReader(encoded))))

	// A queue from the old state must be gone, including from the cache that
	// answers DescribeQueue.
	_, err := targetStore.DescribeQueue(ctx, &v1.DescribeQueueRequest{QueueId: "staleque"})
	td.Cmp(t, err, td.Not(nil), "the replaced queue is really gone")

	response := apply(t, target, 2, protoCommand(t, command.OpSend, &v1.SendRequest{
		QueueId: "queueone", Messages: []*v1.SendMessage{{Body: []byte("after restore")}},
	}, "msg1"))

	requireApplied(t, response, "writes work against the restored state")
}

// A restore that fails halfway must leave the node with its previous state.
// Holding half a snapshot means holding a state the cluster was never in.
func TestFailedRestoreLeavesThePreviousState(t *testing.T) {
	ctx := context.Background()

	source, _ := newFSM(t)

	apply(t, source, 1, protoCommand(t, command.OpCreateQueue,
		&v1.CreateQueueRequest{QueueName: "orders"}, "queueone",
	))
	apply(t, source, 2, protoCommand(t, command.OpSend, &v1.SendRequest{
		QueueId: "queueone", Messages: []*v1.SendMessage{{Body: []byte("a")}},
	}, "msg1"))

	encoded := persistSnapshot(t, source)

	target, targetStore := newFSM(t)

	apply(t, target, 1, protoCommand(t, command.OpCreateQueue,
		&v1.CreateQueueRequest{QueueName: "existing"}, "existing",
	))

	before := dumpState(t, ctx, targetStore)

	// Truncate the stream mid-record.
	err := target.Restore(io.NopCloser(bytes.NewReader(encoded[:len(encoded)-5])))
	td.Require(t).CmpError(err)

	td.Cmp(t, dumpState(t, ctx, targetStore), before, "the node still holds what it had")
}

func TestRestoreRejectsForeignStreams(t *testing.T) {
	machine, _ := newFSM(t)

	err := machine.Restore(io.NopCloser(bytes.NewReader([]byte("this is not a snapshot at all"))))
	td.CmpError(t, err)

	// A snapshot from a newer PlainQ must be refused rather than
	// half-understood.
	future := append([]byte{}, snapshotMagic[:]...)
	future = append(future, 99)

	err = machine.Restore(io.NopCloser(bytes.NewReader(future)))
	td.Require(t).CmpError(err)
	td.Cmp(t, err.Error(), td.Contains("version"))
}

// A large queue must not have to fit in memory on either side of the round
// trip, and the batching must not lose or reorder anything.
func TestSnapshotHandlesManyMessages(t *testing.T) {
	ctx := context.Background()

	source, sourceStore := newFSM(t)

	apply(t, source, 1, protoCommand(t, command.OpCreateQueue,
		&v1.CreateQueueRequest{QueueName: "bulk"}, "bulkqueue",
	))

	const total = 2500

	messages := make([]*v1.SendMessage, 0, total)
	ids := make([]string, 0, total)

	for i := range total {
		messages = append(messages, &v1.SendMessage{Body: []byte{byte(i % 251)}})
		ids = append(ids, "msg"+pad(i))
	}

	apply(t, source, 2, protoCommand(t, command.OpSend,
		&v1.SendRequest{QueueId: "bulkqueue", Messages: messages}, ids...,
	))

	encoded := persistSnapshot(t, source)

	target, targetStore := newFSM(t)
	td.Require(t).CmpNoError(target.Restore(io.NopCloser(bytes.NewReader(encoded))))

	sourcePeek, err := sourceStore.Peek(ctx, &queue.PeekRequest{QueueID: "bulkqueue", Limit: 1})
	td.Require(t).CmpNoError(err)

	targetPeek, targetErr := targetStore.Peek(ctx, &queue.PeekRequest{QueueID: "bulkqueue", Limit: 1})
	td.Require(t).CmpNoError(targetErr)

	td.Cmp(t, targetPeek.Total, uint64(total))
	td.Cmp(t, targetPeek.Total, sourcePeek.Total)
}

// persistSnapshot drives the snapshot the way raft does — take it, write it,
// release it — and returns the bytes.
func persistSnapshot(t *testing.T, machine *FSM) []byte {
	t.Helper()

	view, err := machine.Snapshot()
	td.Require(t).CmpNoError(err, "take snapshot")

	sink := &memorySink{}

	td.Require(t).CmpNoError(view.Persist(sink), "persist snapshot")

	view.Release()

	return sink.Bytes()
}

// memorySink is a raft.SnapshotSink that keeps the snapshot in memory.
type memorySink struct {
	buf      bytes.Buffer
	cancoled bool
}

func (s *memorySink) Write(p []byte) (int, error) { return s.buf.Write(p) }
func (s *memorySink) Close() error                { return nil }
func (s *memorySink) ID() string                  { return "test-snapshot" }

func (s *memorySink) Cancel() error {
	s.cancoled = true

	return nil
}

func (s *memorySink) Bytes() []byte { return s.buf.Bytes() }

// Compilation time check that memorySink is a usable sink.
var _ hraft.SnapshotSink = (*memorySink)(nil)

// queueDump is the comparable shape of a store's contents.
type queueDump struct {
	Queue    *v1.DescribeQueueResponse
	Messages []*queue.PeekMessage
}

// dumpState reads everything a store holds, in a form two stores can be
// compared by.
func dumpState(t *testing.T, ctx context.Context, storage *litestore.Storage) []queueDump {
	t.Helper()

	listed, err := storage.ListQueues(ctx, &v1.ListQueuesRequest{Limit: 1000})
	td.Require(t).CmpNoError(err, "list queues")

	dumps := make([]queueDump, 0, len(listed.GetQueues()))

	for _, q := range listed.GetQueues() {
		peeked, peekErr := storage.Peek(ctx, &queue.PeekRequest{QueueID: q.GetQueueId(), Limit: 10000})
		td.Require(t).CmpNoError(peekErr, "peek queue %s", q.GetQueueId())

		dumps = append(dumps, queueDump{Queue: q, Messages: peeked.Messages})
	}

	return dumps
}

// requireApplied fails the test when a command came back as an error value.
func requireApplied(t *testing.T, response any, format string, args ...any) {
	t.Helper()

	if err, isErr := response.(error); isErr {
		t.Fatalf(format+": %v", append(args, err)...)
	}
}

func pad(i int) string {
	s := ""

	for range 6 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}

	return s
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
