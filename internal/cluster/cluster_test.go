package cluster

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/mutations"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/plainq/internal/server/service/queue/litestore"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/maxatome/go-testdeep/td"
)

// testCluster is a set of in-process nodes on loopback.
type testCluster struct {
	t     *testing.T
	nodes []*testNode
}

type testNode struct {
	id      string
	node    *Node
	storage *litestore.Storage
	gossip  string
}

// freePort reserves and releases a port, so the caller can bind it. Gossip
// needs a concrete port rather than zero, since it binds both TCP and UDP.
func freePort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	td.Require(t).CmpNoError(err)

	port := listener.Addr().(*net.TCPAddr).Port //nolint:errcheck,forcetypeassert // test on a TCP listener.

	td.Require(t).CmpNoError(listener.Close())

	return port
}

func newTestStorage(t *testing.T, dir string) *litestore.Storage {
	t.Helper()

	conn, err := litekit.New(filepath.Join(dir, "plainq.db"), litekit.WithJournalMode(litekit.WAL))
	td.Require(t).CmpNoError(err, "open database")

	t.Cleanup(func() { _ = conn.Close() })

	evolver, evolverErr := litekit.NewEvolver(conn, mutations.SqliteStorageMutations())
	td.Require(t).CmpNoError(evolverErr, "create evolver")
	td.Require(t).CmpNoError(evolver.MutateSchema(), "migrate schema")

	storage, storageErr := litestore.New(conn, litestore.WithoutGC())
	td.Require(t).CmpNoError(storageErr, "create storage")

	t.Cleanup(func() { _ = storage.Close() })

	return storage
}

// newTestCluster starts size nodes that find each other through static
// discovery and bootstrap together.
//
// The timings are deliberately aggressive. A real deployment wants the library
// defaults; a test wants an election to resolve before the suite times out.
func newTestCluster(t *testing.T, size int) *testCluster {
	t.Helper()

	gossipPorts := make([]int, size)
	gossipAddrs := make([]string, size)

	for i := range size {
		gossipPorts[i] = freePort(t)
		gossipAddrs[i] = net.JoinHostPort("127.0.0.1", strconv.Itoa(gossipPorts[i]))
	}

	cluster := testCluster{t: t}

	for i := range size {
		id := fmt.Sprintf("node-%d", i+1)
		dir := t.TempDir()

		storage := newTestStorage(t, dir)

		// Each node seeds from every node, itself included; a node skips its
		// own address when it joins.
		cfg := Config{
			Enabled:            true,
			NodeID:             id,
			BindAddr:           "127.0.0.1:0",
			GossipAddr:         gossipAddrs[i],
			GossipProfile:      "local",
			DataDir:            filepath.Join(dir, "cluster"),
			Discovery:          []string{"static://" + strings.Join(gossipAddrs, ",")},
			DiscoveryInterval:  200 * time.Millisecond,
			BootstrapExpect:    size,
			ReconcileInterval:  300 * time.Millisecond,
			SweepInterval:      time.Hour,
			ApplyTimeout:       10 * time.Second,
			HeartbeatTimeout:   200 * time.Millisecond,
			ElectionTimeout:    200 * time.Millisecond,
			LeaderLeaseTimeout: 200 * time.Millisecond,
			CommitTimeout:      20 * time.Millisecond,
			Version:            "test",
		}

		// A one-node cluster is bootstrapped outright; bootstrap-expect=1 is
		// the same thing said awkwardly, and the validator rejects 2.
		if size == 1 {
			cfg.BootstrapExpect = 0
			cfg.Bootstrap = true
		}

		node, err := NewNode(cfg, storage, nil)
		td.Require(t).CmpNoError(err, "create node %s", id)

		t.Cleanup(func() { _ = node.Close() })

		td.Require(t).CmpNoError(node.Start(context.Background()), "start node %s", id)

		cluster.nodes = append(cluster.nodes, &testNode{
			id: id, node: node, storage: storage, gossip: gossipAddrs[i],
		})
	}

	return &cluster
}

// leader returns the node that currently leads, waiting for an election.
func (c *testCluster) leader(timeout time.Duration) *testNode {
	c.t.Helper()

	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		for _, n := range c.nodes {
			if n.node.consensus.IsLeader() {
				return n
			}
		}

		time.Sleep(20 * time.Millisecond)
	}

	c.t.Fatalf("no leader was elected within %s", timeout)

	return nil
}

// follower returns any node that is not the leader.
func (c *testCluster) follower() *testNode {
	c.t.Helper()

	for _, n := range c.nodes {
		if !n.node.consensus.IsLeader() && !n.stopped() {
			return n
		}
	}

	c.t.Fatal("every node claims to lead")

	return nil
}

func (n *testNode) stopped() bool { return n.node.consensus.Status().State == "shutdown" }

func (c *testCluster) waitFor(timeout time.Duration, condition func() bool, what string) {
	c.t.Helper()

	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if condition() {
			return
		}

		time.Sleep(20 * time.Millisecond)
	}

	c.t.Fatalf("timed out after %s waiting for: %s", timeout, what)
}

// The headline test: three nodes discover each other, elect a leader, and
// agree on a queue's contents.
func TestThreeNodeClusterReplicatesWrites(t *testing.T) {
	if testing.Short() {
		t.Skip("starts three raft nodes")
	}

	ctx := context.Background()

	cluster := newTestCluster(t, 3)

	leader := cluster.leader(30 * time.Second)

	cluster.waitFor(30*time.Second, func() bool {
		return len(leader.node.Status().Members) == 3
	}, "all three nodes are in the configuration")

	created, err := leader.node.Store().CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "orders"})
	td.Require(t).CmpNoError(err, "create a queue on the leader")

	queueID := created.GetQueueId()

	_, sendErr := leader.node.Store().Send(ctx, &v1.SendRequest{
		QueueId:  queueID,
		Messages: []*v1.SendMessage{{Body: []byte("one")}, {Body: []byte("two")}},
	})
	td.Require(t).CmpNoError(sendErr, "send through the leader")

	// Every node's local store must end up holding the same two messages —
	// that is what replication means, and reading the *local* store on each
	// node is what proves it rather than assuming.
	for _, n := range cluster.nodes {
		node := n

		cluster.waitFor(20*time.Second, func() bool {
			peeked, peekErr := node.storage.Peek(ctx, &queue.PeekRequest{QueueID: queueID, Limit: 10})

			return peekErr == nil && len(peeked.Messages) == 2
		}, "node "+node.id+" holds both messages")

		peeked, peekErr := node.storage.Peek(ctx, &queue.PeekRequest{QueueID: queueID, Limit: 10})
		td.Require(t).CmpNoError(peekErr)

		td.Cmp(t, string(peeked.Messages[0].Body), "one", "node %s message order", node.id)
		td.Cmp(t, string(peeked.Messages[1].Body), "two", "node %s message order", node.id)
	}
}

// A client may talk to any node. A follower does not redirect it — that would
// leak topology into every SDK — it hands the write to the leader and returns
// the leader's answer as its own.
func TestFollowerForwardsWritesToTheLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("starts three raft nodes")
	}

	ctx := context.Background()

	cluster := newTestCluster(t, 3)

	cluster.leader(30 * time.Second)

	follower := cluster.follower()

	created, err := follower.node.Store().CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "forwarded"})
	td.Require(t).CmpNoError(err, "create a queue through a follower")
	td.Cmp(t, created.GetQueueId(), td.Not(""), "the follower returned the leader's answer")

	sent, sendErr := follower.node.Store().Send(ctx, &v1.SendRequest{
		QueueId:  created.GetQueueId(),
		Messages: []*v1.SendMessage{{Body: []byte("via a follower")}},
	})
	td.Require(t).CmpNoError(sendErr, "send through a follower")
	td.Require(t).Cmp(sent.GetMessageIds(), td.Len(1))

	// A receive is a write too — it hides what it hands out — so it must also
	// take the trip to the leader rather than be answered locally.
	received, receiveErr := follower.node.Store().Receive(ctx, &v1.ReceiveRequest{
		QueueId: created.GetQueueId(), BatchSize: 1,
	})
	td.Require(t).CmpNoError(receiveErr, "receive through a follower")
	td.Require(t).Cmp(received.GetMessages(), td.Len(1))
	td.Cmp(t, string(received.GetMessages()[0].GetBody()), "via a follower")
	td.Cmp(t, received.GetMessages()[0].GetId(), sent.GetMessageIds()[0],
		"the message keeps the id the leader assigned it",
	)
}

// Losing the leader is the case the whole design exists for: the survivors
// elect a new one and the data is still there.
func TestClusterSurvivesLosingTheLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("starts three raft nodes")
	}

	ctx := context.Background()

	cluster := newTestCluster(t, 3)

	leader := cluster.leader(30 * time.Second)

	created, err := leader.node.Store().CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "durable"})
	td.Require(t).CmpNoError(err)

	queueID := created.GetQueueId()

	_, sendErr := leader.node.Store().Send(ctx, &v1.SendRequest{
		QueueId:  queueID,
		Messages: []*v1.SendMessage{{Body: []byte("survives")}},
	})
	td.Require(t).CmpNoError(sendErr)

	// Wait for the write to reach the followers before pulling the leader, so
	// the test is about failover rather than about a race with replication.
	survivors := make([]*testNode, 0, 2)

	for _, n := range cluster.nodes {
		if n.id != leader.id {
			survivors = append(survivors, n)
		}
	}

	for _, n := range survivors {
		node := n

		cluster.waitFor(20*time.Second, func() bool {
			peeked, peekErr := node.storage.Peek(ctx, &queue.PeekRequest{QueueID: queueID, Limit: 10})

			return peekErr == nil && len(peeked.Messages) == 1
		}, "node "+node.id+" replicated the write")
	}

	td.Require(t).CmpNoError(leader.node.Close(), "stop the leader")

	// Two of three is still a quorum, so a new leader must appear.
	cluster.waitFor(30*time.Second, func() bool {
		for _, n := range survivors {
			if n.node.consensus.IsLeader() {
				return true
			}
		}

		return false
	}, "the survivors elect a new leader")

	var newLeader *testNode

	for _, n := range survivors {
		if n.node.consensus.IsLeader() {
			newLeader = n
		}
	}

	td.Require(t).Cmp(newLeader, td.Not(td.Nil()))
	td.Cmp(t, newLeader.id, td.Not(leader.id), "leadership actually moved")

	// The message is still there, and the cluster still takes writes.
	received, receiveErr := newLeader.node.Store().Receive(ctx, &v1.ReceiveRequest{
		QueueId: queueID, BatchSize: 1,
	})
	td.Require(t).CmpNoError(receiveErr, "receive from the new leader")
	td.Require(t).Cmp(received.GetMessages(), td.Len(1))
	td.Cmp(t, string(received.GetMessages()[0].GetBody()), "survives")

	_, sendErr = newLeader.node.Store().Send(ctx, &v1.SendRequest{
		QueueId:  queueID,
		Messages: []*v1.SendMessage{{Body: []byte("after failover")}},
	})
	td.CmpNoError(t, sendErr, "the cluster accepts writes again")
}

// Exactly one message goes to exactly one consumer, no matter which node each
// of them talks to. This is the property a replicated queue exists to keep.
func TestReceiveDoesNotDuplicateAcrossNodes(t *testing.T) {
	if testing.Short() {
		t.Skip("starts three raft nodes")
	}

	ctx := context.Background()

	cluster := newTestCluster(t, 3)

	cluster.leader(30 * time.Second)

	created, err := cluster.nodes[0].node.Store().CreateQueue(ctx, &v1.CreateQueueRequest{
		QueueName: "exclusive", VisibilityTimeoutSeconds: 300,
	})
	td.Require(t).CmpNoError(err)

	queueID := created.GetQueueId()

	const total = 9

	messages := make([]*v1.SendMessage, 0, total)
	for i := range total {
		messages = append(messages, &v1.SendMessage{Body: []byte(strconv.Itoa(i))})
	}

	_, sendErr := cluster.nodes[0].node.Store().Send(ctx, &v1.SendRequest{
		QueueId: queueID, Messages: messages,
	})
	td.Require(t).CmpNoError(sendErr)

	// Every node receives in turn. No message may appear twice.
	seen := make(map[string]string, total)

	for round := range total {
		node := cluster.nodes[round%len(cluster.nodes)]

		received, receiveErr := node.node.Store().Receive(ctx, &v1.ReceiveRequest{
			QueueId: queueID, BatchSize: 1,
		})
		td.Require(t).CmpNoError(receiveErr, "receive on %s", node.id)
		td.Require(t).Cmp(received.GetMessages(), td.Len(1), "round %d on %s", round, node.id)

		msg := received.GetMessages()[0]

		if previous, duplicate := seen[msg.GetId()]; duplicate {
			t.Fatalf("message %s was handed out twice: to %s and to %s", msg.GetId(), previous, node.id)
		}

		seen[msg.GetId()] = node.id
	}

	td.Cmp(t, len(seen), total, "every message was delivered exactly once")
}

// A single node is still a cluster — the degenerate case has to work, because
// it is how people try the feature out.
func TestSingleNodeCluster(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}

	ctx := context.Background()

	cluster := newTestCluster(t, 1)

	leader := cluster.leader(30 * time.Second)

	created, err := leader.node.Store().CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "alone"})
	td.Require(t).CmpNoError(err)

	_, sendErr := leader.node.Store().Send(ctx, &v1.SendRequest{
		QueueId: created.GetQueueId(), Messages: []*v1.SendMessage{{Body: []byte("hello")}},
	})
	td.Require(t).CmpNoError(sendErr)

	received, receiveErr := leader.node.Store().Receive(ctx, &v1.ReceiveRequest{
		QueueId: created.GetQueueId(), BatchSize: 1,
	})
	td.Require(t).CmpNoError(receiveErr)
	td.Require(t).Cmp(received.GetMessages(), td.Len(1))

	status := leader.node.Status()

	td.Cmp(t, status.Enabled, true)
	td.Cmp(t, status.Voters, 1)
	td.Cmp(t, status.Quorum, 1)
	td.Cmp(t, status.Healthy, true)
}

// A node added after the cluster formed is caught up from a snapshot rather
// than by replaying history, which is the path a scale-up actually takes.
func TestNodeJoiningAnEstablishedClusterCatchesUp(t *testing.T) {
	if testing.Short() {
		t.Skip("starts raft nodes")
	}

	ctx := context.Background()

	cluster := newTestCluster(t, 3)

	leader := cluster.leader(30 * time.Second)

	created, err := leader.node.Store().CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "backfill"})
	td.Require(t).CmpNoError(err)

	queueID := created.GetQueueId()

	_, sendErr := leader.node.Store().Send(ctx, &v1.SendRequest{
		QueueId:  queueID,
		Messages: []*v1.SendMessage{{Body: []byte("written before the join")}},
	})
	td.Require(t).CmpNoError(sendErr)

	// Force a snapshot so the joiner is caught up by state transfer rather
	// than by replaying the (still short) log.
	td.Require(t).CmpNoError(leader.node.Snapshot(ctx), "snapshot")

	// A fourth node, joining as a non-voter so it does not change quorum.
	dir := t.TempDir()
	storage := newTestStorage(t, dir)

	gossipPort := freePort(t)

	seeds := make([]string, 0, len(cluster.nodes))
	for _, n := range cluster.nodes {
		seeds = append(seeds, n.gossip)
	}

	joiner, joinErr := NewNode(Config{
		Enabled:            true,
		NodeID:             "node-4",
		BindAddr:           "127.0.0.1:0",
		GossipAddr:         net.JoinHostPort("127.0.0.1", strconv.Itoa(gossipPort)),
		GossipProfile:      "local",
		DataDir:            filepath.Join(dir, "cluster"),
		Discovery:          []string{"static://" + strings.Join(seeds, ",")},
		DiscoveryInterval:  200 * time.Millisecond,
		NonVoter:           true,
		ReconcileInterval:  300 * time.Millisecond,
		SweepInterval:      time.Hour,
		ApplyTimeout:       10 * time.Second,
		HeartbeatTimeout:   200 * time.Millisecond,
		ElectionTimeout:    200 * time.Millisecond,
		LeaderLeaseTimeout: 200 * time.Millisecond,
		CommitTimeout:      20 * time.Millisecond,
	}, storage, nil)
	td.Require(t).CmpNoError(joinErr, "create the joining node")

	t.Cleanup(func() { _ = joiner.Close() })

	td.Require(t).CmpNoError(joiner.Start(context.Background()), "start the joining node")

	cluster.waitFor(45*time.Second, func() bool {
		peeked, peekErr := storage.Peek(ctx, &queue.PeekRequest{QueueID: queueID, Limit: 10})

		return peekErr == nil && len(peeked.Messages) == 1
	}, "the new node caught up with the state it missed")

	// A non-voter replicates without changing the arithmetic of quorum.
	status := leader.node.Status()
	td.Cmp(t, status.Voters, 3, "the replica does not vote")
	td.Cmp(t, status.Quorum, 2)
}

// A node that leaves deliberately must be removed from the configuration —
// otherwise quorum keeps being computed against a node that is never coming
// back.
func TestLeaveRemovesTheNodeFromTheConfiguration(t *testing.T) {
	if testing.Short() {
		t.Skip("starts three raft nodes")
	}

	ctx := context.Background()

	cluster := newTestCluster(t, 3)

	cluster.leader(30 * time.Second)

	departing := cluster.follower()

	td.Require(t).CmpNoError(departing.node.Leave(ctx), "leave the cluster")

	cluster.waitFor(30*time.Second, func() bool {
		for _, n := range cluster.nodes {
			if n.id == departing.id || !n.node.consensus.IsLeader() {
				continue
			}

			for _, server := range n.node.Status().Members {
				if server.ID == departing.id && server.Suffrage != "" {
					return false
				}
			}

			return true
		}

		return false
	}, "the departing node is out of the configuration")
}
