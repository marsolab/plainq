# PlainQ clustering — design

Status: accepted
Date: 2026-07-26

## Problem

PlainQ is a single-process queue server. The queue lives in one embedded SQLite
file (or one Postgres database), so a node loss is a service loss and the write
throughput ceiling is one machine. Operators who like the "one binary" story
still need more than one binary running.

We want a *cluster version*: several PlainQ nodes that agree on queue state,
survive the loss of a minority, find each other automatically on the platforms
people actually deploy on, and keep the single-node experience intact for
everyone who does not turn clustering on.

## Goals

- **Replicated, linearizable queue state.** A message acknowledged on one node
  is acknowledged everywhere. No duplicate delivery caused by replication.
- **Automatic failover.** Lose a minority of nodes and the cluster keeps
  serving; the survivors elect a new leader without operator involvement.
- **Automatic membership.** Nodes discover peers on Kubernetes, Docker, AWS,
  GCP, Azure, Consul, plain DNS, or a static list, and keep tracking them as
  the deployment scales.
- **No new operational surface for single-node users.** `plainq serve` with no
  cluster flags behaves exactly as it does today.
- **No heavyweight dependencies.** Cloud discovery talks to the provider REST
  APIs directly rather than pulling a cloud SDK per provider.

## Non-goals

- Sharding / partitioning of queues across nodes. Every node holds the full
  state. Horizontal *write* scale-out is a later, separate design.
- Cross-region replication with relaxed consistency.
- Replacing the Postgres backend's own replication story.

## Consensus: Raft, not Paxos

The task allowed either. We use **Raft** (`hashicorp/raft`), because:

- Raft's log-with-a-leader model maps directly onto a queue: every mutating
  queue operation is already a discrete command with a total order.
- Membership changes are a first-class part of the protocol, which is exactly
  what a discovery-driven cluster needs. Multi-Paxos leaves reconfiguration to
  the implementer.
- `hashicorp/raft` is a mature, single-purpose library that carries no
  service-discovery or RPC framework with it, so it composes with the gossip
  and discovery layers we want rather than competing with them.
- An operator can read a Raft log and reason about it. That matters more than
  the marginal theoretical differences for a queue server.

The engine sits behind `cluster/consensus.Consensus`, so a Paxos (or
alternative Raft) engine can be substituted without touching the queue code.

## Architecture

```
                      ┌──────────────────────────────────────────┐
   discovery ────────▶│ cluster.Node                             │
   (k8s/aws/dns/...)  │                                          │
                      │  gossip (memberlist)  ── membership,     │
                      │       │                   failure detect,│
                      │       │                   metadata       │
                      │       ▼                                  │
                      │  consensus (raft)     ── log, election,  │
                      │       │                   snapshots      │
                      │       ▼                                  │
                      │  fsm ──▶ queue.Storage (litestore)       │
                      └──────────────────────────────────────────┘
                              ▲
   queue.Service ── cluster.Store ── writes: replicate (or forward to leader)
                                     reads:  local
```

### Layers

| Package | Responsibility |
| --- | --- |
| `internal/cluster/discovery` | Find peer addresses. One `Discoverer` interface, one implementation per platform, a spec-string registry, plus `Multi` and caching wrappers. |
| `internal/cluster/gossip` | Membership and failure detection over `hashicorp/memberlist`. Carries per-node metadata (node id, raft address, roles). |
| `internal/cluster/consensus` | `Consensus` interface + `hashicorp/raft` engine, a SQLite-backed log/stable store, and a multiplexed TCP transport. |
| `internal/cluster/command` | The replicated command envelope and its codec. |
| `internal/cluster/fsm` | `raft.FSM` that applies commands to the local `queue.Storage`, plus logical snapshot/restore. |
| `internal/cluster/transport` | One TCP port carrying both Raft RPC and internal peer RPC, demultiplexed by a leading magic byte. |
| `internal/cluster` | `Node`: lifecycle, reconciliation of discovered peers into Raft voters, leader-only jobs, status reporting. `Store`: the `queue.Storage` the service actually talks to. |

### Write path

1. A client calls `Send` on any node.
2. `cluster.Store` builds a **fully determined** command: every value the
   replicas must not invent for themselves (message ULIDs, timestamps, queue
   ids) is stamped once, here.
3. If this node is the leader, the command goes into the Raft log. Otherwise it
   is forwarded to the leader over the internal peer RPC, and the leader
   proposes it.
4. Once committed, every node's FSM applies the command to its local storage.
   The leader's apply returns the response to the caller.

### Read path

Reads (`ListQueues`, `DescribeQueue`, `Peek`) are served from the local replica
by default — the cheapest and the most useful behaviour for a dashboard. A
`ConsistencyMode` of `strong` routes them through the leader with a Raft
barrier instead. `Receive` is *not* a read: it mutates visibility and always
goes through the log.

### Determinism

The FSM must reach the same state on every node, so a replicated write cannot
call `time.Now()` or generate an id inside storage. `queue.Determinism` carries
the leader's stamped values on the context; `litestore` uses them when present
and falls back to the wall clock and a fresh ULID when absent (the single-node
path, unchanged).

Concretely:

- `CreateQueue` — queue id and `created_at`.
- `Send` — one ULID per message, plus `created_at`/`visible_at`.
- `Receive` — the visibility deadline, and a `now` for the visibility
  predicate, which used to be SQLite's `current_timestamp`.
- `CreateTopic` / `Subscribe` — the generated id.
- Message selection is ordered by `(created_at, msg_id)` so ties break
  identically everywhere.

Background garbage collection is disabled on cluster members: it would have
each node independently deleting different rows. Instead the **leader** runs
the sweeper and proposes a `Sweep` command per queue with an explicit cutoff.

### Snapshots

Snapshots are *logical*: queues and their messages are written as a versioned
stream, not as a copy of the SQLite file. That keeps a snapshot portable across
storage backends and page-format changes, and makes it testable without a
filesystem.

### Membership

Gossip and Raft answer different questions and we use both:

- **memberlist** answers "who is alive right now?" — fast failure detection,
  no quorum needed, and it carries node metadata. It is the input to
  reconciliation and to the `/cluster/members` view.
- **Raft** answers "who votes?" — the authoritative, quorum-agreed
  configuration.

The leader reconciles the two: a node that gossip reports alive and that is not
in the Raft configuration gets added as a voter (or non-voter, if it advertises
itself as one); a node gossip reports as permanently gone is removed after
`RemoveTimeout`. Discovery seeds gossip; gossip drives Raft.

### Bootstrapping

- `-cluster.bootstrap` — form a single-node cluster immediately. For the first
  node of a hand-built cluster and for tests.
- `-cluster.bootstrap-expect=N` — wait until N peers are known, then have the
  lowest-id node bootstrap with all N as voters. This is the Consul model and
  it is what the Helm chart uses; it avoids the split-brain that racing
  single-node bootstraps produce.
- Neither — the node joins an existing cluster through discovery and waits.

## Discovery

```go
type Peer struct {
    ID     string            // optional stable identity
    Addr   string            // host:port of the peer's cluster port
    Meta   map[string]string // provider-supplied labels
    Source string            // which provider produced this peer
}

type Discoverer interface {
    Name() string
    Discover(ctx context.Context) ([]Peer, error)
    io.Closer
}
```

Providers are selected by a spec string so the whole thing is one flag:

| Spec | Provider |
| --- | --- |
| `static://10.0.0.1:8082,10.0.0.2:8082` | fixed list |
| `dns://plainq.internal?port=8082` | A/AAAA records |
| `dns+srv://_plainq._tcp.example.com` | SRV records |
| `kubernetes://?namespace=default&selector=app%3Dplainq&port=8082` | Kubernetes API (EndpointSlices → Endpoints → Pods) |
| `docker://?label=plainq.cluster%3Dprod&port=8082` | Docker Engine API |
| `aws://?region=eu-west-1&tag%3ACluster=plainq&port=8082` | EC2 `DescribeInstances` |
| `gcp://?project=p&zone=z&label=cluster%3Dplainq` | GCE `instances.list` |
| `azure://?subscription=…&resource-group=…&tag=cluster%3Dplainq` | Azure Resource Graph |
| `consul://?address=http://127.0.0.1:8500&service=plainq` | Consul catalog |

Several specs can be given at once; results are merged and de-duplicated.

Every provider is a thin REST client with an injectable `*http.Client` and
clock, so each one is unit-tested against an `httptest.Server` with recorded
provider payloads. No cloud SDK is added to `go.mod`; AWS request signing
reuses the SigV4 signer already in the dependency graph.

## Security

- Gossip is encrypted and authenticated with a shared key
  (`-cluster.gossip.secret`, a base64 16/24/32-byte AES key).
- Internal peer RPC requires `-cluster.secret` in a header, compared in
  constant time.
- Raft's transport can be wrapped in TLS via `-cluster.tls.*`.

None of the three is on by default when clustering is off; all three are
required (and validated at startup) when `-cluster.enable` is set and the
advertised address is not loopback.

## Operator surface

- `GET /api/v1/cluster` — status: node id, state, leader, term, applied index.
- `GET /api/v1/cluster/members` — gossip + Raft view of every member.
- `POST /api/v1/cluster/members` / `DELETE /api/v1/cluster/members/{id}` —
  manual join/leave for hand-built clusters.
- `plainq cluster status|members|join|leave` on the CLI.
- Metrics for state, term, applied index, commit latency, forwarded writes,
  gossip member count, and discovery results.

## Storage backends

| Backend | Clustered behaviour |
| --- | --- |
| `sqlite` | Full Raft replication. Each node keeps a complete copy. |
| `postgres` | Storage is already shared, so replicating it would duplicate every write. The cluster layer runs in **coordination mode**: gossip and Raft still run and elect a leader, and that leader owns the singleton jobs (GC, retention), but queue operations go straight to Postgres on whichever node received them. |

## Testing

- Unit tests per discovery provider against recorded provider payloads.
- Codec round-trip and forward/backward-compatibility tests for commands.
- FSM determinism tests: apply the same command sequence to two independent
  stores and assert identical resulting state.
- Snapshot/restore round-trip.
- A three-node in-process cluster test that elects a leader, replicates
  sends/receives, kills the leader, and asserts the survivors keep the data.
- Log store tests covering the `raft.LogStore`/`StableStore` contract.
