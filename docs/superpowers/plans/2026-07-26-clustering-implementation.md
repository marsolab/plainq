# PlainQ clustering — implementation

Plan for [the clustering design](../specs/2026-07-26-clustering-design.md).
Status: complete.

## Shape of the change

The queue service talks to a `queue.Storage`. That interface is the seam: in a
cluster it gets a `cluster.Store` that replicates writes instead of the local
backend, and nothing above it knows the difference. Everything else follows
from that one decision.

New packages, bottom-up:

| Package | What it does |
| --- | --- |
| `internal/cluster/discovery` | `Discoverer` + a provider per platform + a spec-string registry. |
| `internal/cluster/transport` | One TCP port carrying Raft and peer RPC, demuxed by a leading byte. |
| `internal/cluster/gossip` | `Gossip` + a `hashicorp/memberlist` implementation. |
| `internal/cluster/consensus` | `Consensus` + a `hashicorp/raft` engine. |
| `internal/cluster/command` | The replicated command envelope and codec. |
| `internal/cluster/fsm` | `raft.FSM` over a local store, plus snapshot/restore. |
| `internal/cluster/peer` | Internal peer RPC: forward, join, leave, status. |
| `internal/cluster` | `Node` (lifecycle, reconciliation, leader jobs) and `Store`. |

## Steps

1. **Determinism in storage.** `queue.Determinism` on the context; `litestore`
   takes ids and timestamps from it when present and from the wall clock when
   not. Message selection ordered by `(created_at, msg_id)`. Local GC
   disableable.
2. **Snapshot/restore contract.** `queue.StateSnapshotter` / `StateRestorer` in
   the queue package (records), the serialization format in the cluster layer
   (bytes). `BeginSnapshot` pins a read view at the instant raft asks, because
   the writing out happens later.
3. **Discovery.** Interface, spec parsing, `Multi`, then one file per provider:
   static, DNS, Kubernetes, Docker, AWS, GCP, Azure, Consul. REST clients with
   injectable HTTP clients and clocks — no cloud SDKs.
4. **Transport.** Muxed listener, advertise-address validation.
5. **Gossip.** memberlist wrapper with node metadata and an event stream.
6. **Consensus.** Raft engine, BoltDB log store, file snapshot store, hclog
   adapter.
7. **Commands and FSM.** Envelope codec; FSM dispatch; snapshot stream.
8. **Store and Node.** Write path, forwarding, read modes, bootstrap, join,
   reconciliation, leader-only sweeper.
9. **Wiring.** `-cluster.*` flags, `initClusterNode`, WAL enforcement,
   Postgres rejection, `/api/v1/cluster`, `plainq cluster` subcommands,
   metrics.
10. **Deployment and docs.** Helm cluster mode, clustering guide, references.

## Testing

- Per-provider tests against recorded provider payloads (`httptest`).
- Codec round-trip and truncation tests.
- FSM: the same command sequence applied to two independent stores must leave
  identical state; snapshot/restore round trip; failed restore leaves the
  previous state.
- A real three-node in-process cluster: election, replication, forwarding,
  failover, exactly-once delivery across nodes, join-and-catch-up, leave.
- Everything under `-race`.

## What this changed outside the cluster packages

- `litestore` writes message timestamps explicitly instead of relying on column
  defaults, and takes the visibility instant as a bind parameter.
- Two pre-existing bugs surfaced while making eviction deterministic and are
  fixed: the retention predicate had its placeholder inside a string literal
  (`datetime(created_at, '+? seconds')`), so retention-based eviction never
  matched a row; and the dead-letter path selected five columns into a
  three-column scan, so it errored whenever it did match one.
- `maxSendInsertBatch` halved, since each message now binds four parameters.

## Deliberately not done

- **Sharding.** Every node holds the full state. Partitioning queues across
  nodes is a separate design.
- **Replicating accounts, RBAC and OAuth.** They stay per-node.
- **A Houston cluster page.** The API is there
  (`GET /api/v1/cluster`); the dashboard view is follow-up frontend work.
- **Postgres replication.** Storage is already shared there; the server refuses
  the combination rather than doing something surprising.
