# Clustering

A single PlainQ is a complete PlainQ. Clustering is for when losing one machine
must not mean losing the queue.

With `-cluster.enable`, several PlainQ nodes agree on queue state through Raft
consensus, track each other's liveness through a gossip protocol, and find each
other automatically on whatever platform you deploy to. Every node holds a full
copy of the queue; a majority has to acknowledge every write; the loss of a
minority costs you nothing.

Nothing on this page applies unless you turn it on. `plainq serve` with no
cluster flags behaves exactly as it always has.

## Table of contents

- [What clustering gives you](#what-clustering-gives-you)
- [How it works](#how-it-works)
- [Quick start: three nodes on one machine](#quick-start-three-nodes-on-one-machine)
- [Sizing a cluster](#sizing-a-cluster)
- [Discovery](#discovery)
- [Security](#security)
- [Consistency](#consistency)
- [Operating a cluster](#operating-a-cluster)
- [Kubernetes](#kubernetes)
- [Postgres](#postgres)
- [Configuration reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)

## What clustering gives you

- **Durability across machines.** A message acknowledged by the cluster is on a
  majority of nodes before the client hears about it.
- **Automatic failover.** Lose a minority and the survivors elect a new leader
  in under a second. No operator involvement, no manual promotion.
- **Any node accepts any request.** Clients do not need to know who leads. A
  follower hands writes to the leader and returns the leader's answer as its
  own.
- **Automatic membership.** Nodes find each other on Kubernetes, Docker, AWS,
  GCP, Azure, Consul, or plain DNS, and keep tracking the deployment as it
  scales.

What it does not give you: more write throughput. Every node applies every
write, so the cluster's write ceiling is roughly one node's. Clustering buys
availability and read capacity, not write scale.

## How it works

```
                    ┌──────────────────────────────────────┐
  discovery ───────▶│  gossip  — who is alive right now?   │
  (k8s/aws/dns/…)   │     │                                │
                    │     ▼                                │
                    │  consensus — what is the state?      │
                    │     │                                │
                    │     ▼                                │
                    │  local SQLite replica                │
                    └──────────────────────────────────────┘
```

Three layers, each answering a different question:

**Discovery** answers *where are the other nodes?* It runs on an interval for
the life of the process, so a node that joins later is found without a restart.

**Gossip** (`hashicorp/memberlist`) answers *which of them are alive?* It
detects a failure in seconds without needing a quorum, and it carries each
node's metadata — its consensus address, whether it wants to vote, its build
version. That metadata is the join handshake: a node that appears in gossip has
already said everything the cluster needs to admit it.

**Consensus** (`hashicorp/raft`) answers *what is the queue's state?* Every
mutating operation becomes a command in a replicated log. A majority has to
accept a command before it is applied, and every node applies the same commands
in the same order to its own SQLite replica.

The leader reconciles gossip against the consensus configuration: a node gossip
can see that is not yet a member gets added; a node that has been gone longer
than `-cluster.remove.timeout` can be removed (if you opt into
`-cluster.auto-remove`).

### Why Raft

The design allows for either Raft or Paxos. PlainQ uses Raft because a queue's
writes are already a totally ordered sequence of discrete commands — which is
exactly the shape of a Raft log — and because Raft treats membership change as
part of the protocol rather than as an exercise for the implementer. That
matters when the membership is driven by a Kubernetes deployment that scales on
its own. The engine sits behind an interface, so a different one can be
substituted without touching the queue.

### What is replicated, and what is not

Everything about queues and messages goes through the log: creating and
deleting queues, sending, receiving, acknowledging, topics, subscriptions, and
eviction.

`Receive` is a write, not a read. It hides the messages it hands out, and
serving it from a local replica would let two consumers on two nodes claim the
same message. That is the one thing a queue may not do, so a receive takes the
same trip through consensus as a send.

Accounts, RBAC and OAuth configuration are **not** replicated. Those live in
each node's own database. Point every node at the same identity source, or
manage them per node.

## Quick start: three nodes on one machine

Enough to see it work. Each node gets its own data directory and its own ports.

```shell
SECRET=$(openssl rand -hex 32)
GOSSIP=$(openssl rand -base64 32)
JWT=$(openssl rand -hex 32)

for i in 1 2 3; do
  mkdir -p /tmp/plainq-$i
  ./plainq serve \
    -storage.path=/tmp/plainq-$i/plainq.db \
    -grpc.addr=:808$i -http.addr=:818$i \
    -auth.jwt.secret="$JWT" \
    -cluster.enable \
    -cluster.node-id=node-$i \
    -cluster.bind.addr=127.0.0.1:928$i \
    -cluster.gossip.addr=127.0.0.1:938$i \
    -cluster.discovery='static://127.0.0.1:9381,127.0.0.1:9382,127.0.0.1:9383' \
    -cluster.bootstrap-expect=3 \
    -cluster.secret="$SECRET" \
    -cluster.gossip.secret="$GOSSIP" &
done
```

The three nodes find each other, elect a leader, and form a cluster. Check on
it:

```shell
./plainq cluster status -http.addr=http://localhost:8181 -token="$TOKEN"
```

```
Node:          node-2 (leader)
Leader:        node-2
Term:          2
Log:           commit 4, applied 4, last 4
Quorum:        2 of 3 voters (healthy)
Commands:      3 applied, 0 failed

ID      ADDRESS          SUFFRAGE  REACHABLE  ROLE
node-1  127.0.0.1:9281   voter     true
node-2  127.0.0.1:9282   voter     true       leader, this node
node-3  127.0.0.1:9283   voter     true
```

Send to one node and receive from another — the cluster does not care which:

```shell
QID=$(./plainq create orders -grpc.addr=localhost:8081)
./plainq send -message='hello' "$QID" -grpc.addr=localhost:8082
./plainq receive -ack "$QID" -grpc.addr=localhost:8083
```

Now kill the leader and watch the other two carry on.

## Sizing a cluster

A Raft cluster commits a write when a majority of voters accepts it, so it
survives the loss of `(N-1)/2` nodes:

| Voters | Quorum | Failures tolerated | Verdict |
| --- | --- | --- | --- |
| 1 | 1 | 0 | Fine for testing; no redundancy. |
| 2 | 2 | **0** | **Never do this.** Strictly worse than one node — now *either* machine takes the cluster down. |
| 3 | 2 | 1 | The usual choice. |
| 5 | 3 | 2 | For when a single failure during maintenance is unacceptable. |
| 7 | 4 | 3 | Rarely worth the extra commit latency. |

Always use an odd number. A cluster of four tolerates exactly as many failures
as a cluster of three and costs a machine more. PlainQ rejects
`-cluster.bootstrap-expect=2` outright and warns about other even sizes.

Need more replicas without more voters? Add **non-voters** with
`-cluster.non-voter`. They replicate the full log and serve local reads, but
they do not vote and do not change quorum.

## Discovery

One flag, `-cluster.discovery`, takes a spec string naming how to find peers.
Discovery answers with **gossip** addresses; a peer's consensus address is part
of what it gossips, so only one port has to be discoverable.

Several specs can be given, comma-separated. Results are merged and
de-duplicated, and a provider that fails does not blind the ones that work — a
static seed list alongside a cloud provider is a good belt-and-braces setup.

### Static

```
static://10.0.0.1:8083,10.0.0.2:8083,10.0.0.3:8083
```

A bare list with no scheme is treated as static, so
`-cluster.discovery=10.0.0.1:8083,10.0.0.2:8083` works too.

### DNS

```
dns://plainq.internal?port=8083
dns+srv://_plainq._tcp.example.com
```

`dns` resolves A/AAAA records and attaches `port`. `dns+srv` reads the port
from the SRV record. A name that resolves to nothing yet is not an error — it
is a deployment that has not finished rolling out.

### Kubernetes

```
kubernetes://?namespace=default&selector=app%3Dplainq&port=8083
kubernetes://default/plainq-headless?port=8083
```

| Option | Meaning |
| --- | --- |
| `namespace` | Namespace to search. In-cluster it defaults to the pod's own. |
| `service` | A Service whose Endpoints list the peers. |
| `selector` | A label selector, used when `service` is empty or has no endpoints. |
| `port` / `port-name` | The gossip port, fixed or by name. |
| `api-server`, `token-file` | Overrides for running outside a pod. |

Endpoints are tried first, then pods. The fallback matters: no PlainQ pod is
ready until it has joined a cluster, and it cannot join a cluster it cannot
see, so a service with no ready endpoints would otherwise stall a cluster
forming for the first time. Not-ready endpoints count as peers for the same
reason.

In-cluster the provider authenticates with the mounted service account and
trusts the cluster CA. It needs `get` and `list` on `pods` and `endpoints` in
its namespace — the Helm chart creates that Role for you.

### Docker

```
docker://?label=plainq.cluster%3Dprod&port=8083
docker://plainq.cluster=prod?network=plainq&port=8083
```

Containers carrying the label are the cluster. Addresses come from the shared
Docker network, so peers reach each other on the container network rather than
through published ports. Requires the Docker socket
(`/var/run/docker.sock`, or set `host=tcp://…`).

### AWS

```
aws://?region=eu-west-1&tag=Cluster%3Dplainq&port=8083
```

EC2 instances matching the tag. Credentials come from the standard chain —
environment, shared config, instance profile, or ECS task role — and the
instance needs `ec2:DescribeInstances`. Private IPs by default; add
`public=true` for public ones. Arbitrary EC2 filters work too, e.g.
`aws://?region=…&tag:Environment=prod&instance-type=m5.large`.

### GCP

```
gcp://?project=plainq-prod&label=cluster%3Dplainq&port=8083
gcp://?project=plainq-prod&zone=europe-west1-b&filter=labels.cluster%3Dplainq
```

Compute Engine instances matching the filter. Authentication comes from the
instance metadata server, so the workload's service account needs
`compute.instances.list`. Without a `zone` it searches the whole project.

### Azure

```
azure://?subscription=<id>&tag=cluster%3Dplainq&port=8083
azure://?subscription=<id>&resource-group=plainq&scale-set=plainq-vmss&tag=cluster%3Dplainq
```

Virtual machines and scale-set instances carrying the tag, via Azure Resource
Graph. Authentication comes from the instance's managed identity, which needs
`Reader` on the subscription or resource group.

### Consul

```
consul://?address=http://127.0.0.1:8500&service=plainq&tag=cluster
consul://127.0.0.1:8500/plainq
```

Healthy instances of a registered service. `token` sets an ACL token, `dc`
selects a datacenter.

## Security

Cluster traffic carries every message body in the system. Three separate
controls, and you want all three in production:

**Gossip encryption** — `-cluster.gossip.secret`, base64 of a 16, 24 or 32 byte
key. Generate one with `openssl rand -base64 32`. The same key on every node.
Without it, gossip is in the clear and anyone who can reach the port can join.

The key is base64 and only base64. A raw-string fallback would be friendlier
and is a trap: a 32-character key like `0123456789abcdef0123456789abcdef` is
*also* valid base64, so half your cluster would read it as 32 raw bytes and the
other half as the 24 bytes it decodes to, and nothing would say why they cannot
talk.

**Peer RPC authentication** — `-cluster.secret`, any shared string, compared in
constant time. It guards the internal RPC that forwards writes to the leader
and admits nodes to the cluster.

**TLS** — `-cluster.tls.cert`, `-cluster.tls.key`, `-cluster.tls.ca`. All three
or none. Nodes authenticate each other against the cluster CA rather than by
hostname, since they dial each other by IP.

Run the cluster ports on a private network regardless. They are not a public
API.

## Consistency

`-cluster.consistency` decides where reads are served.

**`local`** (default) answers `ListQueues`, `DescribeQueue` and message
browsing from the local replica. It costs nothing, scales with the cluster, and
lags the leader by however long replication takes — typically a millisecond or
two. For a dashboard or a queue listing, that is not a property anyone is
relying on.

**`strong`** routes those reads through the leader behind a consensus barrier,
so a read never returns state older than a write that already completed. It
costs a round trip, and followers answer `409 Conflict` naming the leader
rather than serving a read they cannot make strong.

Writes — including `Receive` — are always linearizable regardless of this
setting.

## Operating a cluster

### Status

```shell
plainq cluster status              # this node's view, plus every member
plainq cluster members             # just the members
plainq cluster members -json       # for scripts
```

Or over HTTP (administrator-only):

```
GET    /api/v1/cluster              status, members, quorum, log position
GET    /api/v1/cluster/members      members only
POST   /api/v1/cluster/members      add a node by hand
DELETE /api/v1/cluster/members/{id} remove a node
POST   /api/v1/cluster/snapshot     force a snapshot, compacting the log
```

The status shows both views side by side — what consensus agreed, and what
gossip can actually see. They differ during a failure, and the difference is
the most useful thing on the page. A member with `SUFFRAGE` of `not admitted`
is up and gossiping but not yet in the configuration.

### Metrics

The `/metrics` endpoint gains a cluster section. The state of the node itself,
all labelled with `node_id`:

| Metric | Meaning |
| --- | --- |
| `plainq_cluster_healthy` | `1` when the cluster can commit a write. **Alert on `0`.** |
| `plainq_cluster_leader` | `1` on the leader, `0` on followers. Sum across the cluster should be exactly `1`. |
| `plainq_cluster_term` | Current consensus term. Climbing steadily means repeated elections. |
| `plainq_cluster_commit_index` | Highest committed log index. |
| `plainq_cluster_applied_index` | Highest index this node has applied. The gap from the commit index is this replica's lag. |
| `plainq_cluster_last_index` | Last index stored locally. |
| `plainq_cluster_voters` | Voters in the configuration. |
| `plainq_cluster_quorum` | Voters a write needs. Compare with `members_reachable` to see how many more failures the cluster survives. |
| `plainq_cluster_members` | Members known, voters and non-voters. |
| `plainq_cluster_members_reachable` | Members gossip can currently see. Below quorum and the cluster cannot commit. |
| `plainq_cluster_leader_last_contact_seconds` | How long ago this follower heard from the leader. |
| `plainq_cluster_commands_applied_total` | Commands applied to the local replica. |
| `plainq_cluster_commands_failed_total` | Commands that failed to apply. A steady climb is worth investigating; a rejected `CreateQueue` is a legitimate one. |
| `plainq_cluster_node_info` | Constant `1` carrying `node_id`, `version` and `engine` as labels — join it onto anything to colour by build. |

The write path, labelled by `operation` and `result`:

| Metric | Meaning |
| --- | --- |
| `plainq_cluster_applies_total` | Writes this node proposed through consensus. |
| `plainq_cluster_apply_duration_seconds` | Propose → commit → apply. **This is the cost clustering adds to a write.** |
| `plainq_cluster_forwards_total` | Writes a follower handed to the leader. |
| `plainq_cluster_forward_duration_seconds` | Round-trip of a forwarded write. Its gap from `apply_duration` is the network hop. |
| `plainq_cluster_not_leader_total` | Writes rejected for want of a leader. Spikes during an election. |
| `plainq_cluster_leadership_changes_total` | Leadership gained or lost, by `state`. |
| `plainq_cluster_fsm_applies_total` | Log entries applied to the local state machine. |
| `plainq_cluster_fsm_apply_duration_seconds` | Time in the state machine. Consistently slow means followers fall behind. |
| `plainq_cluster_determinism_overflows_total` | Commands that needed more identifiers than the leader assigned — a fan-out that raced a subscription change. |
| `plainq_cluster_sweeps_total` | Retention sweeps the leader proposed through the log. |

Snapshots and catch-up:

| Metric | Meaning |
| --- | --- |
| `plainq_cluster_snapshots_total` | Snapshots taken, by `result`. |
| `plainq_cluster_snapshot_duration_seconds`, `plainq_cluster_snapshot_bytes` | How long one took and how big it was — what a joining node has to pull. |
| `plainq_cluster_snapshot_records_total` | What went into them, by `kind`. |
| `plainq_cluster_restores_total`, `plainq_cluster_restore_duration_seconds` | Restores and how long the node was not serving reads. |
| `plainq_cluster_restore_records_total` | What came back out, by `kind`. |

Membership, discovery and the wire:

| Metric | Meaning |
| --- | --- |
| `plainq_cluster_gossip_members` | The gossip view, by `state` (`alive`, `suspect`, `left`, `failed`). |
| `plainq_cluster_gossip_events_total` | Membership events by `type`. A steady stream of join/leave pairs is a flapping node. |
| `plainq_cluster_gossip_joins_total`, `plainq_cluster_gossip_join_peers` | Join attempts and how many peers each reached. |
| `plainq_cluster_membership_changes_total` | Changes the leader made while reconciling, by `action` and `result`. |
| `plainq_cluster_discovery_runs_total` | Discovery queries by `provider` and `result`. **A provider failing every run is a misconfigured cluster that has not noticed yet.** |
| `plainq_cluster_discovery_duration_seconds`, `plainq_cluster_discovery_peers` | How long each provider took and what it last returned. |
| `plainq_cluster_peer_requests_total`, `plainq_cluster_peer_request_duration_seconds` | Internal peer RPC, by `path`. |
| `plainq_cluster_peer_auth_failures_total` | Peer RPCs rejected for a bad shared secret. On a private network this should be flat at zero. |
| `plainq_cluster_transport_connections_total` | Connections on the cluster port, by `protocol` and `direction`. |
| `plainq_cluster_transport_handshake_failures_total` | Inbound connections dropped before naming a protocol. |

Two queries worth having on a dashboard from the start:

```promql
# Replica lag. Sustained non-zero means this node cannot keep up with the log.
plainq_cluster_commit_index - plainq_cluster_applied_index

# What clustering costs a write, at the 99th percentile.
histogram_quantile(0.99, sum by (le, operation) (rate(plainq_cluster_apply_duration_seconds_bucket[5m])))
```

Discovery providers are named individually, so a fan-out over several does not
collapse into one indistinguishable "discovery failed":

```promql
sum by (provider) (rate(plainq_cluster_discovery_runs_total{result="error"}[15m])) > 0
```

The full catalog — every family, its labels and what it means — is at
`GET /api/v1/metrics/catalog`, and in the
[observability guide](observability.md#what-is-measured).

### Adding a node

Start it with the same discovery configuration and no `-cluster.bootstrap*`
flags. It finds the cluster, asks to be admitted, and catches up — from the log
if it is close enough, from a snapshot if it is not.

To add one by hand:

```shell
plainq cluster join -node-id=node-4 -addr=10.0.0.4:8082
```

### Removing a node

A node that is going away for good should leave deliberately, so the cluster
stops counting it toward quorum:

```shell
plainq cluster leave -node-id=node-3
```

A node that simply restarts should **not** leave — a restart is not a
departure, and a node that removed itself on every shutdown could never rejoin
the cluster it belongs to.

### Rolling upgrades

One node at a time. Wait for each to rejoin and catch up (`appliedIndex` close
to `commitIndex` in the status) before taking the next one down. The status
reports each member's build version, so a rolling upgrade is visible while it
is in progress.

### Backups

Every node holds a complete copy, so any node's `plainq.db` is a full backup.
Snapshot a stopped node, or use Litestream against a follower.

## Kubernetes

The bundled Helm chart deploys a clustered PlainQ:

```shell
helm install plainq deploy/helm/plainq \
  --set cluster.enabled=true \
  --set cluster.replicas=3 \
  --set cluster.gossipSecret="$(openssl rand -base64 32)" \
  --set cluster.secret="$(openssl rand -hex 32)" \
  --set auth.jwtSecret="$(openssl rand -hex 32)"
```

That gives you:

- A StatefulSet of three pods with `podManagementPolicy: Parallel`, so they
  come up together — `bootstrap-expect` waits for all of them, and
  `OrderedReady` would deadlock waiting for a readiness that cannot arrive
  until they have found each other.
- One PersistentVolumeClaim per pod via `volumeClaimTemplates`. Each node keeps
  its own replica and its own consensus log; a shared volume would have every
  node writing the same SQLite file.
- A headless service with `publishNotReadyAddresses: true` for stable per-pod
  DNS.
- A Role and RoleBinding letting the pods list pods and endpoints in their own
  namespace, for Kubernetes discovery.
- Each pod's name as its node id (stable across restarts, which the consensus
  log requires) and its pod IP as its advertised address.

Set `cluster.discovery=dns` to use the headless service instead of the API and
skip the RBAC grant — at the cost of only seeing pods that are already ready,
which suits adding nodes to an existing cluster rather than forming one.

Scaling with `kubectl scale` adds pods; the leader admits them automatically.
Scaling *down* leaves the removed nodes in the configuration — remove them with
`plainq cluster leave`, or enable `cluster.autoRemove`.

## Postgres

Cluster mode replicates the embedded store, so it requires
`-storage.driver=sqlite`. With Postgres the database is already shared between
nodes and replicating it would write every message twice; run several
stateless PlainQ nodes against one Postgres instead, and let Postgres own the
replication.

The server refuses `-cluster.enable` with `-storage.driver=postgres` rather
than doing something surprising.

Cluster mode also requires WAL journal mode, which it sets for you. Snapshots
take long read transactions, and outside WAL those stall every write.

## Configuration reference

| Flag | Default | Description |
| --- | --- | --- |
| `-cluster.enable` | `false` | Run as a cluster member. |
| `-cluster.node-id` | hostname | Stable, unique cluster identity. Must survive restarts. |
| `-cluster.bind.addr` | `:8082` | Consensus and internal peer RPC (muxed on one port). |
| `-cluster.advertise.addr` | — | What peers dial. Required when the bind address is `0.0.0.0`. |
| `-cluster.gossip.addr` | `:8083` | Membership gossip (TCP and UDP). |
| `-cluster.gossip.advertise.addr` | derived | Defaults to the host of `-cluster.advertise.addr`. |
| `-cluster.gossip.secret` | — | Base64 16/24/32-byte gossip key. |
| `-cluster.gossip.profile` | `lan` | Failure-detector timing: `lan`, `wan`, `local`. |
| `-cluster.secret` | — | Shared secret for internal peer RPC. |
| `-cluster.data.dir` | next to the DB | Consensus log and snapshots. |
| `-cluster.discovery` | — | How to find peers. See [Discovery](#discovery). |
| `-cluster.discovery.interval` | `15s` | How often discovery re-runs. |
| `-cluster.bootstrap` | `false` | Form a single-node cluster. One node, once. |
| `-cluster.bootstrap-expect` | `0` | Wait for N nodes, then form a cluster from all of them. |
| `-cluster.non-voter` | `false` | Replicate without voting. |
| `-cluster.consistency` | `local` | `local` or `strong` reads. |
| `-cluster.reconcile.interval` | `30s` | How often the leader reconciles gossip against the configuration. |
| `-cluster.auto-remove` | `false` | Let the leader remove long-unreachable members. |
| `-cluster.remove.timeout` | `5m` | How long "unreachable" has to last first. |
| `-cluster.sweep.interval` | `5m` | How often the leader proposes eviction. |
| `-cluster.apply.timeout` | `15s` | How long a replicated write may take. |
| `-cluster.raft.*` | engine defaults | Heartbeat, election, lease, commit, snapshot tuning. |
| `-cluster.tls.cert/key/ca` | — | Mutual TLS between nodes. All three or none. |

### Bootstrapping

Three ways in, and the difference matters:

- **`-cluster.bootstrap`** forms a one-node cluster immediately. Set it on
  exactly one node, exactly once. Two nodes bootstrapping independently
  produce two clusters that each believe they are *the* cluster, and there is
  no automatic recovery from that.
- **`-cluster.bootstrap-expect=N`** waits until N nodes are visible and then
  has the lowest-numbered one form a cluster containing all of them. Every node
  gets identical configuration, and only one actually bootstraps. This is what
  you want for a new cluster, and what the Helm chart uses.
- **Neither** joins an existing cluster through discovery. This is what you
  want for a node added later.

A node that already has consensus state ignores all of this and rejoins the
cluster it belongs to — which is why a restart is safe.

## Troubleshooting

**"cluster bind address is unspecified and no advertise address is set."**
You bound `0.0.0.0` without telling peers what to dial. Every node would be
telling the others to dial "anywhere". Set `-cluster.advertise.addr` to this
node's routable address.

**No leader is ever elected.** Check that the nodes can reach each other on
*both* the cluster port and the gossip port, TCP **and UDP** for gossip. Check
that `-cluster.bootstrap-expect` matches the number of nodes actually starting:
a cluster of three waiting for four never forms. `plainq cluster status` shows
what each node can see.

**A node is listed but `SUFFRAGE` is empty.** Gossip can see it; consensus has
not admitted it yet. The leader reconciles on `-cluster.reconcile.interval`.
If it stays that way, the leader could not reach the node's *consensus* port —
gossip and consensus use different ports, and a firewall rule often covers only
one.

**Writes fail with "cluster has no leader".** An election is in progress, or
quorum is lost. Writes wait out a normal election on their own; if it persists,
you have lost a majority. Check how many voters are reachable in
`plainq cluster status` — you need more than half.

**A removed pod is still counted in quorum.** Scaling down does not remove a
node from the configuration. Use `plainq cluster leave -node-id=…`, or enable
`-cluster.auto-remove`.

**Two clusters exist where there should be one.** Someone set
`-cluster.bootstrap` on more than one node. There is no automatic merge: pick
the cluster with the data you want, stop the other nodes, delete their
`-cluster.data.dir`, and let them rejoin.

## See also

- [Deployment](deployment.md) — images, the Helm chart, resource sizing.
- [Observability](observability.md) — metrics and health endpoints.
- [Configuration](configuration.md) — the non-cluster flags.
- [Design notes](../superpowers/specs/2026-07-26-clustering-design.md) — why it
  is built this way.
