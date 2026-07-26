# PlainQ Kubernetes operator

A design for a controller that turns the whole PlainQ surface — servers,
clusters, queues, topics, accounts, backups, restores — into Kubernetes objects
and keeps reality matching them.

- **Design:** [`docs/superpowers/specs/2026-07-26-kubernetes-operator-design.md`](../../docs/superpowers/specs/2026-07-26-kubernetes-operator-design.md)
- **Implementation plan:** [`docs/superpowers/plans/2026-07-26-kubernetes-operator-implementation.md`](../../docs/superpowers/plans/2026-07-26-kubernetes-operator-implementation.md)

> **Status: proposed.** The manifests in [`samples/`](samples) are the design's
> API surface written out as YAML. There is no controller yet — applying them
> today will fail because the CRDs do not exist. They are here so the API can be
> reviewed as something you would actually type.

## Operator or Helm chart?

Both ship. They answer different questions.

| | [Helm chart](../helm/plainq) | Operator |
| --- | --- | --- |
| Install one PlainQ | ✅ one command | ✅ one `PlainQ` object |
| Provision queues and topics | ❌ manual | ✅ `PlainQQueue`, `PlainQTopic` |
| First admin account | ❌ browser onboarding | ✅ `spec.bootstrap` |
| Scheduled backups to S3 / filesystem | ❌ | ✅ `PlainQBackupPolicy` |
| Continuous replication | ❌ run Litestream yourself | ✅ `continuous.enabled` |
| Restore | ❌ manual `litestream restore` | ✅ `PlainQRestore` |
| Safe cluster scale-in | ❌ `kubectl scale` can break quorum | ✅ supervised drain |
| Quorum-aware rolling upgrades | ❌ | ✅ |
| Needs cluster-wide CRDs | no | yes |

Start with the chart. Move to the operator when you have more than one instance,
or when you need backups you can restore from.

## Samples

| File | What it shows |
| --- | --- |
| [`01-single-node.yaml`](samples/01-single-node.yaml) | SQLite, one replica, persistent volume, bootstrapped admin. |
| [`02-cluster.yaml`](samples/02-cluster.yaml) | Three-node Raft cluster with Kubernetes discovery and tuned consensus timings. |
| [`03-postgres.yaml`](samples/03-postgres.yaml) | PostgreSQL backend, several replicas, autoscaling. |
| [`04-queues-and-topics.yaml`](samples/04-queues-and-topics.yaml) | Queues with dead-letter wiring, a topic with fan-out subscriptions. |
| [`05-backup-s3.yaml`](samples/05-backup-s3.yaml) | Continuous replication plus a nightly verified backup to S3-compatible storage. |
| [`06-backup-filesystem.yaml`](samples/06-backup-filesystem.yaml) | Scheduled backups to an NFS/CephFS volume, for on-prem and air-gapped clusters. |
| [`07-restore.yaml`](samples/07-restore.yaml) | Restore into a fresh instance, and point-in-time restore in place. |
