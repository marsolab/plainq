# PlainQ Kubernetes operator

A controller that turns the PlainQ surface — servers, clusters, queues, topics,
accounts — into Kubernetes objects and keeps reality matching them.

- **Source:** [`operator/`](../../operator) (a separate Go module)
- **Design:** [`docs/superpowers/specs/2026-07-26-kubernetes-operator-design.md`](../../docs/superpowers/specs/2026-07-26-kubernetes-operator-design.md)
- **Implementation plan:** [`docs/superpowers/plans/2026-07-26-kubernetes-operator-implementation.md`](../../docs/superpowers/plans/2026-07-26-kubernetes-operator-implementation.md)

## What works today

The provisioning operator — steps 1–9 of the plan, which that plan calls out as
independently shippable.

| Capability | State |
| --- | --- |
| All seven CRDs, with validation, printer columns and status | ✅ |
| Provision single-node SQLite, Postgres-backed, and Raft clusters | ✅ |
| Every `serve` flag reachable, plus `extraArgs` | ✅ |
| Bootstrap the first admin without a browser | ✅ |
| Declarative queues, with dead-letter ordering and drift reporting | ✅ |
| Declarative topics and subscriptions | ✅ |
| Accounts, with the registration constraint enforced at admission | ✅ |
| Supervised cluster scale-in (voter removed before pod) | ✅ |
| Quorum-derived PodDisruptionBudget, NetworkPolicy, Ingress, HPA | ✅ |
| Cutover alias Service | ✅ |
| Admission webhooks (defaulting + validation) | ✅ |
| **Backups** — `PlainQBackupPolicy`, `PlainQBackup` | ⏳ API only, no controller |
| **Restores** — `PlainQRestore` | ⏳ API only, no controller |
| Backup agent sidecar (`cmd/agent`) | ⏳ not started |

The backup and restore CRDs install and validate, so manifests written against
them are correct — but nothing reconciles them yet. Do not rely on them for
data protection; keep using [Litestream](../../docs/guides/deployment.md) until
the controllers land.

## Operator or Helm chart?

Both ship. They answer different questions.

| | [Helm chart](../helm/plainq) | Operator |
| --- | --- | --- |
| Install one PlainQ | ✅ one command | ✅ one `PlainQ` object |
| Provision queues and topics | ❌ manual | ✅ `PlainQQueue`, `PlainQTopic` |
| First admin account | ❌ browser onboarding | ✅ `spec.bootstrap` |
| Safe cluster scale-in | ❌ `kubectl scale` can break quorum | ✅ supervised drain |
| Backups and restores | ❌ | ⏳ designed, not built |
| Needs cluster-wide CRDs | no | yes |

Start with the chart. Move to the operator when you have more than one
instance, or when you want queues under version control.

## Install

```shell
cd operator

make install                      # CRDs only
make deploy IMAGE=... VERSION=...  # CRDs, RBAC and the manager

# Or run it locally against your current kubecontext:
make run
```

`make run` disables leader election and the webhooks, because the webhooks need
a serving certificate. Validation still runs — the rules live in
`internal/validation` and the reconcilers re-check the ones that depend on live
cluster state — but rejections arrive as conditions rather than at admission.

Migrating from the chart is a `PlainQ` with
`storage.sqlite.persistence.existingClaim` pointing at the chart's PVC and
`auth.jwtSecretRef` at its Secret: same volume, same secret, no data movement.

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

Samples 05–07 describe the backup and restore API, which installs but does not
reconcile yet.

These are not decoration: `operator/internal/manifests` decodes every one of
them strictly against the Go types on each `make test`, so a misspelled or
removed field fails in CI rather than at someone's `kubectl apply`.
