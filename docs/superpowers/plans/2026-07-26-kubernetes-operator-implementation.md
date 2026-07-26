# PlainQ Kubernetes operator — implementation

Plan for [the operator design](../specs/2026-07-26-kubernetes-operator-design.md).
Status: proposed.

## Shape of the change

A second Go module, `operator/`, holding two binaries: the controller manager
and a small agent that runs as a sidecar (backups) and as an init container
(restores). Nothing in `internal/` or `cmd/` changes — the server keeps its
current dependency graph and its current binary size.

The seam between the two modules is the **REST API on `:8081`**. The operator
never links PlainQ code; it speaks HTTP to it, exactly as Houston does. That
keeps the coupling to a wire contract instead of a package boundary, and it
means the operator can manage instances it did not provision.

New packages, bottom-up:

| Package | What it does |
| --- | --- |
| `operator/api/v1alpha1` | The seven CRD types, deepcopy, defaulting helpers. |
| `operator/internal/plainqapi` | REST client, token cache with proactive refresh, cluster admin calls. |
| `operator/internal/render` | `PlainQSpec` → StatefulSet/Deployment/Service/PVC/Secret/… |
| `operator/internal/backup` | Engines (`Litestream`, `Online`, `VolumeSnapshot`, `PostgresDump`), destinations (S3, filesystem), compression, encryption, retention, verification. |
| `operator/internal/controller` | One reconciler per kind. |
| `operator/internal/webhook` | Defaulting and validating webhooks. |
| `operator/cmd/manager` | Manager wiring, leader election, flags. |
| `operator/cmd/agent` | `backup`, `restore`, and `serve` (the sidecar control API). |

## Steps

1. **Scaffold.** `kubebuilder init` into `operator/` with its own `go.mod`,
   `PROJECT`, `Makefile`, and kustomize `config/` tree. Wire `make -C operator`
   targets into the root `Makefile` (`operator-build`, `operator-test`,
   `operator-manifests`, `operator-e2e`) so the repo has one entry point.

2. **API types.** All seven kinds in `api/v1alpha1`, with kubebuilder markers
   for validation (enums, patterns, minimums), printer columns, subresources,
   and short names (`pq`, `pqq`, `pqt`, `pqb`, `pqbp`, `pqr`, `pqa`). Generate
   CRDs and deepcopy. No controllers yet — the API is the contract and it is
   worth reviewing before anything reconciles against it.

3. **`plainqapi` client.** Typed methods for onboarding, signin/refresh, queues,
   topics, subscriptions, cluster status/members/join/remove/snapshot, and
   system config. Token cache keyed by instance, refreshed before expiry, with a
   retry/backoff policy that distinguishes "server is starting" from "server
   said no". Tested against an `httptest` fake implementing the same routes as
   `internal/server/service/queue` and friends.

4. **`render`.** Port `deploy/helm/plainq/templates/_pod.tpl` into Go: args
   builder, env builder (`$(VAR)` secret references), cluster args, discovery
   spec, container spec, volumes. Then the workload selector — StatefulSet for
   SQLite, StatefulSet with `volumeClaimTemplates` + `Parallel` for cluster,
   Deployment for Postgres — plus Services, PVC, Secrets, ServiceAccount, RBAC,
   PDB, Ingress, NetworkPolicy, ServiceMonitor. Golden-file tests assert the
   output matches `helm template` for equivalent inputs; that test is what keeps
   the chart and the operator from diverging.

5. **`PlainQ` reconciler, provisioning only.** Create/patch owned resources,
   generate missing Secrets, set `status.phase`, conditions, endpoints, and
   `observedGeneration`. Server-side apply with a field manager so hand-edits to
   owned objects are reverted deliberately rather than fought over.

6. **Bootstrap + `PlainQAccount`.** `GET /api/v1/onboarding/status`, then
   `POST /api/v1/onboarding/complete` with credentials generated into the admin
   Secret. Once complete, the reconciler can authenticate, which unblocks
   everything downstream. `PlainQAccount` for non-bootstrap accounts, with
   role assignment through `/api/v1/rbac`.

7. **Cluster status and formation.** Poll `/api/v1/cluster` and
   `/api/v1/cluster/members`, project into `status.cluster`, set `ClusterFormed`
   and `Degraded`. Formation watchdog with an event that names what each pod
   sees when the timeout expires.

8. **`PlainQQueue` and `PlainQTopic`.** Create/describe/delete, name→ID
   resolution, `deadLetterQueueRef` dependency ordering with backoff, drift
   detection with the `Reject`/`Recreate` update policy, finalizers with
   `Retain`/`Delete`. Topics reconcile subscriptions as a set.

9. **Webhooks.** Defaulting and the validation table from the design. Cert
   management through cert-manager when present, self-signed generation
   otherwise, so the operator installs on a bare cluster.

10. **Backup — destinations and pipeline.** S3 (path-style, custom endpoints,
    IRSA/workload identity, SSE, private CAs) and filesystem. Then the shared
    pipeline: read → compress (zstd/gzip/none) → encrypt (age) → upload →
    checksum. Streamed, never buffered whole: a 50Gi database must not need
    50Gi of sidecar memory.

11. **Backup — engines.** `Online` first (agent sidecar, `VACUUM INTO`, control
    API guarded by a bearer token), because it is the default and the hardest.
    Then `Litestream` (rendered config, sidecar, lag reported into status), then
    `PostgresDump`, then `VolumeSnapshot`.

12. **`PlainQBackupPolicy` + `PlainQBackup`.** CronJob owned by the policy, each
    firing creating a `PlainQBackup`; the backup reconciler runs the engine and
    fills status. Source selection in a cluster: non-voter, else follower, never
    the leader; `POST /api/v1/cluster/snapshot` on the chosen node first.
    Retention with grandfather-father-son semantics pruning both artifacts and
    CRs. `verify: Restore` as a throwaway Job running `PRAGMA integrity_check`.

13. **`PlainQRestore`.** `NewInstance` first — an owned `PlainQ` with a restore
    init container — because it is the default and the non-destructive one.
    Then `InPlace`: scale to zero, restore Job, cluster data-dir wipe,
    single-node `-cluster.bootstrap` bring-up, peers rejoin. Then
    `recreateResources` re-applying queues and topics against the target.

14. **Cluster scale-in and quorum-aware upgrades.** The supervised drain:
    quorum check → `DELETE /api/v1/cluster/members/{id}` → wait for the member
    to disappear → scale down one → optional PVC reclaim → repeat. Then the
    `OnDelete`-driven rolling upgrade, leader last.

15. **Observability.** Operator metrics, events on every consequential action,
    the `PrometheusRule` alert set, the Grafana dashboard ConfigMap.

16. **Packaging.** `config/` kustomize bundle, a generated
    `dist/plainq-operator.yaml` single-file install, and
    `deploy/helm/plainq-operator` for people who install by chart. Multi-arch
    images for the manager and the agent, built by the release workflow
    alongside the server image and tagged with the same version.

17. **Docs.** `docs/guides/kubernetes-operator.md` (install, provision, tune,
    back up, restore, scale), `docs/reference/operator-api.md` (generated CRD
    field reference), links from `docs/README.md`, `README.md`, and
    `docs/guides/deployment.md`, plus a note in the Helm chart README explaining
    which path to choose.

## Testing strategy

- Unit tests per package; `render` golden files diffed against `helm template`.
- Envtest for every reconciler: creation, drift, finalizer, ordering,
  immutable-field rejection, webhook admission.
- A fake PlainQ REST server exercising success, conflict, 5xx, and timeout.
- kind e2e: single node, Postgres, 3-node cluster; scale 3→5→3; backup to MinIO
  and restore asserting message-level round-trip; rolling upgrade under load
  asserting zero loss.
- Chaos: leader killed mid-backup, operator killed mid-restore, S3 credential
  revoked mid-upload. Each must land in a status a human can act on.

## Sequencing

Steps 1–9 are the provisioning operator and are independently shippable —
they already replace the chart for fleet use. Steps 10–13 are the backup and
restore story, which is the reason most people will adopt it. Step 14 is the
cluster-lifecycle safety net. 15–17 are release quality.

The server-side gaps listed in the design (`UpdateQueue`, leadership transfer)
are separate work. `UpdateQueue` should be scheduled alongside step 8, because
until it exists `updatePolicy` has no good default.
