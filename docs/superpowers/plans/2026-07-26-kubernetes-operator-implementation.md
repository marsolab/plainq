# PlainQ Kubernetes operator — implementation

Plan for [the operator design](../specs/2026-07-26-kubernetes-operator-design.md).
Status: in progress — steps 1–9 and 14 are built and tested in
[`operator/`](../../../operator); steps 10–13 (backup and restore controllers,
the agent sidecar) are API-only so far. See the
[operator README](../../../deploy/operator/README.md) for the current
capability table.

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

   Two REST shapes to get right here, because both are worked around rather
   than used directly: `ResolveQueueByName` pages
   `GET /api/v1/queue?prefix=<name>` and matches exactly, since
   `GET /api/v1/queue/{id}` only accepts an ID; and `WaitForApplied(nodeAddr,
   index)` polls a node's `appliedIndex` against a leader commit index captured
   beforehand.

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

   Because that revert is deliberate, the alias Service is the *one* thing the
   operator manages without tying it to a `PlainQ` owner: it is how a cutover
   survives the next reconcile. Claim tracking (one holder per alias name, with
   webhook enforcement) belongs here, not in the restore controller.

6. **Bootstrap + `PlainQAccount`.** `GET /api/v1/onboarding/status`, then
   `POST /api/v1/onboarding/complete` with credentials generated into the admin
   Secret. Once complete, the reconciler can authenticate, which unblocks
   everything downstream.

   `PlainQAccount` for non-bootstrap accounts goes through
   `POST /api/v1/account/signup` plus role assignment via `/api/v1/rbac` — and
   that route refuses whenever the target instance has registration disabled.
   Implement the webhook rejection for that combination *before* the
   reconciler, so the failure is an admission error naming the cause rather
   than a 401 loop in a controller log.

7. **Cluster status and formation.** Poll `/api/v1/cluster` and
   `/api/v1/cluster/members`, project into `status.cluster`, set `ClusterFormed`
   and `Degraded`. Formation watchdog with an event that names what each pod
   sees when the timeout expires.

8. **`PlainQQueue` and `PlainQTopic`.** Create/describe/delete, name→ID
   resolution through the prefix scan from step 3 with the result cached in
   `status.queueID`, `deadLetterQueueRef` dependency ordering with backoff,
   drift detection with the `Reject`/`Recreate` update policy, finalizers with
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
    fills status. Retention with grandfather-father-son semantics pruning both
    artifacts and CRs. `verify: Restore` as a throwaway Job running
    `PRAGMA integrity_check`.

    Two invariants to build in from the start, because retrofitting either one
    invalidates every backup taken before it:

    - **Freeze `status.effectiveConfig` before execution.** Destination,
      endpoint, credential and encryption *references*, compression, engine,
      and the source instance's shape. A run that only remembers `policyRef`
      stops being restorable the moment the policy is edited.
    - **Prove the source is caught up.** Select non-voter, else follower, never
      the leader — then capture the leader's `commitIndex`, wait for the source
      node's `appliedIndex` to reach it (bounded by `sourceSyncTimeout`), and
      only then `POST /api/v1/cluster/snapshot` and copy. `Healthy` on a
      cluster does not imply a given follower has applied everything committed.

13. **`PlainQRestore`.** `NewInstance` first — a `PlainQ` with a restore init
    container — because it is the default and the non-destructive one. It is
    created with a `plainq.dev/restored-from` annotation and **no owner
    reference**: deleting a completed restore record must never cascade into
    the instance it produced. Spec inheritance comes from the backup's frozen
    `effectiveConfig.source`; raw-location sources inherit nothing and require a
    complete `newInstance.spec`, enforced at admission.

    Then `InPlace`: scale to zero, restore Job, cluster data-dir wipe,
    single-node `-cluster.bootstrap` bring-up, peers rejoin. Then
    `recreateResources` re-applying queues and topics against the target, and
    the alias move from step 5 as the documented cutover.

14. **Cluster scale-in and quorum-aware upgrades.** The supervised drain, one
    node at a time: check that *this* removal can commit against the current
    configuration → `DELETE /api/v1/cluster/members/{id}` → wait for the member
    to disappear and a leader to be reported under the new quorum → scale down
    one → optional PVC reclaim → repeat. Quorum is recomputed after each
    committed change, so 3→2→1 is safe step by step even though 1 is below the
    quorum the cluster started with; the check must never compare the final
    target against the original quorum. Then the `OnDelete`-driven rolling
    upgrade, leader last.

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
- kind e2e: single node, Postgres, 3-node cluster; scale 3→5→3 *and* a full
  3→2→1 drain, asserting each step commits; backup to MinIO and restore
  asserting message-level round-trip; rolling upgrade under load asserting zero
  loss.
- Regression tests for the four invariants that are silent when broken: a
  backup taken from a deliberately lagged follower must not complete until the
  follower catches up; a backup must restore after its policy has been edited
  *and* after it has been deleted; deleting a completed `PlainQRestore` must
  leave the restored instance running; and an alias move must survive the
  previous owner's next reconcile.
- Chaos: leader killed mid-backup, operator killed mid-restore, S3 credential
  revoked mid-upload. Each must land in a status a human can act on.

## Sequencing

Steps 1–9 are the provisioning operator and are independently shippable —
they already replace the chart for fleet use. Steps 10–13 are the backup and
restore story, which is the reason most people will adopt it. Step 14 is the
cluster-lifecycle safety net. 15–17 are release quality.

The server-side gaps listed in the design are separate work, and three of them
have workarounds baked into the steps above that should not become permanent:

- **`UpdateQueue`** alongside step 8 — until it exists `updatePolicy` has no
  good default.
- **An admin-only account-creation endpoint** alongside step 6 — until it
  exists, non-bootstrap `PlainQAccount` is rejected against any instance with
  self-registration disabled, which is most production instances.
- **A name-capable queue lookup** alongside step 3 — until it exists, every
  first resolution is a paged scan.
