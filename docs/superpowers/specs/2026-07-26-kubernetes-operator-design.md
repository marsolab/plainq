# PlainQ Kubernetes operator — design

Status: proposed
Date: 2026-07-26

## Problem

PlainQ ships a good Helm chart. A chart renders manifests once and then stops
caring: it cannot form a Raft cluster safely, cannot take a backup, cannot
restore one, cannot create a queue, and cannot tell you that the queue you
declared three commits ago never actually got created because the server was
down that day.

Everything above the manifest is manual today:

- **Queues are imperative.** `plainq create` from a shell or a `kubectl exec`.
  Nothing reconciles them; nothing recreates them after a restore into a fresh
  volume.
- **Backups are a README.** The [deployment guide](../../guides/deployment.md)
  tells you to run Litestream yourself in a sidecar and to run
  `litestream restore` by hand. There is no schedule, no retention, no
  verification, no restore path that a human under pressure can trust.
- **Cluster lifecycle is unsupervised.** Scaling a StatefulSet down removes
  pods; it does not remove voters from the Raft configuration. Take a 3-node
  cluster to 1 with `kubectl scale` and you have lost quorum with no warning.
- **Bootstrapping needs a browser.** The first admin account is created by
  clicking through Houston's onboarding flow, which makes a from-scratch GitOps
  deployment impossible to complete without a human.

We want an operator: a controller that turns the whole product surface —
servers, clusters, queues, topics, accounts, backups, restores — into
declarative Kubernetes objects, and then keeps reality matching them.

## Goals

- **Provision PlainQ.** Single-node SQLite, a Postgres-backed deployment, or a
  Raft cluster, from one `PlainQ` object. Every `serve` flag reachable.
- **Provision queues and topics.** Declarative `PlainQQueue` and `PlainQTopic`
  with their tuning knobs (retention, visibility timeout, receive attempts,
  eviction policy, dead-letter wiring) and cross-object references.
- **Back up to a filesystem or S3-compatible storage.** Scheduled and
  continuous, with retention, compression, encryption, and verification.
- **Restore, believably.** A restore that a person can run at 3am from one YAML
  file, including into a fresh instance so the broken one stays intact.
- **Manage cluster lifecycle.** Safe scale-out, supervised scale-in that removes
  voters before pods, rolling upgrades that respect quorum.
- **Close the bootstrap gap.** Create the first admin account without a browser.
- **Stay optional.** The Helm chart keeps working, unchanged, for people who
  want one command and no CRDs.

## Non-goals

- Replacing the Helm chart. The operator is the fleet/lifecycle answer; the
  chart is the single-install answer. Both ship.
- Managing PostgreSQL itself. If you use the Postgres backend, its own operator
  owns the database; we consume a DSN.
- Autoscaling queue consumers. That is a workload concern, not ours. (We do
  expose the metrics a KEDA scaler would need — see [Observability](#observability).)
- Cross-cluster federation or multi-region replication.

## Where the operator lives

A **separate Go module**, `operator/`, with its own `go.mod`
(`github.com/marsolab/plainq/operator`), in this repository.

Same repo, because the operator's API surface is derived from the server's
flags and REST API and the two must move together; a split repo means a version
skew matrix nobody maintains.

Separate module, because `controller-runtime` pulls in the entire Kubernetes
client dependency tree. PlainQ's headline property is that it is one small
static binary; putting `k8s.io/api` into the server's build graph to get an
operator would be a poor trade. Two modules, two binaries, one repository, one
release tag.

```
operator/
├── go.mod                        # github.com/marsolab/plainq/operator
├── PROJECT                       # kubebuilder scaffolding metadata
├── Makefile
├── api/v1alpha1/                 # CRD Go types + deepcopy
├── cmd/
│   ├── manager/                  # the controller manager
│   └── agent/                    # backup/restore sidecar + init container
├── internal/
│   ├── controller/               # one reconciler per kind
│   ├── render/                   # PlainQ -> StatefulSet/Deployment/Service/...
│   ├── plainqapi/                # REST client, token cache, cluster admin
│   ├── backup/                   # engines, destinations, retention, verify
│   └── webhook/                  # defaulting + validation
└── config/                       # kustomize bases: crd, rbac, manager, samples
deploy/helm/plainq-operator/      # chart that installs the operator + CRDs
```

## Talking to PlainQ: REST, not gRPC

The operator uses the **HTTP REST API on `:8081`**, not the gRPC API, for every
control-plane call. Three reasons, in order of weight:

1. **gRPC has no authentication.** The queue gRPC surface does not enforce JWT
   (see the [deployment guide](../../guides/deployment.md#network-exposure));
   the REST surface does, through `middleware.AuthenticateJWT`. An operator
   should hold a credential, not rely on network position.
2. **Topics only exist on REST.** `POST /api/v1/queue/topics` and its
   subscription routes have no gRPC equivalent. A gRPC operator could not
   manage topics at all.
3. **Cluster and onboarding admin are REST-only.** `/api/v1/cluster/*`,
   `/api/v1/onboarding/*`, `/api/v1/system/config`.

The endpoints the operator depends on:

| Purpose | Endpoint |
| --- | --- |
| Bootstrap first admin | `GET /api/v1/onboarding/status`, `POST /api/v1/onboarding/complete` |
| Obtain / renew a token | `POST /api/v1/account/signin`, `POST /api/v1/account/refresh` |
| Queues | `POST /api/v1/queue`, `GET /api/v1/queue`, `GET /api/v1/queue/{id}`, `DELETE /api/v1/queue/{id}`, `POST /api/v1/queue/{id}/purge` |
| Topics | `POST /api/v1/queue/topics`, `GET /api/v1/queue/topics`, `DELETE /api/v1/queue/topics/{id}`, `POST /api/v1/queue/topics/{id}/subscriptions`, `DELETE /api/v1/queue/topics/{id}/subscriptions/{subID}` |
| Cluster | `GET /api/v1/cluster`, `GET /api/v1/cluster/members`, `POST /api/v1/cluster/members`, `DELETE /api/v1/cluster/members/{id}`, `POST /api/v1/cluster/snapshot` |
| Effective config | `GET /api/v1/system/config` |

`internal/plainqapi` owns a per-instance client with a cached access token and
proactive refresh, keyed by `namespace/name`. Credentials come from the admin
Secret the operator itself created during bootstrap, or from a user-supplied
Secret for instances the operator did not provision.

## API group and kinds

Group `plainq.dev`, version `v1alpha1`. All kinds namespaced.

| Kind | What it is |
| --- | --- |
| `PlainQ` | A server instance: single node, Postgres-backed, or a Raft cluster. |
| `PlainQQueue` | One queue on a referenced instance, with its tuning knobs. |
| `PlainQTopic` | One topic and its subscriptions. |
| `PlainQAccount` | An account on the instance — including the bootstrap admin. |
| `PlainQBackupPolicy` | Continuous replication and/or a backup schedule, with retention. |
| `PlainQBackup` | A single backup — created by a policy, or by hand for an ad-hoc one. |
| `PlainQRestore` | A restore of a backup into an existing or brand-new instance. |

Seven kinds, one per lifecycle noun. The split is deliberate: a backup *run* is
a different object from a backup *policy* because runs have their own status,
their own retention, and their own reason to be created by a human.

### Object graph

```
                    PlainQBackupPolicy ──schedules──▶ PlainQBackup
                            │                             │
                            │ targets                     │ restored by
                            ▼                             ▼
  PlainQQueue ──serverRef──▶ PlainQ ◀───targets─── PlainQRestore
       ▲                    ▲  ▲
       │ deadLetterQueueRef │  │ serverRef
       │                    │  │
  PlainQQueue          PlainQAccount  PlainQTopic
                                           │ subscriptions[].queueRef
                                           ▼
                                      PlainQQueue
```

Everything hangs off `PlainQ`. References are by object name, never by the
server-assigned queue ID — the operator resolves names to IDs and records them
in `status`, so a queue recreated after a restore keeps working without anyone
editing YAML.

## `PlainQ` — the server

The whole of `plainq serve` reachable declaratively. Fields map one-to-one onto
flags from the [configuration reference](../../reference/configuration.md);
anything we have not modelled is still reachable through `extraArgs`.

```yaml
apiVersion: plainq.dev/v1alpha1
kind: PlainQ
metadata:
  name: orders
spec:
  version: "1.4.0"                    # -> image tag when image.tag is empty
  image:
    repository: ghcr.io/marsolab/plainq
    tag: ""
    pullPolicy: IfNotPresent
    pullSecrets: []

  replicas: 1                         # ignored when cluster.enabled (see cluster.replicas)

  storage:
    driver: sqlite                    # sqlite | postgres          IMMUTABLE
    sqlite:
      path: /data/plainq.db
      journalMode: wal                # -storage.journal-mode
      accessMode: ""                  # -storage.access-mode
      persistence:
        enabled: true
        size: 8Gi
        storageClassName: ""
        accessModes: [ReadWriteOnce]
        existingClaim: ""             # adopt a volume from a Helm install
        annotations: {}
    postgres:
      dsnSecretRef: {name: plainq-pg, key: dsn}
    gc:
      timeout: 30m                    # -storage.gc.timeout
    log: false                        # -storage.log.enable

  listeners:
    grpc:
      port: 8080
    http:
      port: 8081
      readTimeout: 0s
      readHeaderTimeout: 0s
      writeTimeout: 0s
      idleTimeout: 0s

  auth:
    enabled: true
    jwtSecretRef: {name: "", key: jwt-secret}   # generated when empty
    accessTokenTTL: 60m
    refreshTokenTTL: 720h
    registration: true
    emailVerification: true

  cluster:
    enabled: false                    # IMMUTABLE
    replicas: 3
    clusterPort: 8082
    gossipPort: 8083
    discovery: kubernetes             # kubernetes | dns | custom
    discoverySpec: ""                 # verbatim -cluster.discovery when discovery=custom
    discoveryInterval: 15s
    consistency: local                # local | strong
    nonVoter: false
    bootstrapExpect: 0                # 0 -> defaults to cluster.replicas
    autoRemove: false
    removeTimeout: 5m
    reconcileInterval: 30s
    sweepInterval: 5m
    applyTimeout: 15s
    secretRef:                        # gossip + peer-RPC secrets; generated when empty
      name: ""
      gossipKey: gossip-secret
      secretKey: cluster-secret
    dataDir: /data/cluster
    raft:                             # all optional; empty -> engine default
      heartbeatTimeout: ""
      electionTimeout: ""
      leaderLeaseTimeout: ""
      commitTimeout: ""
      snapshotInterval: ""
      snapshotThreshold: 0
      trailingLogs: 0
    tls:
      secretRef: {name: "", certKey: tls.crt, keyKey: tls.key, caKey: ca.crt}
    podDisruptionBudget:
      enabled: true                   # maxUnavailable derived from quorum

  telemetry:
    enabled: true
    provider: sqlite
    collectionInterval: 10s
    gcInterval: 10m
    retentionPeriod: 336h
    prometheusBaseURL: ""
    log: false

  observability:
    health:
      enabled: true
      route: /health
      logs: false
      metrics: false
      reporter: ""
    metrics:
      enabled: true
      route: /metrics
      logs: false
      metrics: false
    serviceMonitor:
      enabled: false
      interval: 30s
      scrapeTimeout: 10s
      labels: {}
      relabelings: []
      metricRelabelings: []
    prometheusRule:
      enabled: false                  # ships the alert set in "Observability"
    grafanaDashboard:
      enabled: false                  # ConfigMap with the sidecar label

  logging:
    enabled: true
    level: info                       # debug | info | warning | error
    accessLogs: true

  server:
    cors: true
    profiler: false

  # Bootstrap the first admin without a browser. Credentials are read from the
  # Secret, or generated into it when it does not exist.
  bootstrap:
    enabled: true
    adminSecretRef: {name: orders-admin}   # keys: email, password

  networking:
    service:
      type: ClusterIP
      annotations: {}
      labels: {}
    ingress:
      enabled: false
      className: ""
      annotations: {}
      hosts: []                       # same shape as the Helm chart
      tls: []
    networkPolicy:
      enabled: false
      allowFrom: []                   # podSelectors/namespaceSelectors allowed to reach grpc+http

  # Standard pod plumbing, applied to every rendered workload.
  pod:
    resources: {}
    nodeSelector: {}
    tolerations: []
    affinity: {}
    topologySpreadConstraints: []
    annotations: {}
    labels: {}
    securityContext: {}               # pod-level; hardened default
    containerSecurityContext: {}      # container-level; hardened default
    priorityClassName: ""
    terminationGracePeriodSeconds: 60
    serviceAccount:
      create: true
      name: ""
      annotations: {}                 # IRSA / workload identity
    env: []
    envFrom: []
    extraVolumes: []
    extraVolumeMounts: []
    sidecars: []
    initContainers: []
    livenessProbe: {}
    readinessProbe: {}
    startupProbe: {}

  autoscaling:                        # postgres driver only
    enabled: false
    minReplicas: 2
    maxReplicas: 5
    targetCPUUtilizationPercentage: 80
    targetMemoryUtilizationPercentage: 0

  updateStrategy:
    type: RollingUpdate               # RollingUpdate | OnDelete
    quorumAware: true                 # cluster only: one pod at a time, leader last

  extraArgs: []                       # escape hatch, appended verbatim
```

### What it renders

| Condition | Workload |
| --- | --- |
| `storage.driver=sqlite`, no cluster | StatefulSet, `replicas: 1`, PVC, ClusterIP Service |
| `storage.driver=sqlite`, cluster | StatefulSet, `replicas: cluster.replicas`, `podManagementPolicy: Parallel`, `volumeClaimTemplates`, headless Service + client Service, PDB |
| `storage.driver=postgres` | Deployment, `replicas`, optional HPA, ClusterIP Service |

Plus, always: ServiceAccount, Secret (JWT, cluster secrets, admin credentials —
generated when not supplied), and conditionally Role/RoleBinding (Kubernetes
discovery), Ingress, NetworkPolicy, ServiceMonitor, PrometheusRule, Grafana
dashboard ConfigMap.

The rendering rules are the ones the chart already proves out — args built as
`$(VAR)` references so secrets never appear in a manifest, node ID from
`metadata.name`, advertise addresses from `status.podIP`, discovery spec
pointing at the operator's own label selector. `internal/render` is a port of
`_pod.tpl` into Go, and the chart's templates become the conformance target for
its tests.

### Status

```yaml
status:
  phase: Running                      # Pending|Provisioning|Running|Degraded|Restoring|Deleting
  observedGeneration: 7
  readyReplicas: 3
  endpoint: orders.default.svc.cluster.local
  grpcEndpoint: orders.default.svc.cluster.local:8080
  httpEndpoint: http://orders.default.svc.cluster.local:8081
  version: "1.4.0"
  storage: {driver: sqlite, persistentVolumeClaims: [data-orders-0, ...]}
  cluster:
    formed: true
    leader: orders-1
    voters: 3
    nonVoters: 0
    members:
      - {id: orders-0, address: 10.4.1.7:8082, status: alive, voter: true}
  bootstrap: {completed: true, adminSecret: orders-admin}
  lastBackup:
    name: orders-20260726-0300
    time: "2026-07-26T03:00:11Z"
    result: Succeeded
  conditions:
    - {type: Ready,          status: "True"}
    - {type: Progressing,    status: "False"}
    - {type: Degraded,       status: "False"}
    - {type: ClusterFormed,  status: "True"}
    - {type: Bootstrapped,   status: "True"}
    - {type: BackupHealthy,  status: "True"}
```

Printer columns: `PHASE`, `READY`, `VERSION`, `DRIVER`, `LEADER`, `AGE`.

### Cluster lifecycle

The parts a chart cannot do.

**Formation.** Unchanged from the chart's proven approach: `Parallel` pod
management, `-cluster.bootstrap-expect=<replicas>`, Kubernetes discovery so
peers are visible before any of them is ready. The operator adds a formation
watchdog: if `ClusterFormed` has not gone true within
`cluster.formationTimeout` (default 5m), it emits an event naming what each pod
can see, instead of leaving a StatefulSet stuck with no explanation.

**Scale-out.** Raise `cluster.replicas`. New pods discover the cluster and the
leader adds them as voters. The operator waits for `GET /api/v1/cluster/members`
to report the new node before considering the change complete.

**Scale-in.** This is the case that makes the operator worth writing. Lowering
`cluster.replicas` runs a supervised drain, one node at a time, highest ordinal
first:

1. Refuse outright if the target count would break quorum against the *current*
   healthy member count. The validating webhook rejects the edit; the
   reconciler re-checks at apply time in case health changed in between.
2. `DELETE /api/v1/cluster/members/{nodeID}` on the leader, removing the voter
   from the Raft configuration.
3. Wait for the member to disappear from `GET /api/v1/cluster/members`.
4. Scale the StatefulSet down by one.
5. Delete the orphaned PVC if `cluster.reclaimVolumes: Delete` (default
   `Retain` — a volume that still holds a queue replica is not garbage).
6. Repeat.

**Rolling upgrade.** With `updateStrategy.quorumAware: true` the operator drives
the roll itself (`OnDelete` under the hood): one pod at a time, waiting for the
restarted pod to rejoin as a voter and for the cluster to report a leader before
touching the next. The current leader is restarted **last**, which turns one
mid-roll election into the only election.

> Server-side gap: there is no leadership-transfer endpoint, so the final leader
> restart still costs an election (sub-second, but not zero). See
> [Server-side gaps](#server-side-gaps).

## `PlainQQueue` — queues

```yaml
apiVersion: plainq.dev/v1alpha1
kind: PlainQQueue
metadata:
  name: orders-inbound
spec:
  serverRef:
    name: orders                      # a PlainQ in this namespace
    # -- or an instance we do not own:
    # endpoint: http://plainq.other.svc:8081
    # credentialsSecretRef: {name: plainq-admin, emailKey: email, passwordKey: password}
  queueName: orders-inbound           # defaults to metadata.name; IMMUTABLE
  retentionPeriod: 336h
  visibilityTimeout: 30s
  maxReceiveAttempts: 5
  evictionPolicy: DeadLetter          # Drop | DeadLetter | Reorder
  deadLetterQueueRef:
    name: orders-dlq                  # resolved to its status.queueID
  # deadLetterQueueID: "..."          # or an explicit ID for a queue we do not manage

  updatePolicy: Reject                # Reject | Recreate
  deletionPolicy: Retain              # Retain | Delete
  allowDataLoss: false                # gate for Recreate and non-empty Delete
status:
  queueID: q_01J8Z...
  conditions: [{type: Ready, status: "True"}, {type: Synced, status: "True"}]
```

**Reconciliation.** Look up the queue by name (`DescribeQueue` accepts a name).
Absent → create it and record `status.queueID`. Present → compare the returned
settings against spec.

**Queue settings are create-only on the server.** There is no `UpdateQueue` RPC
and no `PUT /api/v1/queue/{id}`. The operator does not pretend otherwise:

- `updatePolicy: Reject` (default) — set `Synced=False` with reason
  `ImmutableFieldChanged`, listing exactly which fields diverge, and emit a
  warning event. The queue keeps serving with its old settings. Nothing is
  destroyed to satisfy a YAML edit.
- `updatePolicy: Recreate` — delete and recreate the queue, **only** when
  `allowDataLoss: true`. Every message in it is gone. This exists because some
  people run queues that are genuinely disposable, and for them a manual
  delete-and-recreate dance is worse than an explicit opt-in.

When the server grows an `UpdateQueue` RPC, a third value —
`updatePolicy: InPlace`, and eventually the default — drops in without breaking
anyone's manifests.

**Ordering.** `deadLetterQueueRef` makes the DLQ a dependency: the operator
requeues with backoff until the referenced `PlainQQueue` reports
`status.queueID`, so a `kubectl apply -f dir/` with the DLQ in the second file
converges without the user thinking about order.

**Deletion.** A finalizer. `Retain` (default) drops the finalizer and leaves the
queue on the server — deleting a Kubernetes object should not silently destroy
data. `Delete` deletes the queue, refusing while it still holds messages unless
`allowDataLoss: true`.

## `PlainQTopic` — pub/sub

```yaml
apiVersion: plainq.dev/v1alpha1
kind: PlainQTopic
metadata:
  name: order-events
spec:
  serverRef: {name: orders}
  topicName: order-events
  subscriptions:
    - queueRef: {name: billing-inbound}
    - queueRef: {name: analytics-inbound}
    - queueID: "q_externally_managed"
  deletionPolicy: Retain
status:
  topicID: t_01J8Z...
  subscriptions:
    - {queue: billing-inbound, queueID: q_..., subscriptionID: s_..., ready: true}
```

Subscriptions reconcile as a set: subscribe what is in spec and missing on the
server, unsubscribe what is on the server and absent from spec. Same
name-to-ID resolution and dependency-ordering rules as the DLQ reference.

## `PlainQAccount` — accounts and the bootstrap gap

Today the first admin is created by a human in a browser. That makes a clean
GitOps deployment impossible to finish unattended, and it is the single biggest
"the operator has to exist" argument after backups.

```yaml
apiVersion: plainq.dev/v1alpha1
kind: PlainQAccount
metadata:
  name: platform-admin
spec:
  serverRef: {name: orders}
  email: platform@example.com
  credentialsSecretRef: {name: platform-admin, passwordKey: password}  # generated when absent
  role: admin                         # admin | user, or a role name managed via /api/v1/rbac
  bootstrap: false                    # true -> use POST /api/v1/onboarding/complete
  deletionPolicy: Retain
status:
  accountID: a_01J8Z...
  conditions: [{type: Ready, status: "True"}]
```

`PlainQ.spec.bootstrap.enabled` is sugar: the `PlainQ` reconciler synthesizes an
owned `PlainQAccount` with `bootstrap: true`, generating a 32-byte password into
the referenced Secret when the Secret does not exist. The operator then uses
that credential for every subsequent API call against the instance. The
onboarding endpoint self-closes once an admin exists, so a re-run is a no-op —
the reconciler checks `GET /api/v1/onboarding/status` first and treats
"already onboarded" as success.

## Backups

The largest piece, and the one with the most design tension: PlainQ's default
backend is an embedded SQLite file on a `ReadWriteOnce` volume, inside a
distroless container with a read-only root filesystem and no shell. You cannot
`kubectl exec` a `sqlite3 .backup` into it, and no second pod on another node
can mount the volume to read it.

### Engines

Three, selected per policy, because the right answer genuinely differs by
cluster and by recovery objective.

| Engine | Mechanism | RPO | Requires |
| --- | --- | --- | --- |
| `Litestream` | Sidecar shipping the WAL continuously to the destination | seconds | Nothing beyond the destination |
| `Online` (default for scheduled) | Agent sidecar runs `VACUUM INTO` a temp file, then compresses, encrypts, uploads | the schedule | Sidecar CPU/memory, scratch space |
| `VolumeSnapshot` | CSI `VolumeSnapshot`, then a Job mounts a PVC created from it and uploads | the schedule | CSI driver with snapshot support |
| `PostgresDump` (auto-selected for the postgres driver) | Job runs `pg_dump -Fc` using the DSN Secret | the schedule | Network reach to the database |

**Why a sidecar for `Online`.** It is the only process that can see the data
volume while the server is running. `VACUUM INTO` is SQLite's supported online
backup: it produces a consistent, defragmented copy of a live WAL-mode database
without blocking writers and without a filesystem-level snapshot. The agent
(`cmd/agent`) is a small static binary built from the same module as the
operator, injected by the `PlainQ` reconciler when a `PlainQBackupPolicy`
selects the instance. It exposes a control API on `127.0.0.1` plus a pod-network
port guarded by a bearer token from an operator-generated Secret; the operator
POSTs a job description and polls for completion.

*Alternative considered:* have the agent watch the Kubernetes API for
`PlainQBackup` objects addressed to its pod. Rejected — it would grant every
PlainQ pod API read access on our CRDs, a much larger blast radius than one
token-authenticated port that a rendered NetworkPolicy can close to everything
but the operator.

**`VolumeSnapshot`** avoids the sidecar entirely and moves the I/O off the
serving pod, at the cost of a CSI dependency and a crash-consistent (rather than
clean) copy — SQLite recovers such a copy by replaying the WAL, which is
correct but is a recovery, not a clean open. Offered, not defaulted.

**In a Raft cluster**, every node holds a full copy, so the operator picks the
backup source deliberately: a non-voter if one exists, otherwise a healthy
follower, never the leader. Before copying it calls
`POST /api/v1/cluster/snapshot` on that node so the consensus log is compacted
first and the copied volume is small and current.

### Destinations

```yaml
destination:
  s3:
    endpoint: https://s3.us-east-1.amazonaws.com   # or MinIO/R2/Ceph/Wasabi
    region: us-east-1
    bucket: plainq-backups
    prefix: prod/orders
    forcePathStyle: false                          # MinIO and friends want true
    credentialsSecretRef:                          # omit for IRSA / workload identity
      name: backup-s3
      accessKeyIDKey: access-key-id
      secretAccessKeyKey: secret-access-key
      sessionTokenKey: ""
    serverSideEncryption: ""                       # "" | AES256 | aws:kms
    kmsKeyID: ""
    storageClass: ""                               # e.g. STANDARD_IA, GLACIER_IR
    caBundleSecretRef: {name: "", key: ca.crt}     # private-CA S3 endpoints
    insecureSkipVerify: false
  # -- or --
  filesystem:
    existingClaim: plainq-backups                  # ReadWriteMany for cluster-wide reuse
    # claimTemplate: {size: 100Gi, storageClassName: nfs, accessModes: [ReadWriteMany]}
    path: prod/orders
```

Exactly one of `s3` / `filesystem`; the webhook enforces it. The filesystem
destination is what makes on-prem NFS/CephFS deployments and air-gapped
clusters first-class rather than an afterthought.

### `PlainQBackupPolicy`

```yaml
apiVersion: plainq.dev/v1alpha1
kind: PlainQBackupPolicy
metadata:
  name: orders-backups
spec:
  serverRef: {name: orders}

  continuous:                          # Litestream engine
    enabled: true
    syncInterval: 10s
    snapshotInterval: 1h
    resources: {}

  schedule:                            # Online/VolumeSnapshot/PostgresDump engine
    enabled: true
    cron: "0 3 * * *"
    timeZone: UTC
    engine: Online                     # Online | VolumeSnapshot | PostgresDump
    startingDeadlineSeconds: 600
    concurrencyPolicy: Forbid
    suspend: false
    timeout: 1h

  destination: {...}                   # as above

  compression: zstd                    # none | gzip | zstd
  encryption:
    enabled: false
    secretRef: {name: backup-age, key: age.key}    # age recipient/identity

  retention:
    keepLast: 7
    keepDaily: 7
    keepWeekly: 4
    keepMonthly: 6
    maxAge: 365d

  verify: Checksum                     # None | Checksum | Restore

  source:                              # cluster only
    prefer: NonVoter                   # NonVoter | Follower | Any

  resources: {}
  podTemplate: {}                      # nodeSelector/tolerations/affinity for backup Jobs
status:
  lastSuccessfulBackup: "2026-07-26T03:00:11Z"
  lastBackup: {name: orders-20260726-0300, result: Succeeded}
  continuous: {healthy: true, lag: 4s, lastSync: "2026-07-26T09:12:00Z"}
  backupsRetained: 17
  totalSize: 4.2Gi
  conditions:
    - {type: Ready,             status: "True"}
    - {type: ContinuousHealthy, status: "True"}
    - {type: ScheduleHealthy,   status: "True"}
```

The policy controller owns a CronJob for the schedule; each firing creates a
`PlainQBackup` object rather than doing the work itself, so every run is a
first-class object you can look at, retry, or restore from. Retention runs after
each successful backup: it prunes objects at the destination *and* garbage
collects the corresponding `PlainQBackup` resources, using a
grandfather-father-son policy so an aggressive `keepLast` cannot delete the only
monthly you have.

`verify: Restore` is the honest setting: after upload, a throwaway Job pulls the
artifact back down, materializes it in a scratch volume, and runs
`PRAGMA integrity_check` (or `pg_restore --list` for dumps). A backup that has
never been read is a hypothesis.

### `PlainQBackup`

Created by the policy's CronJob, or by hand for an ad-hoc backup:

```yaml
apiVersion: plainq.dev/v1alpha1
kind: PlainQBackup
metadata:
  name: orders-pre-upgrade
spec:
  serverRef: {name: orders}
  policyRef: {name: orders-backups}    # inherit destination/compression/encryption
  # or inline: destination/compression/encryption/engine, for a one-off
  ttl: 720h                            # object GC; empty -> governed by policy retention
status:
  phase: Succeeded                     # Pending|Running|Succeeded|Failed|Deleting
  engine: Online
  sourceNode: orders-2
  startedAt: "2026-07-26T03:00:02Z"
  completedAt: "2026-07-26T03:00:11Z"
  duration: 9s
  size: 612Mi
  compressedSize: 148Mi
  location: s3://plainq-backups/prod/orders/2026/07/26/orders-20260726-0300.db.zst.age
  checksum: {algorithm: sha256, value: "b1946ac9..."}
  serverVersion: "1.4.0"
  storageDriver: sqlite
  verification: {result: Passed, at: "2026-07-26T03:01:40Z"}
  conditions: [{type: Complete, status: "True"}]
```

Printer columns: `PHASE`, `ENGINE`, `SIZE`, `DURATION`, `VERIFIED`, `AGE`.

Deleting a `PlainQBackup` deletes the artifact at the destination through a
finalizer, unless `deletionPolicy: Retain`.

### `PlainQRestore`

```yaml
apiVersion: plainq.dev/v1alpha1
kind: PlainQRestore
metadata:
  name: orders-recovery
spec:
  source:
    backupRef: {name: orders-20260725-0300}
    # -- or point-in-time against a continuous (Litestream) policy:
    # policyRef: {name: orders-backups}
    # pointInTime: "2026-07-25T14:32:00Z"
    # -- or a raw artifact the operator did not create:
    # location: s3://bucket/path/plainq.db.zst
    # destination: {...}   # credentials to read it

  target:
    strategy: NewInstance             # NewInstance | InPlace
    newInstance:
      name: orders-restored
      spec: {}                        # PlainQSpec overlay; inherits the source's spec
    # inPlace:
    #   plainqRef: {name: orders}

  allowDataLoss: false                # required for InPlace
  recreateResources: true             # re-apply PlainQQueue/PlainQTopic after restore
status:
  phase: Completed                    # Pending|Preparing|Restoring|Verifying|Completed|Failed
  restoredTo: orders-restored
  restoredAt: "2026-07-26T11:04:22Z"
  bytesRestored: 612Mi
  conditions: [{type: Complete, status: "True"}]
```

**`NewInstance` (default, recommended).** The operator creates a new `PlainQ`
owned by the restore, with a restore init container that materializes the
database into the fresh PVC before the server ever starts. The damaged instance
is untouched, so you can compare the two and cut over with a Service edit. This
is the strategy a person should reach for at 3am, and it is the default for that
reason.

**`InPlace`.** Requires `allowDataLoss: true`. The operator sets
`status.phase: Restoring` on the target, scales it to zero, runs a restore Job
that replaces the database file (and, for a cluster, wipes
`cluster.dataDir` on every node so stale Raft logs cannot resurrect old state),
then scales back up. For a cluster it brings up exactly one node with
`-cluster.bootstrap` and lets the rest rejoin and pull a fresh snapshot — never
several nodes each convinced they hold the truth.

`recreateResources` re-applies the `PlainQQueue` and `PlainQTopic` objects
pointing at the target once it is serving. This is why references are by object
name and not by server-assigned ID: a restored instance mints new IDs, and
name-based references survive it without anyone editing YAML.

## Webhooks

**Defaulting** fills image tag from `spec.version`, ports, timeouts, probes,
hardened security contexts, `bootstrapExpect` from `cluster.replicas`, queue
name from `metadata.name`, and generates Secret names.

**Validation** rejects, with a message that names the field:

| Rule | Why |
| --- | --- |
| `cluster.enabled` with `storage.driver=postgres` | Cluster mode requires SQLite + WAL. |
| `replicas > 1` with `sqlite` and no cluster | SQLite is single-writer on one RWO volume. |
| Mutating `storage.driver`, `cluster.enabled`, `queueName` | Not reconcilable; would silently destroy data. |
| Shrinking `storage.sqlite.persistence.size` | PVCs do not shrink. |
| Cluster scale-in below quorum of current healthy members | Loses the cluster. |
| `evictionPolicy: DeadLetter` without a DLQ reference | Undeliverable messages with nowhere to go. |
| A queue naming itself as its own DLQ | Eviction loop. |
| Neither or both of `destination.s3` / `destination.filesystem` | Ambiguous. |
| `PostgresDump` engine with `storage.driver=sqlite` (and inverse) | Engine/backend mismatch. |
| `restore.target.strategy: InPlace` without `allowDataLoss` | Overwrites a live database. |
| `updatePolicy: Recreate` without `allowDataLoss` | Drops every message in the queue. |
| Cron expression that does not parse | Fails silently at 3am otherwise. |

Even cluster replica counts produce a **warning**, not a rejection: a 4-node
cluster tolerates the same single failure a 3-node does, so the extra node buys
only cost — but it is a legal configuration during a scale transition.

## RBAC and security

**Operator ServiceAccount.** Cluster-scoped by default, watching all namespaces;
`--namespaces=a,b` restricts it for shared clusters. Permissions: full CRUD on
`plainq.dev` CRs and their status; StatefulSets, Deployments, Services, PVCs,
Secrets, ConfigMaps, ServiceAccounts, Roles, RoleBindings, Jobs, CronJobs, PDBs,
HPAs, Events; `create` on `VolumeSnapshots` when that engine is enabled;
`monitoring.coreos.com` when ServiceMonitor/PrometheusRule are enabled. Leader
election through a Lease.

**Instance ServiceAccounts** get only what Kubernetes discovery needs: `list`
and `watch` on pods and endpoints in their own namespace. `dns` discovery needs
no RBAC at all and the operator drops the Role entirely for it.

**Secrets.** Generated secrets (JWT, gossip key, peer-RPC secret, admin
password) are created with `crypto/rand` and owned by the `PlainQ`, so they are
garbage collected with it. They are referenced through `$(VAR)` expansion in
container args exactly as the chart does, so no plaintext secret ever appears in
a rendered manifest. Rotating the JWT Secret rolls the pods via a checksum
annotation.

**Network.** `networking.networkPolicy.enabled` renders a default-deny policy
allowing `:8080`/`:8081` only from the selectors you list, plus intra-cluster
`:8082`/`:8083` between instance pods, plus the operator to the backup agent
port. Given that gRPC carries no authentication today, this is the control that
actually protects the queue API, and the docs will say so.

## Observability

**Operator metrics** (`/metrics` on the manager): controller-runtime's standard
set plus `plainq_operator_reconcile_errors_total`,
`plainq_operator_backup_duration_seconds`,
`plainq_operator_backup_last_success_timestamp_seconds`,
`plainq_operator_backup_size_bytes`, `plainq_operator_cluster_members`,
`plainq_operator_cluster_has_leader`, `plainq_operator_queues_managed`.

**Events** on every consequential action: cluster formed, member removed,
leader changed, backup started/succeeded/failed, restore phases, queue created,
immutable-field drift detected.

**`prometheusRule.enabled`** ships the alerts that follow from those metrics:
`PlainQBackupTooOld` (no successful backup within 2× the schedule interval),
`PlainQBackupFailing`, `PlainQContinuousReplicationLagging`,
`PlainQClusterNoLeader`, `PlainQClusterDegraded` (voters below expected),
`PlainQQueueOutOfSync`, `PlainQInstanceNotReady`.

**`grafanaDashboard.enabled`** ships a ConfigMap with the sidecar discovery
label, wrapping PlainQ's own `/metrics` output plus the operator's.

## Server-side gaps this design depends on

Writing the operator surfaced things the server should grow. None of them block
v1alpha1 — the design works around each — but each workaround is worth
retiring.

1. **`UpdateQueue`.** Queue settings are create-only. Until then,
   `updatePolicy` is `Reject` or destructive `Recreate`. This is the single
   biggest wart in the CRD surface.
2. **Leadership transfer endpoint.** Would make a quorum-aware rolling upgrade
   election-free instead of election-once.
3. **Readiness that distinguishes "serving" from "joined".** `/health` today
   cannot tell a Kubernetes readiness gate that a node is up but has not yet
   joined the cluster, which is why formation relies on `Parallel` pod
   management plus discovery-before-ready.
4. **gRPC authentication.** Would let the operator (and everyone else) use the
   faster surface instead of routing control-plane calls through REST.
5. **A maintenance endpoint for `VACUUM INTO`.** Would let the `Online` engine
   drop the sidecar entirely and ask the server for a consistent copy.

Items 1 and 2 are the ones worth scheduling alongside the operator itself.

## Compatibility and rollout

- `v1alpha1`, with a conversion-webhook path already scaffolded for `v1beta1`.
  Storage version is pinned in the CRDs so a future bump is mechanical.
- The Helm chart is unchanged and stays supported. Migration from chart to
  operator is a `PlainQ` with `storage.sqlite.persistence.existingClaim`
  pointing at the chart's PVC, plus `auth.jwtSecretRef` at the chart's Secret —
  same volume, same secret, no data movement.
- Operator upgrades are safe to roll: CRD changes are additive within
  `v1alpha1`, and the manager tolerates status fields it does not recognize.
- CRDs install with the operator chart but can be applied separately for
  clusters where CRD management is a privileged, separate step.

## Testing

- **Unit** — `internal/render` golden files, asserted against the Helm chart's
  rendered output so the two provisioning paths cannot drift apart.
- **Envtest** — every reconciler against a real API server: creation, drift,
  finalizers, dependency ordering, immutable-field rejection.
- **Fake PlainQ API** — an `httptest` server implementing the REST surface
  above, driving the queue/topic/account/cluster reconcilers through success,
  conflict, and outage paths.
- **e2e on kind** — single node, Postgres, and 3-node cluster; scale 3→5→3 with
  the drain path; a backup to MinIO and a restore that is asserted to contain
  the messages sent before it; a rolling upgrade under continuous load with
  zero message loss asserted.
- **Chaos** — kill the leader mid-backup, kill the operator mid-restore, revoke
  the S3 credential mid-upload. Each must land in a status a human can read.

## Open questions

1. **Message-level backup.** Everything here backs up the database file. A
   logical, format-stable export (queues + messages as JSON/Parquet) would
   survive a PlainQ major version bump and enable partial restore of a single
   queue. Worth a `PlainQExport` kind later; out of scope now.
2. **Cross-namespace `serverRef`.** Currently same-namespace only, which is the
   safe default. Multi-tenant platform teams will ask; it needs a reference-grant
   mechanism before it is safe to grant.
3. **`PlainQRole` / RBAC-as-CRD.** The server has a full RBAC subsystem.
   `PlainQAccount.spec.role` covers the common case; whether roles and queue
   permissions deserve their own kind depends on how people actually use them.
4. **KEDA.** A `ScaledObject` driven by queue depth is an obvious companion.
   Ship the metrics first, judge the demand, then decide whether the operator
   should render it.
