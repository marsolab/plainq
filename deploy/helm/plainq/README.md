# PlainQ Helm Chart

A production-grade Helm chart for [PlainQ](https://github.com/marsolab/plainq) — a
lightweight, self-hostable queue server exposing a gRPC queue API and the Houston
admin web UI.

The container image is `ghcr.io/marsolab/plainq` and runs as a nonroot,
read-only-root-filesystem, distroless workload.

## TL;DR

```sh
# SQLite (default) — single replica, persistent volume, inline development secrets
helm install plainq ./deploy/helm/plainq \
  --set auth.jwtSecret=$(openssl rand -hex 32) \
  --set auth.bootstrap.secret=$(openssl rand -hex 32)

# Production — authentication secrets from a pre-created Kubernetes Secret
kubectl create secret generic plainq-auth \
  --from-literal=jwt-secret=$(openssl rand -hex 32) \
  --from-literal=bootstrap-secret=$(openssl rand -hex 32)
helm install plainq ./deploy/helm/plainq \
  --set auth.existingSecret=plainq-auth \
  --set auth.bootstrap.existingSecret=plainq-auth
```

## Ports

| Port | Name | Purpose |
| ---- | ---- | ------- |
| 8080 | grpc | Primary gRPC queue API |
| 8081 | http | Houston admin UI, REST auth API, `/health`, `/metrics` |

## How authentication secrets are wired

PlainQ reads configuration only from CLI flags, not environment variables. To
keep the secret out of the rendered manifest, the chart:

1. Stores each credential in a Kubernetes `Secret` (generated for development,
   or supplied through `auth.existingSecret` and `auth.bootstrap.existingSecret`).
2. Exposes them as `PLAINQ_JWT_SECRET` and `PLAINQ_BOOTSTRAP_SECRET` via
   `secretKeyRef`.
3. Passes only variable references in `-auth.jwt.secret` and
   `-auth.bootstrap.secret` arguments.

Kubernetes itself expands `$(VAR)` references in container `args` (a native
kubelet feature, independent of any shell), so this works on the distroless image
which has no shell. Only the variable reference — never the plaintext secret —
appears in the rendered YAML. The Postgres DSN is wired the same way via
`PLAINQ_POSTGRES_DSN`.

## SQLite vs Postgres

| | SQLite (default) | Postgres |
| - | ---------------- | -------- |
| Workload | `StatefulSet` | `Deployment` |
| Replicas | Always 1 (single writer) | `replicaCount`, autoscalable |
| Storage | PersistentVolumeClaim (RWO) mounted at the DB dir | External Postgres |
| Autoscaling | Not supported | `autoscaling.enabled` |

### SQLite

```sh
helm install plainq ./deploy/helm/plainq \
  --set storage.driver=sqlite \
  --set storage.sqlite.persistence.size=20Gi \
  --set auth.existingSecret=plainq-auth \
  --set auth.bootstrap.existingSecret=plainq-auth
```

The PVC is created by `templates/pvc.yaml` and mounted at `dir(storage.sqlite.path)`
(default `/data`). Keep `replicaCount` at 1.

### Postgres

```sh
kubectl create secret generic plainq-pg --from-literal=dsn='postgres://user:pass@host:5432/plainq?sslmode=require'
helm install plainq ./deploy/helm/plainq \
  --set storage.driver=postgres \
  --set storage.postgres.existingSecret=plainq-pg \
  --set storage.postgres.secretKey=dsn \
  --set replicaCount=3 \
  --set auth.existingSecret=plainq-auth \
  --set auth.bootstrap.existingSecret=plainq-auth
```

## Ingress and gRPC

Ingress is disabled by default. The default `ingress.hosts` shows the pattern: one
host routed to the `http` Service port (Houston UI) and a separate host routed to
the `grpc` port. gRPC over Ingress requires HTTP/2 (so TLS) and a controller hint,
for example on NGINX:

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "GRPC"
  hosts:
    - host: grpc.plainq.example.com
      paths:
        - path: /
          pathType: Prefix
          port: grpc
  tls:
    - secretName: plainq-tls
      hosts: [grpc.plainq.example.com]
```

Because gRPC annotations apply to the whole Ingress object, keep the HTTP UI on a
separate Ingress/host if you need different backend protocols.

## Key values

| Key | Default | Description |
| --- | ------- | ----------- |
| `replicaCount` | `1` | Replicas. Keep at 1 for SQLite. |
| `image.repository` | `ghcr.io/marsolab/plainq` | Image repo. |
| `image.tag` | `""` | Defaults to chart `appVersion`. |
| `imagePullSecrets` | `[]` | Pull secrets for private registries. |
| `service.type` | `ClusterIP` | Service type. |
| `service.grpcPort` | `8080` | gRPC port. |
| `service.httpPort` | `8081` | HTTP port. |
| `storage.driver` | `sqlite` | `sqlite` or `postgres`. |
| `storage.sqlite.path` | `/data/plainq.db` | SQLite DB file path. |
| `storage.sqlite.persistence.enabled` | `true` | Create a PVC. |
| `storage.sqlite.persistence.size` | `8Gi` | PVC size. |
| `storage.sqlite.persistence.storageClass` | `""` | PVC storage class. |
| `storage.postgres.existingSecret` | `""` | Secret holding the DSN. |
| `storage.postgres.dsn` | `""` | Inline DSN (dev only). |
| `auth.enabled` | `true` | Enable authentication. |
| `auth.existingSecret` | `""` | Secret holding the JWT secret. |
| `auth.jwtSecret` | `""` | Inline JWT secret (dev only). |
| `auth.secretKey` | `jwt-secret` | Key within the JWT secret. |
| `auth.bootstrap.existingSecret` | `""` | Secret holding the remote bootstrap secret. |
| `auth.bootstrap.secret` | `""` | Inline bootstrap secret (development only). |
| `auth.bootstrap.secretKey` | `bootstrap-secret` | Key within the bootstrap Secret. |
| `config.logLevel` | `info` | Log level. |
| `extraArgs` | `[]` | Extra `serve` flags. |
| `resources` | requests 100m/128Mi | Container resources. |
| `autoscaling.enabled` | `false` | HPA (postgres only). |
| `ingress.enabled` | `false` | Create an Ingress. |
| `metrics.serviceMonitor.enabled` | `false` | Create a Prometheus Operator `ServiceMonitor` scraping the HTTP `/metrics` endpoint. |
| `metrics.serviceMonitor.interval` | `30s` | Scrape interval. |
| `metrics.serviceMonitor.labels` | `{}` | Extra labels (e.g. `release: kube-prometheus-stack`) so the operator selects it. |

See [`values.yaml`](./values.yaml) for the fully commented set.

### Prometheus scraping

With the [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator)
installed, enable a `ServiceMonitor` so PlainQ's `/metrics` endpoint is scraped
automatically:

```shell
helm install plainq deploy/helm/plainq \
  --set auth.jwtSecret="$(openssl rand -hex 32)" \
  --set auth.bootstrap.secret="$(openssl rand -hex 32)" \
  --set metrics.serviceMonitor.enabled=true \
  --set metrics.serviceMonitor.labels.release=kube-prometheus-stack
```

The `release` label must match your operator's `serviceMonitorSelector` (for
the kube-prometheus-stack chart that is the release name). Without the operator
CRDs installed the template is skipped.

## Clustering

`cluster.enabled=true` turns the single-replica StatefulSet into a Raft cluster:
several pods, each with its own volume and its own replica of the queue, that
find each other through the Kubernetes API.

```sh
helm install plainq ./deploy/helm/plainq \
  --set cluster.enabled=true \
  --set cluster.replicas=3 \
  --set cluster.gossipSecret="$(openssl rand -base64 32)" \
  --set cluster.secret="$(openssl rand -hex 32)" \
  --set auth.jwtSecret="$(openssl rand -hex 32)" \
  --set auth.bootstrap.secret="$(openssl rand -hex 32)"
```

| Value                       | Default      | Purpose                                                     |
| --------------------------- | ------------ | ----------------------------------------------------------- |
| `cluster.enabled`           | `false`      | Deploy a cluster instead of a single node.                   |
| `cluster.replicas`          | `3`          | Number of nodes. **Use an odd number.**                      |
| `cluster.clusterPort`       | `8082`       | Consensus + peer RPC.                                        |
| `cluster.gossipPort`        | `8083`       | Membership gossip (TCP and UDP).                             |
| `cluster.discovery`         | `kubernetes` | `kubernetes` (API) or `dns` (headless service).              |
| `cluster.discoveryOverride` | `""`         | A discovery spec replacing the generated one.                |
| `cluster.consistency`       | `local`      | `local` or `strong` reads.                                   |
| `cluster.autoRemove`        | `false`      | Let the leader remove long-unreachable members.              |
| `cluster.removeTimeout`     | `5m`         | How long "unreachable" must last first.                      |
| `cluster.gossipSecret`      | `""`         | Base64 16/24/32-byte gossip key.                             |
| `cluster.secret`            | `""`         | Shared secret for internal peer RPC.                         |
| `cluster.existingSecret`    | `""`         | A pre-created Secret holding both.                           |
| `cluster.rbac.create`       | `true`       | Role + RoleBinding for Kubernetes discovery.                 |
| `cluster.extraArgs`         | `[]`         | Extra `-cluster.*` flags.                                    |

What the chart does differently in cluster mode:

- `replicas: cluster.replicas` and `podManagementPolicy: Parallel`, so the pods
  start together — `bootstrap-expect` waits for all of them, and `OrderedReady`
  would deadlock waiting for a readiness that cannot arrive until they have
  found each other.
- `volumeClaimTemplates` instead of a single shared PVC: each node keeps its own
  replica and its own consensus log.
- A headless service with `publishNotReadyAddresses: true`, since a PlainQ pod
  is not ready until it has joined a cluster.
- A namespaced, read-only Role for `pods` and `endpoints` (skipped when
  `cluster.discovery=dns`).
- Each pod's name as its node id, and its pod IP as its advertised address.

Use an odd `cluster.replicas`. A cluster of four tolerates the same single
failure as a cluster of three; `cluster.replicas=2` is rejected at startup
because it tolerates none at all.

Scaling down with `kubectl scale` does not remove nodes from the consensus
configuration — run `plainq cluster leave -node-id=<pod-name>` or set
`cluster.autoRemove=true`.

Clustering requires `storage.driver=sqlite`. With Postgres the database is
already shared, so run several stateless nodes against one Postgres instead.

## Upgrade notes

- Schema migration 006 deliberately revokes sessions created by older
  releases because those tables stored clear bearer material. Users must sign
  in once after the upgrade; no clear-token fallback is retained.
- New installs protect legacy `schema.v1` gRPC by default. Upgrades preserve
  anonymous old-client compatibility until you explicitly set
  `agent.protectLegacy=true`; compatibility is scheduled for removal after two
  releases.
- Changing the JWT or Postgres secret content rolls the pods automatically (a
  `checksum/secret` pod annotation tracks the rendered Secret).
- When `auth.enabled=true`, rendering requires both a JWT signing credential and
  a remote bootstrap credential. Prefer the corresponding `existingSecret`
  values in production so neither plaintext credential enters Helm values.
- Switching `storage.driver` between `sqlite` and `postgres` swaps the workload
  kind (StatefulSet <-> Deployment); Helm replaces the old object on upgrade. Data
  is not migrated between backends.

## Validation

```sh
helm lint ./deploy/helm/plainq
helm template ./deploy/helm/plainq --set auth.existingSecret=plainq-auth --set auth.bootstrap.existingSecret=plainq-auth
helm template ./deploy/helm/plainq --set storage.driver=postgres --set storage.postgres.existingSecret=plainq-pg --set auth.existingSecret=plainq-auth --set auth.bootstrap.existingSecret=plainq-auth
helm template ./deploy/helm/plainq --set auth.existingSecret=plainq-auth --set auth.bootstrap.existingSecret=plainq-auth --set cluster.enabled=true --set cluster.existingSecret=plainq-cluster
```
