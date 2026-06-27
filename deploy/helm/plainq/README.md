# PlainQ Helm Chart

A production-grade Helm chart for [PlainQ](https://github.com/marsolab/plainq) — a
lightweight, self-hostable queue server exposing a gRPC queue API and the Houston
admin web UI.

The container image is `ghcr.io/marsolab/plainq` and runs as a nonroot,
read-only-root-filesystem, distroless workload.

## TL;DR

```sh
# SQLite (default) — single replica, persistent volume, inline dev JWT secret
helm install plainq ./deploy/helm/plainq \
  --set auth.jwtSecret=$(openssl rand -hex 32)

# Production — JWT secret from a pre-created Kubernetes Secret
kubectl create secret generic plainq-jwt --from-literal=jwt-secret=$(openssl rand -hex 32)
helm install plainq ./deploy/helm/plainq \
  --set auth.existingSecret=plainq-jwt \
  --set auth.secretKey=jwt-secret
```

## Ports

| Port | Name | Purpose |
| ---- | ---- | ------- |
| 8080 | grpc | Primary gRPC queue API |
| 8081 | http | Houston admin UI, REST auth API, `/health`, `/metrics` |

## How the JWT secret is wired

PlainQ reads configuration only from CLI flags, not environment variables. To
keep the secret out of the rendered manifest, the chart:

1. Stores the secret in a Kubernetes `Secret` (generated, or one you supply via
   `auth.existingSecret`).
2. Exposes it to the container as the env var `PLAINQ_JWT_SECRET` via
   `secretKeyRef`.
3. Passes the flag as `-auth.jwt.secret=$(PLAINQ_JWT_SECRET)`.

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
  --set auth.existingSecret=plainq-jwt
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
  --set auth.existingSecret=plainq-jwt
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
| `config.logLevel` | `info` | Log level. |
| `extraArgs` | `[]` | Extra `serve` flags. |
| `resources` | requests 100m/128Mi | Container resources. |
| `autoscaling.enabled` | `false` | HPA (postgres only). |
| `ingress.enabled` | `false` | Create an Ingress. |

See [`values.yaml`](./values.yaml) for the fully commented set.

## Upgrade notes

- Changing the JWT or Postgres secret content rolls the pods automatically (a
  `checksum/secret` pod annotation tracks the rendered Secret).
- When `auth.enabled=true`, rendering fails if neither `auth.jwtSecret` nor
  `auth.existingSecret` is set — this is intentional to prevent insecure deploys.
- Switching `storage.driver` between `sqlite` and `postgres` swaps the workload
  kind (StatefulSet <-> Deployment); Helm replaces the old object on upgrade. Data
  is not migrated between backends.

## Validation

```sh
helm lint ./deploy/helm/plainq
helm template ./deploy/helm/plainq --set auth.jwtSecret=dev
helm template ./deploy/helm/plainq --set storage.driver=postgres --set storage.postgres.dsn=postgres://x --set auth.jwtSecret=dev
```
