# Cloud Infrastructure

Comprehensive guide to Kubernetes, cloud platforms, service mesh, and container
optimization.

## Kubernetes Production Checklist

### Resource Management

- [ ] **Resource requests and limits** defined for all containers

  ```yaml
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 512Mi
  ```

- [ ] **Vertical Pod Autoscaler (VPA)** configured for right-sizing
  - Analyzes actual resource usage
  - Recommends optimal requests/limits
  - Can automatically update pods

- [ ] **Quality of Service (QoS)** classes assigned
  - **Guaranteed:** Requests = Limits (highest priority)
  - **Burstable:** Requests < Limits (medium priority)
  - **BestEffort:** No requests/limits (lowest priority, first to evict)

- [ ] **Resource quotas** per namespace to prevent noisy neighbors

  ```yaml
  apiVersion: v1
  kind: ResourceQuota
  metadata:
    name: compute-quota
  spec:
    hard:
      requests.cpu: "10"
      requests.memory: 20Gi
      limits.cpu: "20"
      limits.memory: 40Gi
  ```

### High Availability

- [ ] **Pod Disruption Budgets (PDBs)** defined

  ```yaml
  apiVersion: policy/v1
  kind: PodDisruptionBudget
  metadata:
    name: app-pdb
  spec:
    minAvailable: 1
    selector:
      matchLabels:
        app: myapp
  ```

- [ ] **Topology spread constraints** configured (distribute across zones)

  ```yaml
  topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: DoNotSchedule
    labelSelector:
      matchLabels:
        app: myapp
  ```

- [ ] **Multiple replicas** for stateless services (minimum: 3)
- [ ] **Node affinity rules** for stateful services
- [ ] **Anti-affinity** to prevent pods on same node

### Health Checks

- [ ] **Liveness probes** configured (restart if unhealthy)

  ```yaml
  livenessProbe:
    httpGet:
      path: /healthz
      port: 8080
    initialDelaySeconds: 30
    periodSeconds: 10
    timeoutSeconds: 5
    failureThreshold: 3
  ```

- [ ] **Readiness probes** configured (remove from service if not ready)

  ```yaml
  readinessProbe:
    httpGet:
      path: /ready
      port: 8080
    initialDelaySeconds: 5
    periodSeconds: 5
    timeoutSeconds: 3
    failureThreshold: 3
  ```

- [ ] **Startup probes** for slow-starting applications

  ```yaml
  startupProbe:
    httpGet:
      path: /startup
      port: 8080
    failureThreshold: 30
    periodSeconds: 10
  ```

- [ ] **Appropriate timeouts and thresholds** (avoid flapping)

### Networking

- [ ] **Network policies** restrict inter-pod communication

  ```yaml
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: api-network-policy
  spec:
    podSelector:
      matchLabels:
        app: api
    ingress:
    - from:
      - podSelector:
          matchLabels:
            app: frontend
      ports:
      - protocol: TCP
        port: 8080
  ```

- [ ] **Service mesh** configured (Istio, Linkerd) for complex routing
- [ ] **Ingress controller** with SSL termination
- [ ] **Load balancer health checks** aligned with readiness probes

### Security

- [ ] **Pod Security Standards** enforced (restricted profile)

  ```yaml
  apiVersion: v1
  kind: Namespace
  metadata:
    name: production
    labels:
      pod-security.kubernetes.io/enforce: restricted
  ```

- [ ] **Non-root containers** (securityContext.runAsNonRoot: true)

  ```yaml
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  ```

- [ ] **Read-only root filesystem** where possible

  ```yaml
  securityContext:
    readOnlyRootFilesystem: true
  ```

- [ ] **Secrets management** (external secrets operator, HashiCorp Vault)
- [ ] **RBAC policies** with least privilege
- [ ] **Image scanning** for vulnerabilities (Trivy, Snyk)

### Observability

- [ ] **Prometheus metrics** exported from all services
- [ ] **Distributed tracing** with OpenTelemetry
- [ ] **Centralized logging** (ELK, Loki, CloudWatch)
- [ ] **Service-level objectives (SLOs)** defined and monitored
- [ ] **Dashboards** for key metrics (RED: Rate, Errors, Duration)
- [ ] **Alerts** with appropriate thresholds and runbooks

### Cost Optimization

- [ ] **Horizontal Pod Autoscaler (HPA)** based on business metrics

  ```yaml
  apiVersion: autoscaling/v2
  kind: HorizontalPodAutoscaler
  metadata:
    name: app-hpa
  spec:
    scaleTargetRef:
      apiVersion: apps/v1
      kind: Deployment
      name: app
    minReplicas: 2
    maxReplicas: 10
    metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
  ```

- [ ] **Cluster autoscaler** for node scaling
- [ ] **Spot instances** for fault-tolerant workloads (70% cost savings)
- [ ] **Resource requests tuned** to avoid over-provisioning
- [ ] **Right-sizing** based on actual usage (VPA recommendations)

## Service Mesh Comparison

### Istio vs Linkerd

| Feature | Istio | Linkerd |
|---------|-------|---------|
| **Performance** | Moderate overhead (5-10% latency) | Low overhead (1-3% latency) |
| **Latency Impact** | +2-5ms per hop | +0.5-1ms per hop |
| **Resource Usage** | High (Envoy proxy: 100-200MB per pod) | Low (Linkerd proxy: 10-30MB per pod) |
| **Complexity** | High (many components: Pilot, Galley, Citadel) | Low (simplified architecture) |
| **Features** | Comprehensive (traffic split, mirroring, fault injection) | Focused (core features only) |
| **Language** | Envoy (C++), control plane (Go) | Rust proxies (performance + safety) |
| **Multi-cluster** | Full support, complex setup | Supported, simpler setup |
| **Observability** | Rich (Kiali, Jaeger, Grafana integration) | Built-in (Linkerd dashboard, Prometheus) |
| **Traffic Management** | Advanced (weighted routing, header-based routing) | Basic (percentage-based splits) |
| **Maturity** | Mature, CNCF graduated | Mature, CNCF graduated |
| **Learning Curve** | Steep | Gentle |
| **Best For** | Enterprise, complex requirements | Performance-critical, simplicity |

### Choose Istio If

- Need advanced traffic management (weighted routing, traffic mirroring)
- Require multi-cluster mesh
- Enterprise support needed
- Team has service mesh expertise
- Complex routing rules (header-based, cookie-based)
- A/B testing, canary deployments with fine control

### Choose Linkerd If

- Performance is critical (low latency, minimal overhead)
- Want operational simplicity
- Team new to service mesh
- Resource efficiency important (cost savings)
- Need quick time-to-value
- Prefer Rust safety guarantees

### Neither If

- Simple application (< 10 services)
- No need for mTLS, traffic management, observability features
- Can use API gateway for routing
- Team too small to manage service mesh

## Container Optimization

### Multi-Stage Builds

Separate build and runtime stages for smaller images.

**Go example:**

```dockerfile
# Stage 1: Build
FROM golang:1.21 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o app

# Stage 2: Runtime
FROM gcr.io/distroless/static-debian12
COPY --from=builder /app/app /app
ENTRYPOINT ["/app"]
```

**Node.js example:**

```dockerfile
# Stage 1: Build
FROM node:18 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Stage 2: Runtime
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY --from=builder /app/dist ./dist
CMD ["node", "dist/index.js"]
```

**Benefits:**

- Smaller final images (10-50x reduction)
- Exclude build tools and dev dependencies
- Faster CI/CD (smaller uploads/downloads)
- Reduced attack surface

### Layer Caching Strategy

Order Dockerfile instructions for maximum cache reuse.

```dockerfile
# 1. Base image (rarely changes)
FROM node:18-alpine

# 2. System dependencies (rarely changes)
RUN apk add --no-cache python3 make g++

# 3. Application dependencies (changes occasionally)
COPY package.json package-lock.json ./
RUN npm ci --production

# 4. Application code (changes frequently)
COPY . .

# 5. Build (changes with code)
RUN npm run build
```

**Ordering principle:**

- Stable layers first (change rarely)
- Volatile layers last (change frequently)
- Invalidating a layer invalidates all subsequent layers

### Image Size Optimization

**Base image selection:**

- **Distroless:** ~20MB (no shell, minimal packages)
- **Alpine:** ~5MB (tiny Linux with package manager)
- **Slim:** ~50MB (Debian minimal)
- **Full:** ~100-500MB (Ubuntu, Debian with utilities)

**Size comparison example (Node.js app):**

```text
node:18          → 993MB
node:18-slim     → 234MB
node:18-alpine   → 172MB
node:18-alpine + multi-stage → 45MB
```

**Techniques:**

1. **Use .dockerignore**

   ```bash
   .git
   node_modules
   npm-debug.log
   README.md
   .env
   ```

1. **Combine RUN commands**

   ```dockerfile
   # Bad (creates 3 layers)
   RUN apt-get update
   RUN apt-get install -y curl
   RUN rm -rf /var/lib/apt/lists/*

   # Good (creates 1 layer)
   RUN apt-get update && \
       apt-get install -y curl && \
       rm -rf /var/lib/apt/lists/*
   ```

1. **Remove unnecessary files**

   ```dockerfile
   RUN npm ci --production && \
       npm cache clean --force && \
       rm -rf /tmp/*
   ```

### Security Best Practices

**1. Non-root user:**

```dockerfile
# Create user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Switch to user
USER appuser

# Run as non-root
CMD ["./app"]
```

**2. Read-only root filesystem:**

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
- name: tmp
  mountPath: /tmp
- name: cache
  mountPath: /app/cache
```

**3. Scan images for vulnerabilities:**

```bash
# Trivy scan
trivy image myapp:latest

# Snyk scan
snyk container test myapp:latest

# Grype scan
grype myapp:latest
```

**4. Use specific versions (no `latest` tag):**

```dockerfile
# Bad
FROM node:latest

# Good
FROM node:18.17.0-alpine
```

**5. Verify image signatures:**

```bash
# Sign with Cosign
cosign sign myregistry/myapp:v1.0.0

# Verify signature
cosign verify myregistry/myapp:v1.0.0
```

### Performance Benchmarks

**Layer deduplication:**

- 75% of container images share < 5% unique bytes
- Registry deduplication saves significant storage

**Build time impact:**

- Proper caching reduces build time by 60-80%
- Multi-stage builds add 10-20% build time but worth it

**Image size impact:**

- Multi-stage builds: 10-50x reduction
- Alpine vs full image: 5-20x reduction
- Distroless: Smallest secure option

**Pull time:**

- Smaller images = faster deployments
- 100MB image: ~30s pull time
- 1GB image: ~5min pull time

## Cloud Provider Deep Dives

### AWS

**Strengths:**

- Broadest service catalog (200+ services)
- Mature serverless (Lambda, API Gateway)
- Strong startup ecosystem
- Deep feature set per service

**Best for:**

- Startups needing quick iteration
- Applications requiring diverse services
- Serverless-first architecture

**Key services:**

- Compute: EC2, Lambda, ECS, EKS
- Database: RDS, Aurora, DynamoDB
- Storage: S3, EBS, EFS
- Networking: VPC, Route 53, CloudFront

### Azure

**Strengths:**

- Microsoft stack integration (AD, Office 365)
- Enterprise governance (Azure Arc)
- Hybrid cloud (best on-prem integration)
- Enterprise agreements and support

**Best for:**

- Enterprise with Microsoft investment
- Hybrid cloud requirements
- .NET applications

**Key services:**

- Compute: VM, Functions, AKS
- Database: SQL Database, Cosmos DB
- Storage: Blob Storage, File Storage
- Networking: Virtual Network, Front Door

### GCP

**Strengths:**

- Kubernetes-native (GKE best managed K8s)
- Data analytics (BigQuery, Dataflow)
- ML/AI (Vertex AI, TPUs)
- Simple, per-second billing
- Created SRE role

**Best for:**

- Kubernetes workloads
- Data analytics and ML
- Companies valuing simplicity

**Key services:**

- Compute: Compute Engine, Cloud Run, GKE
- Database: Cloud SQL, Firestore, Spanner
- Storage: Cloud Storage
- Networking: VPC, Cloud CDN

## Best Practices

1. **Right-size resources:** Use VPA recommendations, don't overprovision
1. **Automate scaling:** HPA for pods, cluster autoscaler for nodes
1. **Security defaults:** Non-root containers, read-only filesystem, RBAC
1. **Observability first:** Metrics, traces, logs from day one
1. **Test failure scenarios:** Chaos engineering, pod deletions
1. **Document runbooks:** Common failures and recovery procedures
1. **Cost monitoring:** Track spend per service, set budgets
