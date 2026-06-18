# Observability and Operations

Comprehensive guide to monitoring, observability, GitOps, and production
readiness.

## OpenTelemetry Observability

### Three Pillars

#### 1. Metrics (Quantitative Measurements)

**Service metrics (RED method):**

- **R**ate: Requests per second
- **E**rrors: Error rate (percentage)
- **D**uration: Latency (p50, p95, p99)

**Resource metrics (USE method):**

- **U**tilization: % CPU, memory, disk used
- **S**aturation: Queue depth, thread pool usage
- **E**rrors: Failed requests, exceptions

**Business metrics:**

- Orders per hour
- Revenue per minute
- Cart abandonment rate
- User signups

**Example Prometheus metrics:**

```prometheus
# Counter (always increases)
http_requests_total{method="GET", endpoint="/api/users", status="200"} 1547

# Gauge (can go up/down)
memory_usage_bytes{service="api"} 524288000

# Histogram (distribution)
http_request_duration_seconds_bucket{le="0.1"} 9500
http_request_duration_seconds_bucket{le="0.5"} 9950
http_request_duration_seconds_bucket{le="1.0"} 10000
```

#### 2. Traces (Request Propagation)

**Distributed tracing:** Follow a request across services

**Trace structure:**

```text
Trace ID: abc123
├─ Span: API Gateway (10ms)
   ├─ Span: Auth Service (5ms)
   └─ Span: Order Service (80ms)
      ├─ Span: Database Query (30ms)
      ├─ Span: Payment Service (40ms)
      └─ Span: Inventory Service (10ms)
```

**Span attributes:**

```json
{
  "trace_id": "abc123",
  "span_id": "def456",
  "parent_span_id": "ghi789",
  "name": "POST /orders",
  "start_time": "2024-01-08T10:00:00Z",
  "duration_ms": 80,
  "attributes": {
    "http.method": "POST",
    "http.url": "/orders",
    "http.status_code": 201,
    "db.system": "postgresql",
    "db.statement": "INSERT INTO orders..."
  }
}
```

**Sampling strategies:**

**Head-based sampling (decided upfront):**

- Sample 1% of all requests
- Sample 100% of errors
- Sample based on trace ID

**Tail-based sampling (decided after trace completes):**

- Keep slow traces (> 1s)
- Keep error traces
- Keep traces with specific attributes
- More accurate but more expensive

#### 3. Logs (Event Records)

**Structured logging (JSON):**

```json
{
  "timestamp": "2024-01-08T10:00:00Z",
  "level": "ERROR",
  "message": "Failed to process order",
  "trace_id": "abc123",
  "span_id": "def456",
  "service": "order-service",
  "user_id": "user123",
  "order_id": "order456",
  "error": "Payment declined",
  "stack_trace": "..."
}
```

**Log levels:**

- **ERROR:** Application errors requiring attention
- **WARN:** Potential issues, degraded performance
- **INFO:** Normal operational events
- **DEBUG:** Detailed diagnostic information

**Correlation with traces:**

```go
// Inject trace context into logs
logger.With(
    "trace_id", span.TraceID(),
    "span_id", span.SpanID(),
).Info("Processing order")
```

### OpenTelemetry Implementation

**Architecture:**

```text
Application → OTel SDK → OTel Collector → Backends
                                        ├─ Prometheus (metrics)
                                        ├─ Jaeger (traces)
                                        └─ Loki (logs)
```

**Instrumentation:**

**Automatic (framework/library instrumentation):**

```go
import (
    "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// HTTP client automatically traced
client := http.Client{
    Transport: otelhttp.NewTransport(http.DefaultTransport),
}
```

**Manual (custom spans):**

```go
import (
    "go.opentelemetry.io/otel"
)

func ProcessOrder(ctx context.Context, order Order) error {
    tracer := otel.Tracer("order-service")
    ctx, span := tracer.Start(ctx, "ProcessOrder")
    defer span.End()

    span.SetAttributes(
        attribute.String("order.id", order.ID),
        attribute.Float64("order.total", order.Total),
    )

    // Business logic
    if err := validateOrder(ctx, order); err != nil {
        span.RecordError(err)
        return err
    }

    return nil
}
```

**Collector configuration:**

```yaml
receivers:
  otlp:
    protocols:
      grpc:
      http:

processors:
  batch:
    timeout: 10s
    send_batch_size: 1024

  # Sample traces
  probabilistic_sampler:
    sampling_percentage: 10

exporters:
  prometheus:
    endpoint: "prometheus:9090"
  jaeger:
    endpoint: "jaeger:14250"
  loki:
    endpoint: "http://loki:3100/loki/api/v1/push"

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch, probabilistic_sampler]
      exporters: [jaeger]
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [prometheus]
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [loki]
```

## GitOps Principles

### Core Tenets

**1. Declarative configuration**

Infrastructure and applications described in Git:

```yaml
# kubernetes/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: api
        image: myapp:v1.2.3
```

**2. Git as single source of truth**

All changes via Git commits (no `kubectl apply`):

```bash
# Bad: Direct apply
kubectl apply -f deployment.yaml

# Good: Commit to Git, GitOps operator applies
git add deployment.yaml
git commit -m "Scale to 3 replicas"
git push origin main
```

**3. Automated sync**

Operator reconciles cluster state with Git state:

```text
Every 3 minutes:
  1. Fetch latest from Git
  2. Compare with cluster state
  3. Apply differences
  4. Report sync status
```

**4. Pull-based deployment**

Cluster pulls changes (not CI/CD pushes):

```text
Traditional push:
  CI/CD → kubectl apply → Cluster

GitOps pull:
  CI/CD → Git commit
  Cluster operator → Git fetch → Self-apply
```

### Workflow Example

**Environment promotion:**

```text
Feature branch → dev cluster (auto-deploy on commit)
   ↓ PR
Staging branch → staging cluster (auto-deploy after tests)
   ↓ PR + approval
Main branch → production cluster (auto-deploy with approval)
```

**Directory structure:**

```text
infrastructure/
├── base/                  # Common resources
│   ├── deployment.yaml
│   ├── service.yaml
│   └── kustomization.yaml
├── environments/
│   ├── dev/
│   │   ├── kustomization.yaml
│   │   └── config.yaml   # Dev-specific overrides
│   ├── staging/
│   │   ├── kustomization.yaml
│   │   └── config.yaml
│   └── prod/
│       ├── kustomization.yaml
│       └── config.yaml
```

**Benefits:**

1. **Audit trail:** All changes in Git history
1. **Easy rollback:** `git revert` to undo changes
1. **Disaster recovery:** Recreate cluster from Git
1. **Consistency:** Environments defined as code
1. **Review process:** PRs for infrastructure changes

### Tools

**Flux:**

- CNCF graduated project
- Multi-tenancy support
- Helm and Kustomize support
- Notification system

**ArgoCD:**

- Rich web UI
- Application-centric view
- RBAC integration
- Multiple sync strategies

**Jenkins X:**

- Kubernetes-native CI/CD
- Preview environments
- Automated promotion

## Production Readiness Checklist

### Monitoring and Observability

- [ ] **Service dashboards** with RED metrics
  - Request rate
  - Error rate (4xx, 5xx)
  - Duration (p50, p95, p99)

- [ ] **Resource dashboards** with USE metrics
  - CPU utilization and saturation
  - Memory utilization and saturation
  - Disk I/O and saturation
  - Network bandwidth

- [ ] **Alerts** with appropriate thresholds
  - Error rate > 1% for 5 minutes
  - P95 latency > 500ms for 5 minutes
  - CPU > 80% for 10 minutes
  - Memory > 90% for 5 minutes

- [ ] **Distributed tracing** configured and sampled
  - 100% sampling for errors
  - 10% sampling for success
  - Trace retention: 7 days

- [ ] **Structured logging** with correlation IDs
  - JSON format
  - Trace ID and span ID included
  - Log level configurable per service

- [ ] **SLOs defined** and tracked
  - Availability: 99.9% uptime
  - Latency: P95 < 500ms
  - Error rate: < 0.1%

### Incident Response

- [ ] **Runbooks** for common failure modes
  - Database connection pool exhausted
  - High latency troubleshooting
  - Memory leak investigation
  - Disk full recovery

- [ ] **On-call rotation** and escalation paths
  - Primary: 30 min response time
  - Secondary: 1 hour response time
  - Manager: 2 hour response time

- [ ] **Incident management process**
  - Detection: Automated alerts
  - Response: Runbooks and playbooks
  - Resolution: Fix or rollback
  - Postmortem: Blameless review within 48 hours

- [ ] **Rollback procedures** documented and tested
  - Application rollback: < 5 minutes
  - Database rollback: < 30 minutes
  - Infrastructure rollback: < 15 minutes

- [ ] **Emergency contacts** and communication channels
  - Slack: #incidents channel
  - PagerDuty: Escalation policies
  - Email: Distribution lists

### Security and Compliance

- [ ] **Secrets managed externally**
  - HashiCorp Vault
  - AWS Secrets Manager
  - Kubernetes External Secrets

- [ ] **Dependency scanning** for vulnerabilities
  - Daily scans
  - Critical: Fix within 24 hours
  - High: Fix within 7 days

- [ ] **Container image scanning**
  - Scan on build
  - Block deployment of critical vulnerabilities
  - Rescan images weekly

- [ ] **Encryption at rest and in transit**
  - TLS 1.3 for all services
  - Database encryption enabled
  - Encrypted backups

- [ ] **Access control** with least privilege
  - RBAC for Kubernetes
  - IAM roles for cloud resources
  - MFA for human access

- [ ] **Compliance validation**
  - SOC 2 Type II
  - HIPAA (if applicable)
  - GDPR (if applicable)
  - PCI DSS (if applicable)

### Performance and Scalability

- [ ] **Load testing** completed
  - Expected load + 3x headroom
  - Peak traffic scenarios
  - Sustained load (24 hours)

- [ ] **Auto-scaling** configured and tested
  - HPA: Scale at 70% CPU
  - Cluster autoscaler: Add nodes at 80% capacity
  - Scale-down delay: 10 minutes

- [ ] **Database query performance** validated
  - No N+1 queries
  - Proper indexes on common queries
  - Query execution time < 100ms (p95)

- [ ] **Caching strategy** implemented
  - CDN for static assets
  - Redis for session data
  - Application cache for reference data

- [ ] **Rate limiting** and throttling configured
  - Per-user: 1000 requests/minute
  - Per-IP: 10000 requests/minute
  - Burst: 2x sustained rate for 10s

### Ownership and Documentation

- [ ] **Service ownership** assigned
  - Team: Platform Team
  - On-call: Rotation schedule
  - Slack: #team-platform

- [ ] **Architecture documentation** current
  - System diagram
  - Data flow diagram
  - Architecture Decision Records (ADRs)

- [ ] **API documentation** published
  - OpenAPI spec for REST
  - GraphQL schema
  - Code examples

- [ ] **Deployment procedures** documented
  - CI/CD pipeline description
  - Manual deployment steps
  - Rollback procedure

- [ ] **Disaster recovery plan** tested
  - Last test date: Q3 2024
  - Next test date: Q1 2025
  - Recovery time: 2 hours (RTO)
  - Data loss: 15 minutes (RPO)

## Key Metrics to Monitor

### Service Health

**Latency percentiles (not averages!):**

```text
P50: 100ms   (median)
P95: 250ms   (95% of requests faster)
P99: 500ms   (99% of requests faster)
P99.9: 2s    (slowest 0.1%)
```

**Error budget:**

```text
SLO: 99.9% availability = 0.1% error budget
Monthly error budget: 43 minutes downtime
Burn rate: % of budget used per day
```

**Apdex score (Application Performance Index):**

```text
Satisfied: Latency < 300ms    (weight: 1.0)
Tolerating: 300ms - 1200ms    (weight: 0.5)
Frustrated: > 1200ms          (weight: 0.0)

Apdex = (Satisfied + 0.5 * Tolerating) / Total
```

### Resource Utilization

**CPU:**

- Target: 70% average
- Alert: > 80% for 10 min

**Memory:**

- Target: 80% usage
- Alert: > 90% for 5 min

**Disk:**

- Target: < 80% full
- Alert: > 90% full

**Network:**

- Monitor: Bandwidth usage
- Alert: Approaching interface limits

## Best Practices

1. **Monitor business metrics:** Not just technical metrics
1. **Alert on symptoms:** User-facing issues, not root causes
1. **Reduce alert fatigue:** Only actionable alerts
1. **Test your monitoring:** Chaos engineering, failure injection
1. **Correlate metrics, traces, logs:** Single pane of glass
1. **Define SLOs early:** Before going to production
1. **Automate remediation:** Self-healing where possible
1. **Document everything:** Runbooks save lives during incidents
