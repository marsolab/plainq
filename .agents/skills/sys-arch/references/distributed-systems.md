# Distributed Systems

Comprehensive guide to building reliable, scalable distributed systems.

## CAP Theorem Application

**Theorem:** In a distributed system with network partitions, choose 2 of 3:

- **Consistency (C):** Every read sees the most recent write
- **Availability (A):** Every request gets a response (no guarantee it's latest)
- **Partition Tolerance (P):** System continues despite network failures

**Reality:** Partitions happen, so choose CP or AP.

### CP Systems (Consistency + Partition Tolerance)

**Use when:** Financial transactions, inventory management, authentication

**Examples:** PostgreSQL with sync replication, etcd, Consul, HBase

**Behavior during partition:** Block requests to maintain consistency

**Trade-offs:**

- ✓ Strong consistency guarantees
- ✓ Data accuracy maintained
- ✗ Reduced availability during network partitions
- ✗ Higher latency (coordination overhead)

### AP Systems (Availability + Partition Tolerance)

**Use when:** Social feeds, product catalogs, analytics, caching

**Examples:** Cassandra, DynamoDB, Riak, CouchDB

**Behavior during partition:** Accept writes, resolve conflicts later

**Trade-offs:**

- ✓ Always available for reads and writes
- ✓ Better performance and scalability
- ✗ Temporary inconsistency
- ✗ Conflict resolution complexity

### CA Systems (Consistency + Availability)

**Reality:** Only in single-datacenter systems with no network partitions

**Examples:** Single PostgreSQL instance, traditional RDBMS

**Limitation:** No partition tolerance—network split breaks system

## Distributed Transactions

### Two-Phase Commit (2PC)

**Use when:**

- Strong consistency required across services
- Operations within same datacenter
- Short-lived transactions (< 1 second)
- Can tolerate blocking during coordinator failure

**Avoid when:**

- Cross-region operations (high latency)
- Long-running transactions
- High availability critical

**How it works:**

1. **Prepare Phase:** Coordinator asks all participants to prepare
1. **Vote:** Participants respond with "ready" or "abort"
1. **Commit Phase:** If all ready, coordinator sends commit; otherwise abort
1. **Complete:** Participants execute and acknowledge

**Trade-offs:**

- ✓ Strong consistency across multiple databases
- ✓ ACID guarantees maintained
- ✗ Coordinator is single point of failure
- ✗ Blocking protocol (participants wait for coordinator)
- ✗ Performance penalty (multiple round-trips)

### Saga Pattern

**Use when:**

- Long-running business processes
- Cross-service transactions
- High availability required
- Can tolerate eventual consistency

**Two approaches:**

#### 1. Choreography (Event-Driven)

Services publish events, others react.

**Example:**

```text
OrderService creates order → publishes OrderCreated
InventoryService reserves inventory → publishes InventoryReserved
PaymentService processes payment → publishes PaymentProcessed
ShippingService creates shipment → publishes OrderShipped
```

**Pros:**

- No central coordinator
- Loose coupling between services
- Services can be added/removed easily

**Cons:**

- Hard to understand complete flow
- Complex error handling across services
- Difficult to debug and monitor

#### 2. Orchestration (Centralized)

Central coordinator directs the process.

**Example:**

```text
OrderOrchestrator:
  1. Call OrderService.createOrder()
  2. Call InventoryService.reserveInventory()
  3. Call PaymentService.processPayment()
  4. Call ShippingService.createShipment()
```

**Pros:**

- Clear, understandable flow
- Centralized error handling
- Easy to add business logic
- Simpler debugging

**Cons:**

- Coordinator is single point of failure
- Potential bottleneck
- Tighter coupling to coordinator

### Compensating Transactions

Each step has a rollback action for saga patterns:

```text
Forward flow:
  CreateOrder → ReserveInventory → ProcessPayment → ShipOrder

Compensating flow (rollback):
  CancelOrder ← ReleaseInventory ← RefundPayment ← CancelShipment
```

**Design principles:**

- Idempotent operations (safe to retry)
- Compensating actions for each step
- Store saga state for recovery
- Timeout mechanisms for stalled sagas

## Fault Tolerance Strategies

### 1. Redundancy

**Active-Active:** Both nodes serve traffic (load balancing)

- Use for: High availability, no downtime
- Example: Two app servers behind load balancer

**Active-Passive:** Passive node takes over on failure (failover)

- Use for: Cost efficiency, simpler management
- Example: Primary database with standby replica

**N+1 Redundancy:** One extra node for every N needed

- Use for: Moderate redundancy, cost-effective
- Example: 4 servers to handle load of 3

**N+2 Redundancy:** Two extra nodes (survive simultaneous failures)

- Use for: Mission-critical systems
- Example: 5 servers to handle load of 3

### 2. Health Checks

**Liveness probe:** Is service running? (restart if fails)

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10
```

**Readiness probe:** Can service handle traffic? (remove from load balancer if
fails)

```yaml
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
```

**Startup probe:** Has service finished initialization? (delay other probes)

```yaml
startupProbe:
  httpGet:
    path: /startup
    port: 8080
  failureThreshold: 30
  periodSeconds: 10
```

### 3. Retry Strategies

**Exponential backoff:** Progressively increase wait time

```text
Attempt 1: Wait 1s
Attempt 2: Wait 2s
Attempt 3: Wait 4s
Attempt 4: Wait 8s
Attempt 5: Wait 16s
```

**Jitter:** Add randomness to prevent synchronized retries

```text
wait_time = base_delay * (2 ^ attempt) * (1 + random(0, 0.1))
```

**Idempotency:** Design endpoints to safely handle duplicate requests

- Use idempotency keys for writes
- Check if operation already completed
- Return same result for duplicate requests

**Retry budgets:** Limit total retries to prevent resource exhaustion

```text
max_retries = 3
timeout_per_attempt = 5s
total_timeout = 20s
```

### 4. Circuit Breaker Pattern

Prevent cascading failures by detecting unhealthy dependencies.

**States:**

**Closed (Normal):** Requests pass through

- Monitor error rate and latency
- Count consecutive failures

**Open (Failing):** All requests fail immediately

- Prevents load on failing service
- Allows service time to recover
- Transition to half-open after timeout

**Half-Open (Testing):** Limited requests allowed

- Test if service recovered
- If successful, transition to closed
- If failed, transition back to open

**Configuration example:**

```text
error_threshold: 50%
consecutive_failures: 10
timeout: 30s
half_open_requests: 3
```

### 5. Bulkhead Pattern

Isolate resources to prevent cascading failures.

**Thread pool isolation:**

```text
Payment service: 20 threads
Inventory service: 10 threads
User service: 30 threads
```

**Connection pool limits:**

```text
Database pool: 50 connections
Redis pool: 20 connections
External API pool: 10 connections
```

**Resource quotas:**

```text
CPU: 2 cores per service
Memory: 4GB per service
Connections: 100 per service
```

### 6. Consensus Protocols

For distributed coordination and agreement.

**Paxos:**

- Academic foundation for distributed consensus
- Complex to understand and implement
- Proven correctness guarantees

**Raft:**

- Designed for understandability
- Widely adopted (etcd, Consul, CockroachDB)
- Leader election + log replication

**Use cases:**

- Leader election in distributed systems
- Distributed configuration management
- Distributed locks
- Replicated state machines

**Raft algorithm phases:**

1. **Leader Election:** Nodes elect a leader via voting
1. **Log Replication:** Leader replicates logs to followers
1. **Safety:** Ensure committed entries are durable

## Database Sharding

Horizontal sharding: Split data across multiple databases by key.

### Sharding Strategies

#### 1. Range-Based Sharding

Split by key ranges:

```text
Shard 1: User IDs 1-1,000,000
Shard 2: User IDs 1,000,001-2,000,000
Shard 3: User IDs 2,000,001-3,000,000
```

**Pros:**

- Simple to understand and implement
- Range queries efficient (all data in one shard)
- Easy to add new shards

**Cons:**

- Uneven distribution (hotspots)
- Popular ranges create hot shards
- Requires rebalancing

#### 2. Hash-Based Sharding

Use hash function to determine shard:

```text
shard_id = hash(user_id) % num_shards
```

**Pros:**

- Even data distribution
- No hotspots with good hash function
- Simple logic

**Cons:**

- Range queries span multiple shards
- Resharding requires data migration
- Can't easily add/remove shards

#### 3. Geographic Sharding

Split by geographic region:

```text
US East: us_east_db
Europe: eu_db
Asia: asia_db
```

**Pros:**

- Data locality (low latency)
- Regulatory compliance (GDPR)
- Natural boundaries

**Cons:**

- Uneven distribution
- Cross-region queries expensive
- Complexity in multi-region users

#### 4. Directory-Based Sharding

Lookup table maps keys to shards:

```text
User 123 → Shard A
User 456 → Shard B
User 789 → Shard A
```

**Pros:**

- Maximum flexibility
- Easy to reshard (update directory)
- Can use any sharding logic

**Cons:**

- Lookup overhead on every query
- Directory becomes bottleneck
- Directory is single point of failure

### When to Shard

**Indicators:**

- Single database CPU > 80% sustained
- Database size > 1TB (PostgreSQL), > 100GB (MySQL)
- Query latency degrading despite indexing
- Write throughput exceeds single node capacity

**Before sharding, try:**

1. Vertical scaling (larger instance)
1. Read replicas (scale reads)
1. Query optimization (indexes, caching)
1. Data archiving (remove old data)

**Sharding threshold:**

- PostgreSQL: ~1TB or 10K writes/second
- MySQL: ~100GB or 5K writes/second
- MongoDB: Auto-sharding at any size

### Sharding Challenges

**Cross-shard queries:**

- Scatter-gather pattern (query all shards, merge results)
- Performance penalty
- Complex aggregations

**Distributed transactions:**

- 2PC across shards (slow, blocking)
- Saga pattern (eventual consistency)
- Avoid when possible

**Rebalancing:**

- Adding/removing shards requires data migration
- Consistent hashing reduces migration
- Plan for downtime or dual-write period

**Schema changes:**

- Must coordinate across all shards
- Use online schema migration tools
- Test thoroughly before production

## Best Practices

1. **Design for failure:** Assume components will fail
1. **Idempotency:** Make operations safely retryable
1. **Timeouts:** Every external call needs a timeout
1. **Circuit breakers:** Protect from cascading failures
1. **Monitoring:** Track error rates, latency, throughput
1. **Testing:** Chaos engineering to validate fault tolerance
1. **Documentation:** Document failure modes and recovery procedures
