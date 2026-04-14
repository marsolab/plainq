# Data Architecture

Comprehensive guide to database selection, caching, replication, and backup
strategies.

## Database Comparison Matrix

### Detailed Comparison

| Database | Type | Best For | Consistency | Scaling | Query Flexibility | License |
|----------|------|----------|-------------|---------|-------------------|---------|
| **PostgreSQL** | Relational | Structured data, ACID, complex queries | Strong | Vertical + read replicas | SQL, JSONB queries | Open Source |
| **MongoDB** | Document | Flexible schemas, nested data | Eventual (tunable) | Horizontal sharding | Rich aggregation pipeline | SSPL |
| **Redis** | Key-Value | Caching, sessions, pub/sub | Strong (single instance) | Replication, Redis Cluster | Key lookups, limited queries | BSD |
| **DynamoDB** | Key-Value | Serverless, massive scale, AWS-native | Eventual (strong option) | Automatic horizontal | Primary key, secondary indexes | Proprietary |
| **Cassandra** | Wide-Column | Write-heavy, time-series, AP system | Eventual (tunable) | Linear horizontal | CQL, partition key required | Apache 2.0 |
| **ClickHouse** | Columnar | Analytics, time-series, aggregations | Eventual | Horizontal | SQL, optimized for analytics | Apache 2.0 |
| **MySQL** | Relational | Web applications, read-heavy | Strong | Vertical + read replicas | SQL queries | GPL/Commercial |
| **Elasticsearch** | Search Engine | Full-text search, log analysis | Eventual | Horizontal | JSON-based DSL, complex queries | Elastic License |

### Database Selection Decision Tree

**Need ACID transactions and complex queries?**

- Yes → PostgreSQL or MySQL
- No → Continue

**Need flexible schema and document storage?**

- Yes → MongoDB
- No → Continue

**Need fast key-value access?**

- Yes → Redis (in-memory) or DynamoDB (persistent)
- No → Continue

**Need full-text search?**

- Yes → Elasticsearch
- No → Continue

**Need analytics and aggregations?**

- Yes → ClickHouse or PostgreSQL
- No → Continue

**Need extreme write scalability?**

- Yes → Cassandra or DynamoDB

## Polyglot Persistence

Use the right database for each use case within a single application.

### Example Architecture

```text
User Service:
  PostgreSQL: User accounts, profiles (ACID required)
  Redis: Session store, authentication tokens

Product Catalog:
  MongoDB: Product data, flexible schema
  Elasticsearch: Product search, faceted navigation
  Redis: Product cache, pricing data

Order Service:
  PostgreSQL: Orders, transactions (ACID required)
  Redis: Cart data, temporary order state

Analytics:
  ClickHouse: User events, metrics, dashboards
  PostgreSQL: Aggregated reports, business intelligence

Logging:
  Elasticsearch: Application logs, full-text search
  S3/Object Storage: Long-term log archival
```

### Benefits and Challenges

**Benefits:**

- Optimal tool for each use case
- Independent scaling per data store
- Performance optimization per workload
- Technology experimentation without full migration

**Challenges:**

- Operational complexity (multiple systems to manage)
- Data consistency across stores
- Team expertise requirements
- Increased infrastructure costs
- Complex disaster recovery

### Decision Criteria

1. **Consistency requirements:** Strong (PostgreSQL) vs Eventual (MongoDB,
  Cassandra)
1. **Query patterns:** Complex joins (SQL) vs Simple lookups (NoSQL)
1. **Scale expectations:** Vertical (PostgreSQL) vs Horizontal (Cassandra,
  DynamoDB)
1. **Team expertise:** What does the team know?
1. **Operational burden:** Managed services (DynamoDB, Aurora) vs Self-hosted

## Caching Strategies

### Cache Layers

#### 1. CDN (Edge Caching)

**Location:** Globally distributed edge locations

**Use for:**

- Static assets (images, JavaScript, CSS)
- API responses with long TTL
- HTML pages for public content

**TTL:** Hours to days

**Tools:** CloudFlare, AWS CloudFront, Fastly, Akamai

**Configuration example:**

```text
Static assets: 1 year TTL
API responses: 5 minutes TTL
HTML pages: 1 hour TTL
```

#### 2. Application Cache (In-Process)

**Location:** Within application memory

**Use for:**

- Frequently accessed data
- Computation results
- Reference data (countries, config)

**TTL:** Minutes to hours

**Tools:** Caffeine (Java), Guava Cache, memory dictionaries

**Example:**

```java
LoadingCache<String, User> userCache = CacheBuilder.newBuilder()
    .maximumSize(10000)
    .expireAfterWrite(10, TimeUnit.MINUTES)
    .build(CacheLoader.from(userId -> loadUserFromDatabase(userId)));
```

#### 3. Distributed Cache

**Location:** Separate cache cluster

**Use for:**

- Session data (shared across app instances)
- User preferences
- Rate limiting counters
- Leaderboards, real-time data

**TTL:** Seconds to hours

**Tools:** Redis, Memcached

**Example:**

```python
import redis
cache = redis.Redis(host='cache.example.com', port=6379)

# Cache user profile
cache.setex(f'user:{user_id}', 300, json.dumps(user_data))

# Rate limiting
cache.incr(f'ratelimit:{user_id}:{minute}')
cache.expire(f'ratelimit:{user_id}:{minute}', 60)
```

#### 4. Database Query Cache

**Location:** Database layer

**Use for:**

- Repeated queries with same parameters
- Complex aggregations
- Materialized views

**TTL:** Automatic invalidation on data change

**Tools:** PostgreSQL query cache, MySQL query cache, materialized views

### Cache Invalidation Strategies

#### 1. TTL-Based (Time-to-Live)

Expire after fixed time.

**Pros:**

- Simple to implement
- Predictable behavior
- No coordination needed

**Cons:**

- May serve stale data
- Inefficient (refreshes even if unchanged)

**Example:**

```python
cache.setex('product:123', 300, product_data)  # 5 min TTL
```

#### 2. Write-Through

Update cache on every write.

**Pros:**

- Always consistent
- Cache always warm

**Cons:**

- Slower writes
- Unnecessary if data rarely read

**Example:**

```python
def update_user(user_id, data):
    database.update_user(user_id, data)
    cache.set(f'user:{user_id}', data)
```

#### 3. Write-Behind (Write-Back)

Async cache update after write.

**Pros:**

- Faster writes
- Batching possible

**Cons:**

- Brief inconsistency
- Data loss risk if cache fails

**Example:**

```python
def update_user(user_id, data):
    database.update_user(user_id, data)
    queue.publish('cache_invalidate', {'user_id': user_id})
```

#### 4. Cache-Aside (Lazy Loading)

Application manages cache.

**Pros:**

- Flexible
- Only cache what's accessed
- Handles cache misses gracefully

**Cons:**

- Application complexity
- Stale data possible

**Example:**

```python
def get_user(user_id):
    # Try cache first
    user = cache.get(f'user:{user_id}')
    if user:
        return user

    # Cache miss, load from database
    user = database.get_user(user_id)
    cache.setex(f'user:{user_id}', 300, user)
    return user
```

### Cache Eviction Policies

**LRU (Least Recently Used):** Evict items not accessed recently

- Best for: General purpose caching
- Redis: `maxmemory-policy allkeys-lru`

**LFU (Least Frequently Used):** Evict least popular items

- Best for: Long-lived caches with stable access patterns
- Redis: `maxmemory-policy allkeys-lfu`

**FIFO (First In, First Out):** Evict oldest items

- Best for: Simple, predictable behavior
- Use when: Access patterns don't matter

**TTL:** Evict expired items first

- Best for: Time-sensitive data
- Redis: `maxmemory-policy volatile-ttl`

## Data Replication

### Synchronous Replication

**Behavior:** Primary waits for replica acknowledgment before confirming write

**Consistency:** Strong—replicas always have latest data

**Latency:** Higher—network round-trip added to writes

**Use when:**

- Data loss unacceptable
- Can tolerate write latency
- Within same region/datacenter

**Example: PostgreSQL synchronous replication:**

```sql
-- postgresql.conf
synchronous_standby_names = 'standby1,standby2'
synchronous_commit = on
```

**Trade-offs:**

- ✓ Zero data loss (RPO = 0)
- ✓ Immediate consistency
- ✗ Higher write latency (50-100ms penalty)
- ✗ Write availability depends on replica health

### Asynchronous Replication

**Behavior:** Primary confirms write immediately, replicates in background

**Consistency:** Eventual—replicas lag behind primary

**Latency:** Lower—no write penalty

**Use when:**

- High write throughput required
- Can tolerate brief data loss
- Cross-region replication

**Example: MySQL asynchronous replication:**

```sql
-- On replica
CHANGE MASTER TO
    MASTER_HOST='primary.example.com',
    MASTER_USER='replication',
    MASTER_PASSWORD='password';
START SLAVE;
```

**Trade-offs:**

- ✓ Low write latency
- ✓ High write throughput
- ✗ Data loss during failure (RPO = replication lag)
- ✗ Reads may be stale

### Multi-Region Patterns

#### 1. Active-Passive (Disaster Recovery)

**Setup:**

- Primary region serves all traffic
- Standby region receives async replication
- Failover on primary region failure

**RPO:** Minutes (async replication lag)
**RTO:** 5-15 minutes (failover time)

**Use for:** Cost-effective disaster recovery

#### 2. Active-Active (Multi-Master)

**Setup:**

- Both regions serve traffic simultaneously
- Bidirectional replication
- Conflict resolution mechanism

**RPO:** Near-zero (bidirectional replication)
**RTO:** Seconds (automatic failover)

**Use for:** Global applications, zero-downtime failover

**Conflict resolution strategies:**

- Last-write-wins (timestamp-based)
- Vector clocks (causal ordering)
- CRDTs (Conflict-free Replicated Data Types)
- Application-defined resolution

#### 3. Read Replicas

**Setup:**

- Primary handles writes
- Replicas handle reads
- One-way async replication

**Use for:**

- Read-heavy workloads
- Geographic distribution of reads
- Analytics queries

**Limitation:** Reads may be stale (replication lag: 100ms - 5s typical)

## Backup Strategies

### 3-2-1 Backup Rule

**3 copies:** Production data + 2 backups
**2 media:** Different storage types (disk + cloud)
**1 offsite:** Geographic separation for disaster recovery

### Backup Types

#### 1. Full Backup

Complete copy of all data.

**Pros:**

- Simple to restore (one backup set)
- No dependencies
- Fast restore

**Cons:**

- Slow to create (copies everything)
- Expensive (storage costs)
- High bandwidth usage

**Schedule:** Weekly or monthly

#### 2. Incremental Backup

Changes since last backup (any type).

**Pros:**

- Fast to create
- Minimal storage
- Low bandwidth

**Cons:**

- Complex restore (need all incremental backups)
- Chain of dependencies
- Longer restore time

**Schedule:** Daily or hourly

#### 3. Differential Backup

Changes since last full backup.

**Pros:**

- Moderate speed
- Simpler restore (full + one differential)
- No chain dependencies

**Cons:**

- Grows over time
- More storage than incremental

**Schedule:** Daily

#### 4. Snapshot

Point-in-time copy (filesystem or storage level).

**Pros:**

- Very fast (copy-on-write)
- Storage-efficient
- Consistent state

**Cons:**

- Depends on underlying storage
- Not a true backup (same storage)
- Limited retention

**Schedule:** Hourly or per transaction

### RPO/RTO Targets

| Business Tier | RPO | RTO | Strategy | Estimated Cost |
|---------------|-----|-----|----------|----------------|
| **Critical** | < 1 min | < 5 min | Sync replication, auto failover | 2x base cost |
| **High** | < 15 min | < 1 hour | Async replication, warm standby | 1.5x base cost |
| **Medium** | < 4 hours | < 4 hours | Periodic backups, restore testing | 1.2x base cost |
| **Low** | < 24 hours | < 24 hours | Daily backups, manual restore | 1.1x base cost |

### Backup Testing

**Test restore procedures regularly:**

- [ ] Quarterly full restore test
- [ ] Measure actual restore time vs RTO target
- [ ] Verify data integrity post-restore (checksums, spot checks)
- [ ] Document restore procedure (automate if possible)
- [ ] Test cross-region restore (not just same region)
- [ ] Validate backup encryption and access controls

**Common failures:**

- Backups succeed but restores fail (corrupted, missing dependencies)
- Restore slower than expected (bandwidth, database import time)
- Partial data recovery (missing logs, incomplete backups)
- Incorrect permissions (can't access backup storage)

### Backup Automation

**PostgreSQL example:**

```bash
#!/bin/bash
# Daily backup script
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups"
DATABASE="production"

# Full backup with compression
pg_dump -h localhost -U postgres -d $DATABASE | gzip > \
    $BACKUP_DIR/full_$DATE.sql.gz

# Upload to S3
aws s3 cp $BACKUP_DIR/full_$DATE.sql.gz \
    s3://backups/$DATABASE/

# Delete local backups older than 7 days
find $BACKUP_DIR -name "full_*.sql.gz" -mtime +7 -delete

# Verify backup
gunzip -t $BACKUP_DIR/full_$DATE.sql.gz
```

## Best Practices

1. **Start simple:** PostgreSQL can handle most workloads before needing NoSQL
1. **Cache reads, not writes:** Caching helps read-heavy workloads most
1. **Monitor replication lag:** Alert when lag exceeds acceptable threshold
1. **Test backups:** Untested backups are worthless
1. **Document data flows:** Track how data moves between systems
1. **Plan for failure:** Every component will fail eventually
1. **Measure don't guess:** Profile queries, monitor cache hit rates
