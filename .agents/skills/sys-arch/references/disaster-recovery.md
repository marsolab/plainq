# Disaster Recovery

Comprehensive guide to RPO/RTO planning, multi-region failover, and backup
strategies.

## RPO and RTO Analysis

### Definitions

**Recovery Point Objective (RPO):**

- Maximum acceptable data loss (time between last backup and disaster)
- "How much data can we afford to lose?"
- Measured in time (minutes, hours, days)
- Drives backup frequency and replication strategy

**Recovery Time Objective (RTO):**

- Maximum acceptable downtime
- "How long can we be offline?"
- Measured in time (minutes, hours, days)
- Drives infrastructure redundancy and failover automation

### RPO/RTO Matrix

| Business Tier | RPO | RTO | Strategy | Infrastructure | Annual Cost |
|---------------|-----|-----|----------|----------------|-------------|
| **Critical** | < 1 min | < 5 min | Sync replication, active-active, auto-failover | Multi-region, load-balanced | 2x base |
| **High** | < 15 min | < 1 hour | Async replication, warm standby, automated failover | Multi-region, standby ready | 1.5x base |
| **Medium** | < 4 hours | < 4 hours | Periodic backups, cold standby, manual failover | Single region, backup storage | 1.2x base |
| **Low** | < 24 hours | < 24 hours | Daily backups, restore from scratch | Minimal redundancy | 1.1x base |

### Business Impact Analysis

**Questions to determine tier:**

1. **Revenue impact:** How much revenue lost per hour of downtime?
1. **Customer impact:** How many users affected?
1. **Regulatory requirements:** Any compliance mandates? (HIPAA, PCI DSS)
1. **Reputation risk:** Will downtime damage brand?
1. **Data sensitivity:** How critical is data accuracy?

**Example: E-commerce checkout**

- Revenue: $1M/day = $42K/hour
- Customer impact: 10K daily active users
- Regulatory: PCI DSS requires data protection
- **Decision:** Critical tier (RPO < 1 min, RTO < 5 min)

**Example: Blog analytics dashboard**

- Revenue: Indirect, minimal direct impact
- Customer impact: Internal users only
- Regulatory: None
- **Decision:** Medium tier (RPO < 4 hours, RTO < 4 hours)

### Cost-Benefit Analysis

**Critical tier costs:**

- Active-active infrastructure: 2x compute costs
- Multi-region networking: $500-$1K/month
- Synchronous replication: Performance penalty
- 24/7 on-call team: $200K/year personnel

**High tier costs:**

- Warm standby: 1.3x compute costs (standby at reduced capacity)
- Cross-region replication: $200-$500/month
- Automated failover tooling: $10K/year
- On-call rotation: $100K/year personnel

**Medium tier costs:**

- Backup storage: $100-$300/month
- Restore testing: Quarterly (4 hours each)
- Manual failover procedures: Documentation maintenance

## Multi-Region Failover Patterns

### Active-Passive (Disaster Recovery)

**Setup:**

```text
Primary Region (us-east-1):
  ├─ Application Servers (active, serving traffic)
  ├─ Load Balancer (active)
  ├─ Database Primary (writes + reads)
  └─ Async Replication ──────→

Standby Region (us-west-2):
  ├─ Application Servers (minimal or stopped)
  ├─ Load Balancer (ready but no traffic)
  ├─ Database Replica (read-only, async lag)
  └─ Promoted to primary on failure
```

**Failover process:**

1. **Detection (1-2 minutes):**

   ```text
   - Health checks fail in primary region
   - Route 53 health check detects outage
   - PagerDuty alert triggered
   ```

1. **Promotion (5-10 minutes):**

   ```text
   - Promote replica database to primary
   - Verify replication lag caught up
   - Enable writes on new primary
   ```

1. **DNS Update (1-5 minutes):**

   ```text
   - Update Route 53 to point to standby region
   - Wait for DNS TTL propagation (60-300s)
   - Monitor traffic shifting to new region
   ```

1. **Scale Up (3-5 minutes):**

   ```text
   - Increase standby application server count
   - Verify all services healthy
   - Monitor error rates and latency
   ```

**Total RTO:** 15-30 minutes

**RPO:** 1-5 minutes (async replication lag)

**Pros:**

- Cost-effective (minimal standby resources)
- Simple to understand and implement
- Clear primary region

**Cons:**

- Manual intervention required
- Data loss during failure (RPO > 0)
- Longer recovery time
- Cold start issues (scaling up servers)

### Active-Active (Multi-Region Serving)

**Setup:**

```text
Region A (us-east-1):                Region B (us-west-2):
  ├─ Serves 50% traffic                ├─ Serves 50% traffic
  ├─ Application Servers (full)        ├─ Application Servers (full)
  ├─ Database Primary                  ├─ Database Primary
  └─ Bidirectional Replication ←──────→└─ Bidirectional Replication

Global Load Balancer (Route 53, CloudFlare):
  ├─ Geolocation routing (users → nearest region)
  ├─ Health checks on both regions
  └─ Automatic failover to healthy region
```

**Conflict Resolution Strategies:**

**1. Last-Write-Wins (LWW):**

```text
Update 1: Set user.name = "John" at T=100
Update 2: Set user.name = "Jane" at T=101
Result: user.name = "Jane" (latest timestamp wins)
```

**Pros:** Simple
**Cons:** Lost updates, no causality

**2. Vector Clocks:**

```text
Update A: {A:1} Set user.name = "John"
Update B: {B:1} Set user.name = "Jane"
Conflict detected: {A:1} and {B:1} concurrent
Action: Application resolves (merge, prompt user)
```

**Pros:** Detects conflicts accurately
**Cons:** Complex, application must handle conflicts

**3. CRDTs (Conflict-free Replicated Data Types):**

```json
Counter CRDT: Increments merge by summing
  Region A: +5
  Region B: +3
  Merged: +8 (no conflict)

Set CRDT: Adds merge by union, removes require tombstones
  Region A: Add("user1"), Remove("user2")
  Region B: Add("user3")
  Merged: {"user1", "user3"} (user2 removed)
```

**Pros:** Automatic conflict resolution
**Cons:** Limited data types, complex implementation

**4. Application-Defined:**

```python
def resolve_conflict(local_value, remote_value):
    # Business logic decides winner
    if is_admin_update(remote_value):
        return remote_value  # Admin wins
    if local_value.timestamp > remote_value.timestamp:
        return local_value
    return remote_value
```

**Total RTO:** Seconds (automatic traffic shift via health checks)

**RPO:** Near-zero (bidirectional replication, potential conflicts)

**Pros:**

- Zero-downtime failover
- Optimal latency (users routed to nearest region)
- No data loss (writes to both regions)

**Cons:**

- 2x infrastructure cost
- Conflict resolution complexity
- Data consistency challenges
- More complex operations

### Read Replicas (Global Read Distribution)

**Setup:**

```text
Primary (us-east-1):
  └─ Database Primary (writes) ──────┐
                                     ├──→ Replica (eu-west-1) reads
                                     ├──→ Replica (ap-southeast-1) reads
                                     └──→ Replica (us-west-2) reads
```

**Use cases:**

- Read-heavy workloads (90%+ reads)
- Geographic distribution of reads
- Analytics queries (offload from primary)
- Reporting databases

**Replication lag:**

- Typical: 100ms - 5s
- Acceptable for: Non-critical reads, analytics
- Not acceptable for: After-write reads, strong consistency

**Handling lag:**

```python
# Option 1: Read from primary after write
def create_post(user_id, content):
    post = database.primary.insert(content)
    return post  # Read from primary

# Option 2: Read from replica with retry
def get_post(post_id):
    post = database.replica.get(post_id)
    if not post:
        # Might be replication lag, retry primary
        post = database.primary.get(post_id)
    return post

# Option 3: Include version in write, check in read
def create_post(user_id, content):
    version = get_current_version() + 1
    database.primary.insert(content, version=version)
    return version

def get_post(post_id, expected_version):
    for attempt in range(3):
        post = database.replica.get(post_id)
        if post.version >= expected_version:
            return post
        time.sleep(0.1)  # Wait for replication
    return database.primary.get(post_id)  # Fallback
```

## Backup Testing

### Why Test?

**Common failure modes:**

- Backups complete but can't restore (corrupted, missing dependencies)
- Restore time exceeds RTO
- Partial data recovery (missing transaction logs)
- Incorrect permissions (can't access backup storage)
- Changed infrastructure (backup restore assumes old config)

### Testing Schedule

**Quarterly full restore test:**

```text
1. Schedule test (non-business hours)
2. Provision clean environment
3. Restore from backup
4. Verify data integrity
5. Measure restore time
6. Document results
7. Update procedures
```

**Monthly restore validation:**

```text
1. Restore single table/collection
2. Verify row counts match production
3. Check sample data accuracy
4. Measure partial restore time
```

**Continuous backup monitoring:**

```text
1. Verify backups completing successfully
2. Check backup file sizes (detect corruption)
3. Test backup encryption
4. Validate backup retention policies
```

### Testing Checklist

- [ ] **Restore to clean environment** (not production!)
- [ ] **Measure actual restore time** vs RTO target
- [ ] **Verify data integrity:**
  - [ ] Row counts match production
  - [ ] Checksums validate
  - [ ] Foreign key constraints intact
  - [ ] Indexes rebuilt correctly
- [ ] **Test application functionality** post-restore
- [ ] **Document procedure** and actual times
- [ ] **Update runbooks** with lessons learned
- [ ] **Test cross-region restore** (not just same region)
- [ ] **Validate access controls** (correct IAM roles, credentials)

### Automated Testing

**Backup validation script:**

```bash
#!/bin/bash
# Run weekly

BACKUP_FILE="$1"
TEST_DB="restore_test_$(date +%s)"

echo "Starting restore test..."

# 1. Restore to test database
pg_restore -C -d postgres $BACKUP_FILE -D $TEST_DB
if [ $? -ne 0 ]; then
    echo "ERROR: Restore failed"
    exit 1
fi

# 2. Verify table counts
PROD_COUNT=$(psql -d production -t -c "SELECT COUNT(*) FROM users")
TEST_COUNT=$(psql -d $TEST_DB -t -c "SELECT COUNT(*) FROM users")

if [ "$PROD_COUNT" != "$TEST_COUNT" ]; then
    echo "ERROR: Row count mismatch"
    exit 1
fi

# 3. Run integrity checks
psql -d $TEST_DB -c "
    SELECT schemaname, tablename,
           pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename))
    FROM pg_tables
    WHERE schemaname = 'public';
"

# 4. Cleanup
dropdb $TEST_DB

echo "Restore test successful"
```

## Disaster Recovery Runbook

### Detection and Assessment

**1. Alert triggered:**

```text
- PagerDuty notification
- Check monitoring dashboards
- Verify scope of outage
- Determine if DR needed
```

**2. Severity assessment:**

```text
P1 (Critical): Complete region failure, initiate DR immediately
P2 (High): Partial outage, attempt recovery before DR
P3 (Medium): Degraded performance, monitor and prepare
P4 (Low): Isolated issue, no DR needed
```

### Failover Execution

**Phase 1: Preparation (5 minutes)**

```text
1. Notify team via Slack #incidents
2. Start incident bridge call
3. Assign roles:
   - Incident Commander
   - Technical Lead
   - Communications Lead
   - Scribe
4. Check standby region health
```

**Phase 2: Database Promotion (10 minutes)**

```text
1. Stop replication from primary
2. Promote replica to primary:
   aws rds promote-read-replica \
     --db-instance-identifier prod-db-replica

3. Verify replica promotion:
   - Check replication lag = 0
   - Verify writes enabled
   - Test write operation

4. Update connection strings
```

**Phase 3: Application Failover (10 minutes)**

```text
1. Scale up standby region:
   aws autoscaling set-desired-capacity \
     --auto-scaling-group-name prod-asg-west \
     --desired-capacity 10

2. Update DNS:
   aws route53 change-resource-record-sets \
     --hosted-zone-id Z123 \
     --change-batch file://failover.json

3. Monitor traffic shift:
   - Watch CloudWatch metrics
   - Check error rates
   - Verify latency acceptable
```

**Phase 4: Verification (5 minutes)**

```text
1. Run smoke tests:
   - User login
   - Create/read/update/delete operations
   - Payment processing
   - Critical workflows

2. Monitor for 15 minutes:
   - Error rates < 1%
   - Latency < 500ms p95
   - Success rate > 99%

3. Declare success or roll back
```

### Failback Procedure

When primary region recovers:

```text
1. Verify primary region stable (monitor for 1 hour)
2. Set up reverse replication (standby → primary)
3. Wait for replication to catch up
4. Schedule maintenance window
5. Drain traffic from standby
6. Promote primary back
7. Update DNS
8. Verify primary serving traffic
9. Keep standby as replica
```

## Reference Library and Tools

### Essential Reading

**Books:**

- **Site Reliability Engineering** - Google (Chapter 26: Data Integrity)
- **Database Reliability Engineering** - Charity Majors
- **The Phoenix Project** - Gene Kim (Business continuity)

**Online Resources:**

- [AWS Disaster Recovery Whitepaper](https://aws.amazon.com/disaster-recovery/)
- [Azure Business Continuity](https://learn.microsoft.com/en-us/azure/reliability/)
- [Google Cloud DR Planning](https://cloud.google.com/architecture/dr-scenarios-planning-guide)

### Tools

**Backup and Recovery:**

- **Velero:** Kubernetes backup and restore
- **pgBackRest:** PostgreSQL backup/restore
- **Percona XtraBackup:** MySQL hot backup
- **AWS Backup:** Centralized backup across AWS services

**Disaster Recovery:**

- **CloudEndure:** Continuous replication and recovery (AWS)
- **Azure Site Recovery:** DR orchestration
- **Zerto:** Cross-platform DR replication

**Testing:**

- **Chaos Engineering:** Gremlin, Chaos Monkey, Litmus
- **Game Day Exercises:** Scheduled DR drills
- **Backup Validation:** Custom scripts, monitoring

### AWS-Specific Tools

**Multi-region:**

- Route 53: DNS failover, health checks
- Global Accelerator: Anycast IP, automatic failover
- CloudFormation: Infrastructure as code, region deployment

**Database:**

- RDS Multi-AZ: Synchronous failover within region
- RDS Read Replicas: Async cross-region
- Aurora Global Database: <1s cross-region failover
- DynamoDB Global Tables: Multi-region, active-active

**Backup:**

- AWS Backup: Centralized backup management
- EBS Snapshots: Volume backups
- S3 Cross-Region Replication: Backup storage

## Best Practices

1. **Test regularly:** Quarterly full restore, monthly validation
1. **Automate failover:** Reduce RTO with automation
1. **Document everything:** Runbooks save lives during incidents
1. **Monitor replication lag:** Alert when exceeds acceptable threshold
1. **Practice game days:** Scheduled DR drills with team
1. **Separate backup storage:** Don't rely on same infrastructure
1. **Verify encryption:** Backups should be encrypted
1. **Track costs:** DR can be expensive, justify with business value
1. **Review and update:** Procedures change, keep documentation current
1. **Learn from incidents:** Post-mortem every DR event
