-- name: CreateAgent :exec
INSERT INTO agents (
    agent_id, tenant_id, agent_name, status, auth_version,
    created_by_kind, created_by_id, created_at_ns, updated_at_ns
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: CreateAgentPrincipal :exec
INSERT INTO security_principals (
    tenant_id, principal_kind, principal_id, status, roles_json,
    auth_version, updated_at_ns
)
VALUES (?, 'agent', ?, 'active', '["agent"]', ?, ?);

-- name: GetAgentPrincipal :one
SELECT tenant_id, principal_id, status, auth_version
FROM security_principals
WHERE tenant_id = ? AND principal_kind = 'agent' AND principal_id = ?;

-- name: GetAgent :one
SELECT agent_id, tenant_id, agent_name, status, auth_version,
       created_at_ns, updated_at_ns, disabled_at_ns
FROM agents
WHERE tenant_id = ? AND agent_id = ?;

-- name: GetAgentByName :one
SELECT agent_id, tenant_id, agent_name, status, auth_version,
       created_at_ns, updated_at_ns, disabled_at_ns
FROM agents
WHERE tenant_id = ? AND agent_name = ?;

-- name: HasResourceGrant :one
SELECT EXISTS (
    SELECT 1
    FROM agent_resource_grants
    WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
      AND subject_kind = cast(sqlc.arg('subject_kind') AS text)
      AND subject_id = cast(sqlc.arg('subject_id') AS text)
      AND resource_kind = cast(sqlc.arg('resource_kind') AS text)
      AND resource_id = cast(sqlc.arg('resource_id') AS text)
      AND action = cast(sqlc.arg('action') AS text)
);

-- name: ListAgents :many
SELECT agent_id, tenant_id, agent_name, status, auth_version,
       created_at_ns, updated_at_ns, disabled_at_ns
FROM agents
WHERE tenant_id = sqlc.arg('tenant_id')
  AND (cast(sqlc.arg('name_prefix') AS text) = ''
       OR substr(agent_name, 1, length(cast(sqlc.arg('name_prefix') AS text))) = cast(sqlc.arg('name_prefix') AS text))
  AND (cast(sqlc.arg('after_name') AS text) = ''
       OR agent_name > cast(sqlc.arg('after_name') AS text)
       OR (agent_name = cast(sqlc.arg('after_name') AS text)
           AND agent_id > cast(sqlc.arg('after_id') AS text)))
ORDER BY agent_name, agent_id
LIMIT cast(sqlc.arg('page_limit') AS integer);

-- name: CountAgents :one
SELECT count(*)
FROM agents
WHERE tenant_id = sqlc.arg('tenant_id')
  AND (cast(sqlc.arg('name_prefix') AS text) = ''
       OR substr(agent_name, 1, length(cast(sqlc.arg('name_prefix') AS text))) = cast(sqlc.arg('name_prefix') AS text));

-- name: UpdateAgentStatus :execrows
UPDATE agents
SET status = cast(sqlc.arg('status') AS integer),
    updated_at_ns = cast(sqlc.arg('updated_at_ns') AS integer),
    disabled_at_ns = CASE
        WHEN cast(sqlc.arg('status') AS integer) = 2 THEN cast(sqlc.arg('updated_at_ns') AS integer)
        ELSE NULL
    END
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
  AND agent_id = cast(sqlc.arg('agent_id') AS text);

-- name: UpdateAgentPrincipalStatus :execrows
UPDATE security_principals
SET status = CASE WHEN cast(sqlc.arg('status') AS integer) = 1 THEN 'active' ELSE 'disabled' END,
    updated_at_ns = cast(sqlc.arg('updated_at_ns') AS integer)
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
  AND principal_kind = 'agent'
  AND principal_id = cast(sqlc.arg('agent_id') AS text);

-- name: CreateCredential :exec
INSERT INTO agent_credentials (
    credential_id, tenant_id, agent_id, credential_name, credential_prefix,
    secret_hash, created_at_ns, expires_at_ns
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetCredentialByID :one
SELECT credential_id, tenant_id, agent_id, credential_name, credential_prefix,
       secret_hash, created_at_ns, expires_at_ns, expired_accounted_at_ns,
       revoked_at_ns, last_used_at_ns
FROM agent_credentials
WHERE credential_id = ?;

-- name: GetCredentialByPrefix :one
SELECT credential_id, tenant_id, agent_id, credential_name, credential_prefix,
       secret_hash, created_at_ns, expires_at_ns, expired_accounted_at_ns,
       revoked_at_ns, last_used_at_ns
FROM agent_credentials
WHERE credential_prefix = ?;

-- name: ListCredentials :many
SELECT credential_id, tenant_id, agent_id, credential_name, credential_prefix,
       secret_hash, created_at_ns, expires_at_ns, expired_accounted_at_ns,
       revoked_at_ns, last_used_at_ns
FROM agent_credentials
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
  AND agent_id = cast(sqlc.arg('agent_id') AS text)
  AND (cast(sqlc.arg('after_id') AS text) = ''
       OR credential_id > cast(sqlc.arg('after_id') AS text))
ORDER BY credential_id
LIMIT cast(sqlc.arg('page_limit') AS integer);

-- name: CountActiveCredentials :one
SELECT count(*)
FROM agent_credentials
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
  AND agent_id = cast(sqlc.arg('agent_id') AS text)
  AND revoked_at_ns IS NULL
  AND expired_accounted_at_ns IS NULL
  AND (expires_at_ns IS NULL OR expires_at_ns > cast(sqlc.arg('now_ns') AS integer));

-- name: RevokeCredential :execrows
UPDATE agent_credentials
SET revoked_at_ns = cast(sqlc.arg('revoked_at_ns') AS integer)
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
  AND agent_id = cast(sqlc.arg('agent_id') AS text)
  AND credential_id = cast(sqlc.arg('credential_id') AS text)
  AND revoked_at_ns IS NULL
  AND expired_accounted_at_ns IS NULL;

-- name: TouchCredential :execrows
UPDATE agent_credentials
SET last_used_at_ns = cast(sqlc.arg('used_at_ns') AS integer)
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
  AND agent_id = cast(sqlc.arg('agent_id') AS text)
  AND credential_id = cast(sqlc.arg('credential_id') AS text)
  AND revoked_at_ns IS NULL
  AND expired_accounted_at_ns IS NULL
  AND (expires_at_ns IS NULL OR expires_at_ns > cast(sqlc.arg('used_at_ns') AS integer));

-- name: GetPolicyIdempotency :one
SELECT request_hash, response_json
FROM agent_idempotency
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
  AND principal_kind = cast(sqlc.arg('principal_kind') AS text)
  AND principal_id = cast(sqlc.arg('principal_id') AS text)
  AND operation = cast(sqlc.arg('operation') AS text)
  AND idempotency_key = cast(sqlc.arg('idempotency_key') AS text)
  AND expires_at_ns > cast(sqlc.arg('now_ns') AS integer);

-- name: InsertPolicyIdempotency :exec
INSERT INTO agent_idempotency (
    tenant_id, principal_kind, principal_id, operation, idempotency_key,
    request_hash, response_json, created_at_ns, expires_at_ns
)
VALUES (
    cast(sqlc.arg('tenant_id') AS text),
    cast(sqlc.arg('principal_kind') AS text),
    cast(sqlc.arg('principal_id') AS text),
    cast(sqlc.arg('operation') AS text),
    cast(sqlc.arg('idempotency_key') AS text),
    sqlc.arg('request_hash'),
    cast(sqlc.arg('response_json') AS text),
    cast(sqlc.arg('created_at_ns') AS integer),
    cast(sqlc.arg('expires_at_ns') AS integer)
);

-- name: GetMutationRateLimit :one
SELECT cast(CASE
    WHEN cast(sqlc.arg('action') AS text) = 'topic.publish' THEN publish_per_second
    ELSE send_per_second
END AS integer)
FROM tenant_quotas
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text);

-- name: InsertMutationQuotaWindow :one
INSERT INTO quota_windows (tenant_id, action, window_started_at_ns, used)
SELECT
    cast(sqlc.arg('tenant_id') AS text),
    cast(sqlc.arg('action') AS text),
    cast(sqlc.arg('window_started_at_ns') AS integer),
    cast(sqlc.arg('units') AS integer)
WHERE cast(sqlc.arg('units') AS integer) <= cast(sqlc.arg('quota_limit') AS integer)
ON CONFLICT (tenant_id, action, window_started_at_ns) DO NOTHING
RETURNING used;

-- name: IncrementMutationQuotaWindow :one
UPDATE quota_windows
SET used = used + cast(sqlc.arg('units') AS integer)
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
  AND action = cast(sqlc.arg('action') AS text)
  AND window_started_at_ns = cast(sqlc.arg('window_started_at_ns') AS integer)
  AND used <= cast(sqlc.arg('quota_limit') AS integer) - cast(sqlc.arg('units') AS integer)
RETURNING used;

-- name: GetTenantAgentCapacity :one
SELECT u.agent_count, q.max_agents
FROM tenant_resource_usage u
JOIN tenant_quotas q ON q.tenant_id = u.tenant_id
WHERE u.tenant_id = ?;

-- name: IncrementTenantAgentUsage :execrows
UPDATE tenant_resource_usage
SET agent_count = agent_count + 1,
    updated_at_ns = cast(sqlc.arg('updated_at_ns') AS integer)
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text);

-- name: CreateAgentResourceUsage :exec
INSERT INTO agent_resource_usage (
    tenant_id, agent_id, pending_direct_count, pending_direct_bytes,
    subscription_count, active_credential_count, updated_at_ns
)
VALUES (?, ?, 0, 0, 0, 0, ?);

-- name: GetAgentCredentialCapacity :one
SELECT u.active_credential_count, q.max_credentials_per_agent
FROM agent_resource_usage u
JOIN tenant_quotas q ON q.tenant_id = u.tenant_id
WHERE u.tenant_id = cast(sqlc.arg('tenant_id') AS text)
  AND u.agent_id = cast(sqlc.arg('agent_id') AS text);

-- name: AccountExpiredCredentials :many
UPDATE agent_credentials
SET expired_accounted_at_ns = cast(sqlc.arg('accounted_at_ns') AS integer)
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
  AND agent_id = cast(sqlc.arg('agent_id') AS text)
  AND revoked_at_ns IS NULL
  AND expired_accounted_at_ns IS NULL
  AND expires_at_ns IS NOT NULL
  AND expires_at_ns <= cast(sqlc.arg('accounted_at_ns') AS integer)
RETURNING credential_id;

-- name: RemoveExpiredCredentialUsage :execrows
UPDATE agent_resource_usage
SET active_credential_count = active_credential_count - cast(sqlc.arg('removed') AS integer),
    updated_at_ns = cast(sqlc.arg('updated_at_ns') AS integer)
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
  AND agent_id = cast(sqlc.arg('agent_id') AS text)
  AND active_credential_count >= cast(sqlc.arg('removed') AS integer);

-- name: IncrementActiveCredentialUsage :execrows
UPDATE agent_resource_usage
SET active_credential_count = active_credential_count + 1,
    updated_at_ns = cast(sqlc.arg('updated_at_ns') AS integer)
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
  AND agent_id = cast(sqlc.arg('agent_id') AS text)
  AND active_credential_count < cast(sqlc.arg('credential_limit') AS integer);

-- name: DecrementActiveCredentialUsage :execrows
UPDATE agent_resource_usage
SET active_credential_count = active_credential_count - 1,
    updated_at_ns = cast(sqlc.arg('updated_at_ns') AS integer)
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
  AND agent_id = cast(sqlc.arg('agent_id') AS text)
  AND active_credential_count > 0;

-- name: InsertAgentAuditEvent :exec
INSERT INTO security_audit_events (
    audit_id, tenant_id, principal_kind, principal_id, action,
    resource_kind, resource_id, outcome, request_id, reason,
    source_ip, user_agent, metadata_json, created_at_ns
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: PolicySubjectExists :one
SELECT EXISTS (
    SELECT 1 FROM security_principals
    WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
      AND principal_kind = cast(sqlc.arg('subject_kind') AS text)
      AND principal_id = cast(sqlc.arg('subject_id') AS text)
      AND status = 'active'
);

-- name: PolicyResourceExists :one
SELECT CASE cast(sqlc.arg('resource_kind') AS text)
    WHEN 'tenant' THEN EXISTS (
        SELECT 1 FROM organizations
        WHERE org_id = cast(sqlc.arg('tenant_id') AS text)
          AND org_id = cast(sqlc.arg('resource_id') AS text)
          AND is_active = TRUE
    )
    WHEN 'agent' THEN EXISTS (
        SELECT 1 FROM agents
        WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
          AND agent_id = cast(sqlc.arg('resource_id') AS text)
    )
    WHEN 'queue' THEN EXISTS (
        SELECT 1 FROM queue_properties
        WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
          AND queue_id = cast(sqlc.arg('resource_id') AS text)
    )
    WHEN 'topic' THEN EXISTS (
        SELECT 1 FROM topic_properties
        WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
          AND topic_id = cast(sqlc.arg('resource_id') AS text)
    )
    WHEN 'subscription' THEN EXISTS (
        SELECT 1
        FROM topic_subscriptions s
        JOIN topic_properties t ON t.topic_id = s.topic_id
        WHERE t.tenant_id = cast(sqlc.arg('tenant_id') AS text)
          AND s.subscription_id = cast(sqlc.arg('resource_id') AS text)
    )
    ELSE FALSE
END;

-- name: InsertResourceGrant :exec
INSERT INTO agent_resource_grants (
    grant_id, tenant_id, subject_kind, subject_id,
    resource_kind, resource_id, action, created_at_ns
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetResourceGrant :one
SELECT grant_id, tenant_id, subject_kind, subject_id,
       resource_kind, resource_id, action, created_at_ns
FROM agent_resource_grants
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
  AND grant_id = cast(sqlc.arg('grant_id') AS text);

-- name: ListResourceGrants :many
SELECT grant_id, tenant_id, subject_kind, subject_id,
       resource_kind, resource_id, action, created_at_ns
FROM agent_resource_grants
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
  AND (cast(sqlc.arg('subject_kind') AS text) = '' OR subject_kind = cast(sqlc.arg('subject_kind') AS text))
  AND (cast(sqlc.arg('subject_id') AS text) = '' OR subject_id = cast(sqlc.arg('subject_id') AS text))
  AND (cast(sqlc.arg('resource_kind') AS text) = '' OR resource_kind = cast(sqlc.arg('resource_kind') AS text))
  AND (cast(sqlc.arg('resource_id') AS text) = '' OR resource_id = cast(sqlc.arg('resource_id') AS text))
  AND (cast(sqlc.arg('after_id') AS text) = '' OR grant_id > cast(sqlc.arg('after_id') AS text))
ORDER BY grant_id
LIMIT cast(sqlc.arg('page_limit') AS integer);

-- name: DeleteResourceGrant :execrows
DELETE FROM agent_resource_grants
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
  AND grant_id = cast(sqlc.arg('grant_id') AS text);

-- name: HasPolicyGrant :one
SELECT EXISTS (
    SELECT 1
    FROM agent_resource_grants g
    JOIN security_principals p
      ON p.tenant_id = g.tenant_id
     AND p.principal_kind = g.subject_kind
     AND p.principal_id = g.subject_id
     AND p.status = 'active'
    WHERE g.tenant_id = cast(sqlc.arg('tenant_id') AS text)
      AND g.subject_kind = cast(sqlc.arg('subject_kind') AS text)
      AND g.subject_id = cast(sqlc.arg('subject_id') AS text)
      AND g.resource_kind = cast(sqlc.arg('resource_kind') AS text)
      AND g.resource_id = cast(sqlc.arg('resource_id') AS text)
      AND g.action = cast(sqlc.arg('action') AS text)
);

-- name: HasLegacyPolicyPermission :one
WITH effective_roles AS (
    SELECT ur.role_id
    FROM user_roles ur
    WHERE ur.user_id = cast(sqlc.arg('subject_id') AS text)
    UNION
    SELECT tr.role_id
    FROM user_teams ut
    JOIN teams t ON t.team_id = ut.team_id
    JOIN team_roles tr ON tr.team_id = t.team_id
    WHERE ut.user_id = cast(sqlc.arg('subject_id') AS text)
      AND t.org_id = cast(sqlc.arg('tenant_id') AS text)
      AND t.is_active = TRUE
)
SELECT EXISTS (
    SELECT 1
    FROM users u
    JOIN organizations o ON o.org_id = u.org_id AND o.is_active = TRUE
    JOIN effective_roles er
    JOIN roles r ON r.role_id = er.role_id
    LEFT JOIN queue_properties q
      ON q.queue_id = cast(sqlc.arg('resource_id') AS text)
     AND q.tenant_id = u.org_id
    LEFT JOIN queue_permissions qp ON qp.queue_id = q.queue_id AND qp.role_id = r.role_id
    WHERE u.user_id = cast(sqlc.arg('subject_id') AS text)
      AND u.org_id = cast(sqlc.arg('tenant_id') AS text)
      AND u.status = 'active'
      AND (
        r.role_name = 'admin'
        OR (
          cast(sqlc.arg('resource_kind') AS text) = 'queue'
          AND q.queue_id IS NOT NULL
          AND CASE cast(sqlc.arg('action') AS text)
            WHEN 'queue.send' THEN coalesce(qp.can_send, FALSE)
            WHEN 'queue.receive' THEN coalesce(qp.can_receive, FALSE)
            WHEN 'queue.read' THEN coalesce(qp.can_receive, FALSE)
            WHEN 'queue.ack' THEN coalesce(qp.can_delete, FALSE)
            WHEN 'queue.purge' THEN coalesce(qp.can_purge, FALSE)
            WHEN 'queue.delete' THEN coalesce(qp.can_delete, FALSE)
            ELSE FALSE
          END
        )
      )
);
