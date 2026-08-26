-- name: CreateAgent :exec
INSERT INTO agents (
    agent_id, tenant_id, agent_name, status, auth_version,
    created_by_kind, created_by_id, created_at_ns, updated_at_ns
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: CreateAgentPrincipal :exec
INSERT INTO security_principals (
    tenant_id, principal_kind, principal_id, status, roles_json,
    auth_version, updated_at_ns
)
VALUES ($1, 'agent', $2, 'active', '["agent"]'::jsonb, $3, $4);

-- name: GetAgentPrincipal :one
SELECT tenant_id, principal_id, status, auth_version
FROM security_principals
WHERE tenant_id = $1 AND principal_kind = 'agent' AND principal_id = $2;

-- name: GetAgent :one
SELECT agent_id, tenant_id, agent_name, status, auth_version,
       created_at_ns, updated_at_ns, disabled_at_ns
FROM agents
WHERE tenant_id = $1 AND agent_id = $2;

-- name: GetAgentByName :one
SELECT agent_id, tenant_id, agent_name, status, auth_version,
       created_at_ns, updated_at_ns, disabled_at_ns
FROM agents
WHERE tenant_id = $1 AND agent_name = $2;

-- name: HasResourceGrant :one
SELECT EXISTS (
    SELECT 1
    FROM agent_resource_grants
    WHERE tenant_id = @tenant_id::text
      AND subject_kind = @subject_kind::text
      AND subject_id = @subject_id::text
      AND resource_kind = @resource_kind::text
      AND resource_id = @resource_id::text
      AND action = @action::text
);

-- name: ListAgents :many
SELECT agent_id, tenant_id, agent_name, status, auth_version,
       created_at_ns, updated_at_ns, disabled_at_ns
FROM agents
WHERE tenant_id = @tenant_id::text
  AND (@name_prefix::text = '' OR left(agent_name, char_length(@name_prefix::text)) = @name_prefix::text)
  AND (@after_name::text = ''
       OR agent_name > @after_name::text
       OR (agent_name = @after_name::text AND agent_id > @after_id::text))
ORDER BY agent_name, agent_id
LIMIT @page_limit::bigint;

-- name: CountAgents :one
SELECT count(*)
FROM agents
WHERE tenant_id = @tenant_id::text
  AND (@name_prefix::text = '' OR left(agent_name, char_length(@name_prefix::text)) = @name_prefix::text);

-- name: UpdateAgentStatus :execrows
UPDATE agents
SET status = @status::smallint,
    updated_at_ns = @updated_at_ns::bigint,
    disabled_at_ns = CASE WHEN @status::smallint = 2 THEN @updated_at_ns::bigint ELSE NULL END
WHERE tenant_id = @tenant_id::text AND agent_id = @agent_id::text;

-- name: UpdateAgentPrincipalStatus :execrows
UPDATE security_principals
SET status = CASE WHEN @status::smallint = 1 THEN 'active' ELSE 'disabled' END,
    updated_at_ns = @updated_at_ns::bigint
WHERE tenant_id = @tenant_id::text
  AND principal_kind = 'agent'
  AND principal_id = @agent_id::text;

-- name: CreateCredential :exec
INSERT INTO agent_credentials (
    credential_id, tenant_id, agent_id, credential_name, credential_prefix,
    secret_hash, created_at_ns, expires_at_ns
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetCredentialByID :one
SELECT credential_id, tenant_id, agent_id, credential_name, credential_prefix,
       secret_hash, created_at_ns, expires_at_ns, expired_accounted_at_ns,
       revoked_at_ns, last_used_at_ns
FROM agent_credentials
WHERE credential_id = $1;

-- name: GetCredentialByPrefix :one
SELECT credential_id, tenant_id, agent_id, credential_name, credential_prefix,
       secret_hash, created_at_ns, expires_at_ns, expired_accounted_at_ns,
       revoked_at_ns, last_used_at_ns
FROM agent_credentials
WHERE credential_prefix = $1;

-- name: ListCredentials :many
SELECT credential_id, tenant_id, agent_id, credential_name, credential_prefix,
       secret_hash, created_at_ns, expires_at_ns, expired_accounted_at_ns,
       revoked_at_ns, last_used_at_ns
FROM agent_credentials
WHERE tenant_id = @tenant_id::text
  AND agent_id = @agent_id::text
  AND (@after_id::text = '' OR credential_id > @after_id::text)
ORDER BY credential_id
LIMIT @page_limit::bigint;

-- name: CountActiveCredentials :one
SELECT count(*)
FROM agent_credentials
WHERE tenant_id = @tenant_id::text
  AND agent_id = @agent_id::text
  AND revoked_at_ns IS NULL
  AND expired_accounted_at_ns IS NULL
  AND (expires_at_ns IS NULL OR expires_at_ns > @now_ns::bigint);

-- name: RevokeCredential :execrows
UPDATE agent_credentials
SET revoked_at_ns = @revoked_at_ns::bigint
WHERE tenant_id = @tenant_id::text
  AND agent_id = @agent_id::text
  AND credential_id = @credential_id::text
  AND revoked_at_ns IS NULL
  AND expired_accounted_at_ns IS NULL;

-- name: TouchCredential :execrows
UPDATE agent_credentials
SET last_used_at_ns = @used_at_ns::bigint
WHERE tenant_id = @tenant_id::text
  AND agent_id = @agent_id::text
  AND credential_id = @credential_id::text
  AND revoked_at_ns IS NULL
  AND expired_accounted_at_ns IS NULL
  AND (expires_at_ns IS NULL OR expires_at_ns > @used_at_ns::bigint);

-- name: GetPolicyIdempotency :one
SELECT request_hash, response_json
FROM agent_idempotency
WHERE tenant_id = @tenant_id::text
  AND principal_kind = @principal_kind::text
  AND principal_id = @principal_id::text
  AND operation = @operation::text
  AND idempotency_key = @idempotency_key::text
  AND expires_at_ns > @now_ns::bigint;

-- name: InsertPolicyIdempotency :exec
INSERT INTO agent_idempotency (
    tenant_id, principal_kind, principal_id, operation, idempotency_key,
    request_hash, response_json, created_at_ns, expires_at_ns
)
VALUES (
    @tenant_id::text, @principal_kind::text, @principal_id::text,
    @operation::text, @idempotency_key::text, @request_hash::bytea,
    @response_json::jsonb, @created_at_ns::bigint, @expires_at_ns::bigint
);

-- name: GetMutationRateLimit :one
SELECT (CASE WHEN sqlc.arg('action')::text = 'topic.publish' THEN publish_per_second ELSE send_per_second END)::bigint
FROM tenant_quotas
WHERE tenant_id = sqlc.arg('tenant_id')::text;

-- name: InsertMutationQuotaWindow :one
INSERT INTO quota_windows (tenant_id, action, window_started_at_ns, used)
SELECT sqlc.arg('tenant_id')::text, sqlc.arg('action')::text,
       sqlc.arg('window_started_at_ns')::bigint, sqlc.arg('units')::bigint
WHERE sqlc.arg('units')::bigint <= sqlc.arg('quota_limit')::bigint
ON CONFLICT (tenant_id, action, window_started_at_ns) DO NOTHING
RETURNING used;

-- name: IncrementMutationQuotaWindow :one
UPDATE quota_windows
SET used = used + sqlc.arg('units')::bigint
WHERE tenant_id = sqlc.arg('tenant_id')::text
  AND action = sqlc.arg('action')::text
  AND window_started_at_ns = sqlc.arg('window_started_at_ns')::bigint
  AND used <= sqlc.arg('quota_limit')::bigint - sqlc.arg('units')::bigint
RETURNING used;

-- name: GetTenantAgentCapacity :one
SELECT u.agent_count, q.max_agents
FROM tenant_resource_usage u
JOIN tenant_quotas q ON q.tenant_id = u.tenant_id
WHERE u.tenant_id = $1
FOR UPDATE OF u;

-- name: IncrementTenantAgentUsage :execrows
UPDATE tenant_resource_usage
SET agent_count = agent_count + 1, updated_at_ns = @updated_at_ns::bigint
WHERE tenant_id = @tenant_id::text;

-- name: CreateAgentResourceUsage :exec
INSERT INTO agent_resource_usage (
    tenant_id, agent_id, pending_direct_count, pending_direct_bytes,
    subscription_count, active_credential_count, updated_at_ns
)
VALUES ($1, $2, 0, 0, 0, 0, $3);

-- name: GetAgentCredentialCapacity :one
SELECT u.active_credential_count, q.max_credentials_per_agent
FROM agent_resource_usage u
JOIN tenant_quotas q ON q.tenant_id = u.tenant_id
WHERE u.tenant_id = @tenant_id::text AND u.agent_id = @agent_id::text
FOR UPDATE OF u;

-- name: AccountExpiredCredentials :many
UPDATE agent_credentials
SET expired_accounted_at_ns = @accounted_at_ns::bigint
WHERE tenant_id = @tenant_id::text
  AND agent_id = @agent_id::text
  AND revoked_at_ns IS NULL
  AND expired_accounted_at_ns IS NULL
  AND expires_at_ns IS NOT NULL
  AND expires_at_ns <= @accounted_at_ns::bigint
RETURNING credential_id;

-- name: RemoveExpiredCredentialUsage :execrows
UPDATE agent_resource_usage
SET active_credential_count = active_credential_count - @removed::bigint,
    updated_at_ns = @updated_at_ns::bigint
WHERE tenant_id = @tenant_id::text
  AND agent_id = @agent_id::text
  AND active_credential_count >= @removed::bigint;

-- name: IncrementActiveCredentialUsage :execrows
UPDATE agent_resource_usage
SET active_credential_count = active_credential_count + 1,
    updated_at_ns = @updated_at_ns::bigint
WHERE tenant_id = @tenant_id::text
  AND agent_id = @agent_id::text
  AND active_credential_count < @credential_limit::bigint;

-- name: DecrementActiveCredentialUsage :execrows
UPDATE agent_resource_usage
SET active_credential_count = active_credential_count - 1,
    updated_at_ns = @updated_at_ns::bigint
WHERE tenant_id = @tenant_id::text AND agent_id = @agent_id::text
  AND active_credential_count > 0;

-- name: InsertAgentAuditEvent :exec
INSERT INTO security_audit_events (
    audit_id, tenant_id, principal_kind, principal_id, action,
    resource_kind, resource_id, outcome, request_id, reason,
    source_ip, user_agent, metadata_json, created_at_ns
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14);

-- name: PolicySubjectExists :one
SELECT EXISTS (
    SELECT 1 FROM security_principals
    WHERE tenant_id = @tenant_id::text
      AND principal_kind = @subject_kind::text
      AND principal_id = @subject_id::text
      AND status = 'active'
);

-- name: PolicyResourceExists :one
SELECT CASE @resource_kind::text
    WHEN 'tenant' THEN EXISTS (
        SELECT 1 FROM organizations
        WHERE org_id = @tenant_id::text AND org_id = @resource_id::text AND is_active = TRUE
    )
    WHEN 'agent' THEN EXISTS (
        SELECT 1 FROM agents WHERE tenant_id = @tenant_id::text AND agent_id = @resource_id::text
    )
    WHEN 'queue' THEN EXISTS (
        SELECT 1 FROM queue_properties WHERE tenant_id = @tenant_id::text AND queue_id = @resource_id::text
    )
    WHEN 'topic' THEN EXISTS (
        SELECT 1 FROM topic_properties WHERE tenant_id = @tenant_id::text AND topic_id = @resource_id::text
    )
    WHEN 'subscription' THEN EXISTS (
        SELECT 1 FROM topic_subscriptions s
        JOIN topic_properties t ON t.topic_id = s.topic_id
        WHERE t.tenant_id = @tenant_id::text AND s.subscription_id = @resource_id::text
    )
    ELSE FALSE
END;

-- name: InsertResourceGrant :exec
INSERT INTO agent_resource_grants (
    grant_id, tenant_id, subject_kind, subject_id,
    resource_kind, resource_id, action, created_at_ns
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetResourceGrant :one
SELECT grant_id, tenant_id, subject_kind, subject_id,
       resource_kind, resource_id, action, created_at_ns
FROM agent_resource_grants
WHERE tenant_id = @tenant_id::text AND grant_id = @grant_id::text;

-- name: ListResourceGrants :many
SELECT grant_id, tenant_id, subject_kind, subject_id,
       resource_kind, resource_id, action, created_at_ns
FROM agent_resource_grants
WHERE tenant_id = @tenant_id::text
  AND (@subject_kind::text = '' OR subject_kind = @subject_kind::text)
  AND (@subject_id::text = '' OR subject_id = @subject_id::text)
  AND (@resource_kind::text = '' OR resource_kind = @resource_kind::text)
  AND (@resource_id::text = '' OR resource_id = @resource_id::text)
  AND (@after_id::text = '' OR grant_id > @after_id::text)
ORDER BY grant_id
LIMIT @page_limit::bigint;

-- name: DeleteResourceGrant :execrows
DELETE FROM agent_resource_grants
WHERE tenant_id = @tenant_id::text AND grant_id = @grant_id::text;

-- name: HasPolicyGrant :one
SELECT EXISTS (
    SELECT 1
    FROM agent_resource_grants g
    JOIN security_principals p
      ON p.tenant_id = g.tenant_id
     AND p.principal_kind = g.subject_kind
     AND p.principal_id = g.subject_id
     AND p.status = 'active'
    WHERE g.tenant_id = @tenant_id::text
      AND g.subject_kind = @subject_kind::text
      AND g.subject_id = @subject_id::text
      AND g.resource_kind = @resource_kind::text
      AND g.resource_id = @resource_id::text
      AND g.action = @action::text
);

-- name: HasLegacyPolicyPermission :one
WITH effective_roles AS (
    SELECT ur.role_id FROM user_roles ur WHERE ur.user_id = @subject_id::text
    UNION
    SELECT tr.role_id
    FROM user_teams ut
    JOIN teams t ON t.team_id = ut.team_id
    JOIN team_roles tr ON tr.team_id = t.team_id
    WHERE ut.user_id = @subject_id::text AND t.org_id = @tenant_id::text AND t.is_active = TRUE
)
SELECT EXISTS (
    SELECT 1
    FROM users u
    JOIN organizations o ON o.org_id = u.org_id AND o.is_active = TRUE
    JOIN effective_roles er ON TRUE
    JOIN roles r ON r.role_id = er.role_id
    LEFT JOIN queue_properties q ON q.queue_id = @resource_id::text AND q.tenant_id = u.org_id
    LEFT JOIN queue_permissions qp ON qp.queue_id = q.queue_id AND qp.role_id = r.role_id
    WHERE u.user_id = @subject_id::text
      AND u.org_id = @tenant_id::text
      AND u.status = 'active'
      AND (
        r.role_name = 'admin'
        OR (
          @resource_kind::text = 'queue' AND q.queue_id IS NOT NULL
          AND CASE @action::text
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
