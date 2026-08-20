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
  AND revoked_at_ns IS NULL;

-- name: TouchCredential :execrows
UPDATE agent_credentials
SET last_used_at_ns = @used_at_ns::bigint
WHERE tenant_id = @tenant_id::text
  AND agent_id = @agent_id::text
  AND credential_id = @credential_id::text
  AND revoked_at_ns IS NULL
  AND expired_accounted_at_ns IS NULL
  AND (expires_at_ns IS NULL OR expires_at_ns > @used_at_ns::bigint);
