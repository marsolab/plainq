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
  AND revoked_at_ns IS NULL;

-- name: TouchCredential :execrows
UPDATE agent_credentials
SET last_used_at_ns = cast(sqlc.arg('used_at_ns') AS integer)
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
  AND agent_id = cast(sqlc.arg('agent_id') AS text)
  AND credential_id = cast(sqlc.arg('credential_id') AS text)
  AND revoked_at_ns IS NULL
  AND expired_accounted_at_ns IS NULL
  AND (expires_at_ns IS NULL OR expires_at_ns > cast(sqlc.arg('used_at_ns') AS integer));
