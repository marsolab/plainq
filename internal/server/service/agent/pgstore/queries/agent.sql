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
