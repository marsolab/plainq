-- name: CountAdminUsers :one
SELECT COUNT(*)
FROM user_roles ur
         INNER JOIN roles r ON ur.role_id = r.role_id
WHERE r.role_name = 'admin';

-- name: GetAdminRoleID :one
SELECT role_id
FROM roles
WHERE role_name = 'admin';

-- name: CreateUser :exec
INSERT INTO users (
    user_id, email, password, verified, created_at, updated_at,
    org_id, auth_version, status
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: AssignUserRole :exec
INSERT INTO user_roles (user_id, role_id, created_at)
VALUES ($1, $2, $3);

-- name: UpsertHumanSecurityPrincipal :exec
INSERT INTO security_principals (
    tenant_id, principal_kind, principal_id, status, roles_json,
    auth_version, updated_at_ns
)
SELECT u.org_id,
       'human',
       u.user_id,
       u.status,
       COALESCE((
           SELECT jsonb_agg(role_name ORDER BY role_name)
           FROM (
               SELECT r.role_name AS role_name
               FROM user_roles ur
               JOIN roles r ON r.role_id = ur.role_id
               WHERE ur.user_id = u.user_id
           ) roles
       ), '[]'::jsonb),
       u.auth_version,
       $1
FROM users u
WHERE u.user_id = $2
ON CONFLICT(tenant_id, principal_kind, principal_id) DO UPDATE SET
    status = excluded.status,
    roles_json = excluded.roles_json,
    auth_version = excluded.auth_version,
    updated_at_ns = excluded.updated_at_ns;

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (
    id, aid, token_hash, created_at_ns, expires_at_ns, last_used_at_ns
)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: CreateSecurityAuditEvent :exec
INSERT INTO security_audit_events (
    audit_id, tenant_id, principal_kind, principal_id, action,
    resource_kind, resource_id, outcome, request_id, reason, source_ip,
    user_agent, metadata_json, created_at_ns
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14);
