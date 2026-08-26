-- name: CreateAccount :exec
INSERT INTO users (user_id, email, password, verified, created_at, updated_at, org_id, auth_version, status)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAccountByID :one
SELECT user_id, email, password, verified, created_at, updated_at, org_id, auth_version, status
FROM users
WHERE user_id = ?;

-- name: GetAccountByEmail :one
SELECT user_id, email, password, verified, created_at, updated_at, org_id, auth_version, status
FROM users
WHERE email = ?;

-- name: SetAccountVerified :execrows
UPDATE users
SET verified   = ?,
    updated_at = current_timestamp
WHERE email = ?;

-- name: SetAccountPassword :execrows
UPDATE users
SET password   = ?,
    updated_at = current_timestamp
WHERE user_id = ?;

-- name: DeleteAccount :execrows
DELETE FROM users
WHERE user_id = ?;

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (id, aid, token_hash, created_at_ns, expires_at_ns, last_used_at_ns)
VALUES (?, ?, ?, ?, ?, ?);

-- name: DeleteRefreshToken :execrows
DELETE FROM refresh_tokens
WHERE token_hash = ?;

-- name: DeleteRefreshTokenByTokenID :exec
DELETE FROM refresh_tokens
WHERE id = ?;

-- name: PurgeRefreshTokens :exec
DELETE FROM refresh_tokens
WHERE aid = ?;

-- name: DenyAccessToken :exec
INSERT INTO denylist (token_id, aid, expires_at_ns, created_at_ns, reason)
VALUES (?, ?, ?, ?, ?);

-- name: IsAccessTokenDenied :one
SELECT count(*)
FROM denylist
WHERE token_id = ?
  AND expires_at_ns > ?;

-- name: GetAccountSecurity :one
SELECT org_id, status, auth_version
FROM users
WHERE user_id = ?;

-- name: UpsertHumanSecurityPrincipal :exec
INSERT INTO security_principals (
    tenant_id, principal_kind, principal_id, status, roles_json, auth_version, updated_at_ns
)
SELECT u.org_id, 'human', u.user_id, u.status,
       coalesce((
           SELECT json_group_array(role_name)
           FROM (
               SELECT r.role_name AS role_name
               FROM user_roles ur
               JOIN roles r ON r.role_id = ur.role_id
               WHERE ur.user_id = u.user_id
               ORDER BY r.role_name
           )
       ), '[]'),
       u.auth_version, ?
FROM users u
WHERE u.user_id = ?
ON CONFLICT (tenant_id, principal_kind, principal_id) DO UPDATE SET
    status = excluded.status,
    roles_json = excluded.roles_json,
    auth_version = excluded.auth_version,
    updated_at_ns = excluded.updated_at_ns;

-- name: GetUserRoles :many
SELECT r.role_name
FROM roles r
         INNER JOIN user_roles ur ON r.role_id = ur.role_id
WHERE ur.user_id = ?
ORDER BY r.role_name;

-- name: ListDirectoryAccounts :many
SELECT u.user_id,
       u.email,
       u.verified,
       u.created_at,
       u.updated_at,
       coalesce(u.org_id, '') AS org_id,
       u.oauth_provider,
       u.is_oauth_user,
       u.last_sync_at,
       o.org_code,
       o.org_name
FROM users u
         LEFT JOIN organizations o ON o.org_id = u.org_id
WHERE (cast(sqlc.arg('search') AS text) = ''
    OR lower(u.email) LIKE '%' || lower(cast(sqlc.arg('search') AS text)) || '%')
  AND (cast(sqlc.arg('scope_org') AS boolean) = FALSE
    OR coalesce(u.org_id, '') = cast(sqlc.arg('org_id') AS text))
  AND (cast(sqlc.arg('cursor') AS text) = '' OR u.user_id > cast(sqlc.arg('cursor') AS text))
ORDER BY u.user_id
LIMIT cast(sqlc.arg('page_limit') AS integer);

-- name: CountDirectoryAccounts :one
SELECT count(*)
FROM users u
WHERE (cast(sqlc.arg('search') AS text) = ''
    OR lower(u.email) LIKE '%' || lower(cast(sqlc.arg('search') AS text)) || '%')
  AND (cast(sqlc.arg('scope_org') AS boolean) = FALSE
    OR coalesce(u.org_id, '') = cast(sqlc.arg('org_id') AS text));

-- name: ListRolesForAccounts :many
SELECT ur.user_id, r.role_id, r.role_name
FROM user_roles ur
         INNER JOIN roles r ON r.role_id = ur.role_id
WHERE ur.user_id IN (sqlc.slice('user_ids'))
ORDER BY ur.user_id, r.role_name;

-- name: ListTeamsForAccounts :many
SELECT ut.user_id, t.team_id, t.org_id, t.team_name, t.team_code
FROM user_teams ut
         INNER JOIN teams t ON t.team_id = ut.team_id
WHERE ut.user_id IN (sqlc.slice('user_ids'))
ORDER BY ut.user_id, t.team_name;

-- name: GetAccountOrgID :one
SELECT coalesce(org_id, '') AS org_id
FROM users
WHERE user_id = ?;
