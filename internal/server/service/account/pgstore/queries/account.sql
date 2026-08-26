-- name: CreateAccount :exec
INSERT INTO users (user_id, email, password, verified, created_at, updated_at, org_id, auth_version, status)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetAccountByID :one
SELECT user_id, email, password, verified, created_at, updated_at, org_id, auth_version, status
FROM users
WHERE user_id = $1;

-- name: GetAccountByEmail :one
SELECT user_id, email, password, verified, created_at, updated_at, org_id, auth_version, status
FROM users
WHERE email = $1;

-- name: SetAccountVerified :execrows
UPDATE users
SET verified   = $1,
    updated_at = now()
WHERE email = $2;

-- name: SetAccountPassword :execrows
UPDATE users
SET password   = $1,
    updated_at = now()
WHERE user_id = $2;

-- name: DeleteAccount :execrows
DELETE FROM users
WHERE user_id = $1;

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (id, aid, token_hash, created_at_ns, expires_at_ns, last_used_at_ns)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: DeleteRefreshToken :execrows
DELETE FROM refresh_tokens
WHERE token_hash = $1;

-- name: DeleteRefreshTokenByTokenID :exec
DELETE FROM refresh_tokens
WHERE id = $1;

-- name: PurgeRefreshTokens :exec
DELETE FROM refresh_tokens
WHERE aid = $1;

-- name: DenyAccessToken :exec
INSERT INTO denylist (token_id, aid, expires_at_ns, created_at_ns, reason)
VALUES ($1, $2, $3, $4, $5);

-- name: IsAccessTokenDenied :one
SELECT count(*)
FROM denylist
WHERE token_id = $1
  AND expires_at_ns > $2;

-- name: GetAccountSecurity :one
SELECT org_id, status, auth_version
FROM users
WHERE user_id = $1;

-- name: UpsertHumanSecurityPrincipal :exec
INSERT INTO security_principals (
    tenant_id, principal_kind, principal_id, status, roles_json, auth_version, updated_at_ns
)
SELECT u.org_id, 'human', u.user_id, u.status,
       coalesce((
           SELECT jsonb_agg(r.role_name ORDER BY r.role_name)
           FROM user_roles ur
           JOIN roles r ON r.role_id = ur.role_id
           WHERE ur.user_id = u.user_id
       ), '[]'::jsonb),
       u.auth_version, $1
FROM users u
WHERE u.user_id = $2
ON CONFLICT (tenant_id, principal_kind, principal_id) DO UPDATE SET
    status = excluded.status,
    roles_json = excluded.roles_json,
    auth_version = excluded.auth_version,
    updated_at_ns = excluded.updated_at_ns;

-- name: GetUserRoles :many
SELECT r.role_name
FROM roles r
         INNER JOIN user_roles ur ON r.role_id = ur.role_id
WHERE ur.user_id = $1
ORDER BY r.role_name;

-- name: ListDirectoryAccounts :many
SELECT u.user_id,
       u.email,
       u.verified,
       u.created_at,
       u.updated_at,
       coalesce(u.org_id, '')::text AS org_id,
       u.oauth_provider,
       u.is_oauth_user,
       u.last_sync_at,
       o.org_code,
       o.org_name
FROM users u
         LEFT JOIN organizations o ON o.org_id = u.org_id
WHERE (@search::text = '' OR lower(u.email) LIKE '%' || lower(@search::text) || '%')
  AND (NOT @scope_org::boolean OR coalesce(u.org_id, '') = @org_id::text)
  AND (@cursor::text = '' OR u.user_id > @cursor::text)
ORDER BY u.user_id
LIMIT @page_limit::bigint;

-- name: CountDirectoryAccounts :one
SELECT count(*)
FROM users u
WHERE (@search::text = '' OR lower(u.email) LIKE '%' || lower(@search::text) || '%')
  AND (NOT @scope_org::boolean OR coalesce(u.org_id, '') = @org_id::text);

-- name: ListRolesForAccounts :many
SELECT ur.user_id, r.role_id, r.role_name
FROM user_roles ur
         INNER JOIN roles r ON r.role_id = ur.role_id
WHERE ur.user_id = ANY (@user_ids::text[])
ORDER BY ur.user_id, r.role_name;

-- name: ListTeamsForAccounts :many
SELECT ut.user_id, t.team_id, t.org_id, t.team_name, t.team_code
FROM user_teams ut
         INNER JOIN teams t ON t.team_id = ut.team_id
WHERE ut.user_id = ANY (@user_ids::text[])
ORDER BY ut.user_id, t.team_name;

-- name: GetAccountOrgID :one
SELECT coalesce(org_id, '')::text AS org_id
FROM users
WHERE user_id = $1;
