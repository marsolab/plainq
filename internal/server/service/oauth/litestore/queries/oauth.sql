-- name: CreateOAuthProvider :exec
INSERT INTO oauth_providers (provider_id, provider_name, org_id, config_json, is_active, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetOAuthProviderByName :one
SELECT provider_id, provider_name, org_id, config_json, is_active, created_at, updated_at
FROM oauth_providers
WHERE provider_name = ? AND (org_id = ? OR (org_id IS NULL AND ? = ''));

-- name: UpdateOAuthProvider :execrows
UPDATE oauth_providers
SET provider_name = ?,
    config_json   = ?,
    is_active     = ?,
    updated_at    = ?
WHERE provider_id = ?;

-- name: DeleteOAuthProvider :execrows
DELETE FROM oauth_providers
WHERE provider_id = ?;

-- name: ListOAuthProvidersByOrg :many
SELECT provider_id, provider_name, org_id, config_json, is_active, created_at, updated_at
FROM oauth_providers
WHERE coalesce(org_id, '') = cast(sqlc.arg('org_id') AS text)
ORDER BY provider_name;

-- name: GetUserByOAuthSub :one
SELECT user_id, email, org_id, oauth_provider, oauth_sub, is_oauth_user, last_sync_at, created_at, updated_at
FROM users
WHERE oauth_provider = ? AND oauth_sub = ?;

-- name: GetOAuthUserIdentity :one
SELECT user_id, org_id
FROM users
WHERE oauth_provider = ? AND oauth_sub = ?;

-- name: InsertOAuthUser :exec
INSERT INTO users (user_id, email, password, verified, org_id, oauth_provider, oauth_sub, is_oauth_user, last_sync_at, created_at, updated_at)
VALUES (?, ?, '', TRUE, ?, ?, ?, TRUE, ?, ?, ?);

-- name: UpdateOAuthUser :exec
UPDATE users
SET email        = sqlc.arg('email'),
    auth_version = auth_version + CASE
        WHEN org_id <> CAST(sqlc.arg('org_id') AS text) THEN 1
        ELSE 0
    END,
    org_id       = sqlc.arg('org_id'),
    last_sync_at = sqlc.arg('last_sync_at'),
    updated_at   = sqlc.arg('updated_at')
WHERE user_id = sqlc.arg('user_id');

-- name: DeleteHumanSecurityPrincipal :exec
DELETE FROM security_principals
WHERE tenant_id = sqlc.arg('tenant_id')
  AND principal_kind = 'human'
  AND principal_id = sqlc.arg('principal_id');

-- name: UpsertHumanSecurityPrincipal :exec
INSERT INTO security_principals (
    tenant_id, principal_kind, principal_id, status, roles_json,
    auth_version, updated_at_ns
)
SELECT u.org_id,
       'human',
       u.user_id,
       u.status,
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
       u.auth_version,
       ?
FROM users u
WHERE u.user_id = ?
ON CONFLICT (tenant_id, principal_kind, principal_id) DO UPDATE SET
    status = excluded.status,
    roles_json = excluded.roles_json,
    auth_version = excluded.auth_version,
    updated_at_ns = excluded.updated_at_ns;

-- name: UpdateUserLastSync :exec
UPDATE users
SET last_sync_at = ?,
    updated_at   = ?
WHERE user_id = ?;

-- name: GetOrganizationByCode :one
SELECT org_id, org_code, org_name, org_domain, is_active, created_at, updated_at
FROM organizations
WHERE org_code = ? AND is_active = TRUE;

-- name: GetOrganizationByDomain :one
SELECT org_id, org_code, org_name, org_domain, is_active, created_at, updated_at
FROM organizations
WHERE org_domain = ? AND is_active = TRUE;

-- name: ListTeamsByOrg :many
SELECT team_id, org_id, team_name, team_code, description, is_active, created_at, updated_at
FROM teams
WHERE org_id = ? AND is_active = TRUE;

-- name: GetTeamByCode :one
SELECT team_id, org_id, team_name, team_code, description, is_active, created_at, updated_at
FROM teams
WHERE org_id = ? AND team_code = ?;

-- name: AssignUserToTeam :exec
INSERT INTO user_teams (user_id, team_id, created_at)
VALUES (?, ?, ?)
ON CONFLICT DO NOTHING;

-- name: RemoveUserFromTeam :exec
DELETE FROM user_teams
WHERE user_id = ? AND team_id = ?;

-- name: ListUserTeams :many
SELECT t.team_id, t.org_id, t.team_name, t.team_code, t.description, t.is_active, t.created_at, t.updated_at
FROM teams t
         INNER JOIN user_teams ut ON t.team_id = ut.team_id
WHERE ut.user_id = ?;

-- name: GetOAuthProviderByID :one
SELECT provider_id, provider_name, org_id, config_json, is_active, created_at, updated_at
FROM oauth_providers
WHERE provider_id = ?;

-- name: ListOrganizations :many
SELECT org_id, org_code, org_name, org_domain, is_active, created_at, updated_at
FROM organizations
WHERE is_active = TRUE
ORDER BY org_name;

-- name: GetUserOrgID :one
SELECT coalesce(org_id, '') AS org_id
FROM users
WHERE user_id = ?;

-- name: GetUserSyncStatus :one
SELECT coalesce(oauth_provider, '') AS provider_name, is_oauth_user, last_sync_at
FROM users
WHERE user_id = ?;

-- name: ListProviderSyncStats :many
SELECT coalesce(u.oauth_provider, '') AS provider_name,
       count(*)                       AS user_count,
       (SELECT u2.last_sync_at
        FROM users u2
        WHERE u2.oauth_provider = u.oauth_provider
          AND u2.last_sync_at IS NOT NULL
          AND (cast(sqlc.arg('scope_org') AS boolean) = FALSE
            OR coalesce(u2.org_id, '') = cast(sqlc.arg('org_id') AS text))
        ORDER BY u2.last_sync_at DESC
        LIMIT 1)                      AS last_sync_at
FROM users u
WHERE u.is_oauth_user = TRUE
  AND (cast(sqlc.arg('scope_org') AS boolean) = FALSE
    OR coalesce(u.org_id, '') = cast(sqlc.arg('org_id') AS text))
GROUP BY u.oauth_provider;
