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

-- name: GetUserIDByOAuthSub :one
SELECT user_id
FROM users
WHERE oauth_provider = ? AND oauth_sub = ?;

-- name: InsertOAuthUser :exec
INSERT INTO users (user_id, email, password, verified, org_id, oauth_provider, oauth_sub, is_oauth_user, last_sync_at, created_at, updated_at)
VALUES (?, ?, '', TRUE, ?, ?, ?, TRUE, ?, ?, ?);

-- name: UpdateOAuthUser :exec
UPDATE users
SET email        = ?,
    org_id       = ?,
    last_sync_at = ?,
    updated_at   = ?
WHERE user_id = ?;

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
        ORDER BY u2.last_sync_at DESC
        LIMIT 1)                      AS last_sync_at
FROM users u
WHERE u.is_oauth_user = TRUE
GROUP BY u.oauth_provider;
