-- name: CreateOAuthProvider :exec
INSERT INTO oauth_providers (provider_id, provider_name, org_id, config_json, is_active, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetOAuthProviderByName :one
SELECT provider_id, provider_name, org_id, config_json, is_active, created_at, updated_at
FROM oauth_providers
WHERE provider_name = ? AND (org_id = ? OR (org_id IS NULL AND ? = ''));

-- name: UpdateOAuthProvider :execrows
UPDATE oauth_providers
SET config_json = ?,
    is_active   = ?,
    updated_at  = ?
WHERE provider_id = ?;

-- name: DeleteOAuthProvider :execrows
DELETE FROM oauth_providers
WHERE provider_id = ?;

-- name: ListOAuthProvidersByOrg :many
SELECT provider_id, provider_name, org_id, config_json, is_active, created_at, updated_at
FROM oauth_providers
WHERE org_id = ?;

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
