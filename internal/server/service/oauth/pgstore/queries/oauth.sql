-- name: CreateOAuthProvider :exec
INSERT INTO oauth_providers (provider_id, provider_name, org_id, config_json, is_active, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetOAuthProviderByName :one
SELECT provider_id, provider_name, org_id, config_json, is_active, created_at, updated_at
FROM oauth_providers
WHERE provider_name = $1 AND (org_id = $2 OR (org_id IS NULL AND $2 = ''));

-- name: UpdateOAuthProvider :execrows
UPDATE oauth_providers
SET config_json = $1,
    is_active   = $2,
    updated_at  = $3
WHERE provider_id = $4;

-- name: DeleteOAuthProvider :execrows
DELETE FROM oauth_providers
WHERE provider_id = $1;

-- name: ListOAuthProvidersByOrg :many
SELECT provider_id, provider_name, org_id, config_json, is_active, created_at, updated_at
FROM oauth_providers
WHERE org_id = $1;

-- name: GetUserByOAuthSub :one
SELECT user_id, email, org_id, oauth_provider, oauth_sub, is_oauth_user, last_sync_at, created_at, updated_at
FROM users
WHERE oauth_provider = $1 AND oauth_sub = $2;

-- name: GetUserIDByOAuthSub :one
SELECT user_id
FROM users
WHERE oauth_provider = $1 AND oauth_sub = $2;

-- name: InsertOAuthUser :exec
INSERT INTO users (user_id, email, password, verified, org_id, oauth_provider, oauth_sub, is_oauth_user, last_sync_at, created_at, updated_at)
VALUES ($1, $2, '', TRUE, $3, $4, $5, TRUE, $6, $7, $8);

-- name: UpdateOAuthUser :exec
UPDATE users
SET email        = $1,
    org_id       = $2,
    last_sync_at = $3,
    updated_at   = $4
WHERE user_id = $5;

-- name: UpdateUserLastSync :exec
UPDATE users
SET last_sync_at = $1,
    updated_at   = $2
WHERE user_id = $3;

-- name: GetOrganizationByCode :one
SELECT org_id, org_code, org_name, org_domain, is_active, created_at, updated_at
FROM organizations
WHERE org_code = $1 AND is_active = TRUE;

-- name: GetOrganizationByDomain :one
SELECT org_id, org_code, org_name, org_domain, is_active, created_at, updated_at
FROM organizations
WHERE org_domain = $1 AND is_active = TRUE;

-- name: ListTeamsByOrg :many
SELECT team_id, org_id, team_name, team_code, description, is_active, created_at, updated_at
FROM teams
WHERE org_id = $1 AND is_active = TRUE;

-- name: GetTeamByCode :one
SELECT team_id, org_id, team_name, team_code, description, is_active, created_at, updated_at
FROM teams
WHERE org_id = $1 AND team_code = $2;

-- name: AssignUserToTeam :exec
INSERT INTO user_teams (user_id, team_id, created_at)
VALUES ($1, $2, $3)
ON CONFLICT DO NOTHING;

-- name: RemoveUserFromTeam :exec
DELETE FROM user_teams
WHERE user_id = $1 AND team_id = $2;

-- name: ListUserTeams :many
SELECT t.team_id, t.org_id, t.team_name, t.team_code, t.description, t.is_active, t.created_at, t.updated_at
FROM teams t
         INNER JOIN user_teams ut ON t.team_id = ut.team_id
WHERE ut.user_id = $1;
