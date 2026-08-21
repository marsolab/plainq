-- name: CreateOAuthProvider :exec
INSERT INTO oauth_providers (provider_id, provider_name, org_id, config_json, is_active, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetOAuthProviderByName :one
SELECT provider_id, provider_name, org_id, config_json, is_active, created_at, updated_at
FROM oauth_providers
WHERE provider_name = $1 AND (org_id = $2 OR (org_id IS NULL AND $2 = ''));

-- name: UpdateOAuthProvider :execrows
UPDATE oauth_providers
SET provider_name = $1,
    config_json   = $2,
    is_active     = $3,
    updated_at    = $4
WHERE provider_id = $5;

-- name: DeleteOAuthProvider :execrows
DELETE FROM oauth_providers
WHERE provider_id = $1;

-- name: ListOAuthProvidersByOrg :many
SELECT provider_id, provider_name, org_id, config_json, is_active, created_at, updated_at
FROM oauth_providers
WHERE coalesce(org_id, '') = @org_id::text
ORDER BY provider_name;

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
           SELECT jsonb_agg(r.role_name ORDER BY r.role_name)
           FROM user_roles ur
           JOIN roles r ON r.role_id = ur.role_id
           WHERE ur.user_id = u.user_id
       ), '[]'::jsonb),
       u.auth_version,
       $1
FROM users u
WHERE u.user_id = $2
ON CONFLICT (tenant_id, principal_kind, principal_id) DO UPDATE SET
    status = excluded.status,
    roles_json = excluded.roles_json,
    auth_version = excluded.auth_version,
    updated_at_ns = excluded.updated_at_ns;

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

-- name: GetOAuthProviderByID :one
SELECT provider_id, provider_name, org_id, config_json, is_active, created_at, updated_at
FROM oauth_providers
WHERE provider_id = $1;

-- name: ListOrganizations :many
SELECT org_id, org_code, org_name, org_domain, is_active, created_at, updated_at
FROM organizations
WHERE is_active = TRUE
ORDER BY org_name;

-- name: GetUserOrgID :one
SELECT coalesce(org_id, '')::text AS org_id
FROM users
WHERE user_id = $1;

-- name: GetUserSyncStatus :one
SELECT coalesce(oauth_provider, '')::text AS provider_name, is_oauth_user, last_sync_at
FROM users
WHERE user_id = $1;

-- name: ListProviderSyncStats :many
SELECT coalesce(u.oauth_provider, '')::text AS provider_name,
       count(*)::bigint                     AS user_count,
       (SELECT u2.last_sync_at
        FROM users u2
        WHERE u2.oauth_provider = u.oauth_provider
          AND u2.last_sync_at IS NOT NULL
          AND (NOT @scope_org::boolean OR coalesce(u2.org_id, '') = @org_id::text)
        ORDER BY u2.last_sync_at DESC
        LIMIT 1)                            AS last_sync_at
FROM users u
WHERE u.is_oauth_user = TRUE
  AND (NOT @scope_org::boolean OR coalesce(u.org_id, '') = @org_id::text)
GROUP BY u.oauth_provider;
