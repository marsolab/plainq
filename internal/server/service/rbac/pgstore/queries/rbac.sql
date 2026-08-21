-- name: CreateRole :exec
INSERT INTO roles (role_id, role_name, created_at)
VALUES ($1, $2, $3);

-- name: GetRoleByID :one
SELECT role_id, role_name, created_at
FROM roles
WHERE role_id = $1;

-- name: GetRoleByName :one
SELECT role_id, role_name, created_at
FROM roles
WHERE role_name = $1;

-- name: GetAllRoles :many
SELECT role_id, role_name, created_at
FROM roles
ORDER BY role_name;

-- name: UpdateRole :execrows
UPDATE roles
SET role_name = $1
WHERE role_id = $2;

-- name: DeleteRole :execrows
DELETE FROM roles
WHERE role_id = $1;

-- name: AssignRoleToUser :execrows
INSERT INTO user_roles (user_id, role_id, created_at)
VALUES ($1, $2, $3)
ON CONFLICT DO NOTHING;

-- name: RemoveRoleFromUser :execrows
DELETE FROM user_roles
WHERE user_id = $1 AND role_id = $2;

-- name: UserHasRole :one
SELECT EXISTS(SELECT 1 FROM user_roles WHERE user_id = $1 AND role_id = $2);

-- name: BumpUserAuthVersion :execrows
UPDATE users
SET auth_version = auth_version + 1
WHERE user_id = $1;

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

-- name: ListUserRoles :many
SELECT r.role_id, r.role_name, r.created_at
FROM roles r
         INNER JOIN user_roles ur ON r.role_id = ur.role_id
WHERE ur.user_id = $1
ORDER BY r.role_name;

-- name: ListUsersWithRole :many
SELECT user_id
FROM user_roles
WHERE role_id = $1;

-- name: CreateQueuePermission :exec
INSERT INTO queue_permissions (queue_id, role_id, can_send, can_receive, can_purge, can_delete, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetQueuePermission :one
SELECT queue_id, role_id, can_send, can_receive, can_purge, can_delete, created_at, updated_at
FROM queue_permissions
WHERE queue_id = $1 AND role_id = $2;

-- name: ListRoleQueuePermissions :many
SELECT queue_id, role_id, can_send, can_receive, can_purge, can_delete, created_at, updated_at
FROM queue_permissions
WHERE role_id = $1;

-- name: UpdateQueuePermission :execrows
UPDATE queue_permissions
SET can_send    = $1,
    can_receive = $2,
    can_purge   = $3,
    can_delete  = $4,
    updated_at  = $5
WHERE queue_id = $6 AND role_id = $7;

-- name: DeleteQueuePermission :execrows
DELETE FROM queue_permissions
WHERE queue_id = $1 AND role_id = $2;

-- name: HasQueueSendPermission :one
SELECT COUNT(*)
FROM user_roles ur
         INNER JOIN roles r ON r.role_id = ur.role_id
         INNER JOIN users u ON u.user_id = ur.user_id
         INNER JOIN queue_properties q ON q.queue_id = sqlc.arg('queue_id') AND q.tenant_id = u.org_id
         LEFT JOIN queue_permissions qp ON qp.queue_id = q.queue_id AND qp.role_id = ur.role_id
WHERE ur.user_id = sqlc.arg('user_id') AND u.status = 'active'
  AND (r.role_name = 'admin' OR COALESCE(qp.can_send, FALSE) = TRUE);

-- name: HasQueueReceivePermission :one
SELECT COUNT(*)
FROM user_roles ur
         INNER JOIN roles r ON r.role_id = ur.role_id
         INNER JOIN users u ON u.user_id = ur.user_id
         INNER JOIN queue_properties q ON q.queue_id = sqlc.arg('queue_id') AND q.tenant_id = u.org_id
         LEFT JOIN queue_permissions qp ON qp.queue_id = q.queue_id AND qp.role_id = ur.role_id
WHERE ur.user_id = sqlc.arg('user_id') AND u.status = 'active'
  AND (r.role_name = 'admin' OR COALESCE(qp.can_receive, FALSE) = TRUE);

-- name: HasQueuePurgePermission :one
SELECT COUNT(*)
FROM user_roles ur
         INNER JOIN roles r ON r.role_id = ur.role_id
         INNER JOIN users u ON u.user_id = ur.user_id
         INNER JOIN queue_properties q ON q.queue_id = sqlc.arg('queue_id') AND q.tenant_id = u.org_id
         LEFT JOIN queue_permissions qp ON qp.queue_id = q.queue_id AND qp.role_id = ur.role_id
WHERE ur.user_id = sqlc.arg('user_id') AND u.status = 'active'
  AND (r.role_name = 'admin' OR COALESCE(qp.can_purge, FALSE) = TRUE);

-- name: HasQueueDeletePermission :one
SELECT COUNT(*)
FROM user_roles ur
         INNER JOIN roles r ON r.role_id = ur.role_id
         INNER JOIN users u ON u.user_id = ur.user_id
         INNER JOIN queue_properties q ON q.queue_id = sqlc.arg('queue_id') AND q.tenant_id = u.org_id
         LEFT JOIN queue_permissions qp ON qp.queue_id = q.queue_id AND qp.role_id = ur.role_id
WHERE ur.user_id = sqlc.arg('user_id') AND u.status = 'active'
  AND (r.role_name = 'admin' OR COALESCE(qp.can_delete, FALSE) = TRUE);

-- name: CountUsersPerRole :many
SELECT role_id, count(*)::bigint AS user_count
FROM user_roles
GROUP BY role_id;

-- name: CountUsersWithRole :one
SELECT count(*)
FROM user_roles
WHERE role_id = $1;

-- name: DeleteRoleQueuePermissions :execrows
DELETE FROM queue_permissions
WHERE role_id = $1;

-- name: RemoveRoleFromUserUnlessLastHolder :execrows
DELETE FROM user_roles
WHERE user_roles.user_id = $1
  AND user_roles.role_id = $2
  AND (SELECT count(*) FROM user_roles other WHERE other.role_id = $2) > 1;
