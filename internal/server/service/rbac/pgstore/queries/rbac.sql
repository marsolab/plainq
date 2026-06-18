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

-- name: AssignRoleToUser :exec
INSERT INTO user_roles (user_id, role_id, created_at)
VALUES ($1, $2, $3);

-- name: RemoveRoleFromUser :execrows
DELETE FROM user_roles
WHERE user_id = $1 AND role_id = $2;

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
FROM queue_permissions qp
         INNER JOIN user_roles ur ON qp.role_id = ur.role_id
WHERE ur.user_id = $1 AND qp.queue_id = $2 AND qp.can_send = TRUE;

-- name: HasQueueReceivePermission :one
SELECT COUNT(*)
FROM queue_permissions qp
         INNER JOIN user_roles ur ON qp.role_id = ur.role_id
WHERE ur.user_id = $1 AND qp.queue_id = $2 AND qp.can_receive = TRUE;

-- name: HasQueuePurgePermission :one
SELECT COUNT(*)
FROM queue_permissions qp
         INNER JOIN user_roles ur ON qp.role_id = ur.role_id
WHERE ur.user_id = $1 AND qp.queue_id = $2 AND qp.can_purge = TRUE;

-- name: HasQueueDeletePermission :one
SELECT COUNT(*)
FROM queue_permissions qp
         INNER JOIN user_roles ur ON qp.role_id = ur.role_id
WHERE ur.user_id = $1 AND qp.queue_id = $2 AND qp.can_delete = TRUE;
