-- name: CreateRole :exec
INSERT INTO roles (role_id, role_name, created_at)
VALUES (?, ?, ?);

-- name: GetRoleByID :one
SELECT role_id, role_name, created_at
FROM roles
WHERE role_id = ?;

-- name: GetRoleByName :one
SELECT role_id, role_name, created_at
FROM roles
WHERE role_name = ?;

-- name: GetAllRoles :many
SELECT role_id, role_name, created_at
FROM roles
ORDER BY role_name;

-- name: UpdateRole :execrows
UPDATE roles
SET role_name = ?
WHERE role_id = ?;

-- name: DeleteRole :execrows
DELETE FROM roles
WHERE role_id = ?;

-- name: AssignRoleToUser :exec
INSERT INTO user_roles (user_id, role_id, created_at)
VALUES (?, ?, ?);

-- name: RemoveRoleFromUser :execrows
DELETE FROM user_roles
WHERE user_id = ? AND role_id = ?;

-- name: ListUserRoles :many
SELECT r.role_id, r.role_name, r.created_at
FROM roles r
         INNER JOIN user_roles ur ON r.role_id = ur.role_id
WHERE ur.user_id = ?
ORDER BY r.role_name;

-- name: ListUsersWithRole :many
SELECT user_id
FROM user_roles
WHERE role_id = ?;

-- name: CreateQueuePermission :exec
INSERT INTO queue_permissions (queue_id, role_id, can_send, can_receive, can_purge, can_delete, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetQueuePermission :one
SELECT queue_id, role_id, can_send, can_receive, can_purge, can_delete, created_at, updated_at
FROM queue_permissions
WHERE queue_id = ? AND role_id = ?;

-- name: ListRoleQueuePermissions :many
SELECT queue_id, role_id, can_send, can_receive, can_purge, can_delete, created_at, updated_at
FROM queue_permissions
WHERE role_id = ?;

-- name: UpdateQueuePermission :execrows
UPDATE queue_permissions
SET can_send    = ?,
    can_receive = ?,
    can_purge   = ?,
    can_delete  = ?,
    updated_at  = ?
WHERE queue_id = ? AND role_id = ?;

-- name: DeleteQueuePermission :execrows
DELETE FROM queue_permissions
WHERE queue_id = ? AND role_id = ?;

-- name: HasQueueSendPermission :one
SELECT COUNT(*)
FROM queue_permissions qp
         INNER JOIN user_roles ur ON qp.role_id = ur.role_id
WHERE ur.user_id = ? AND qp.queue_id = ? AND qp.can_send = TRUE;

-- name: HasQueueReceivePermission :one
SELECT COUNT(*)
FROM queue_permissions qp
         INNER JOIN user_roles ur ON qp.role_id = ur.role_id
WHERE ur.user_id = ? AND qp.queue_id = ? AND qp.can_receive = TRUE;

-- name: HasQueuePurgePermission :one
SELECT COUNT(*)
FROM queue_permissions qp
         INNER JOIN user_roles ur ON qp.role_id = ur.role_id
WHERE ur.user_id = ? AND qp.queue_id = ? AND qp.can_purge = TRUE;

-- name: HasQueueDeletePermission :one
SELECT COUNT(*)
FROM queue_permissions qp
         INNER JOIN user_roles ur ON qp.role_id = ur.role_id
WHERE ur.user_id = ? AND qp.queue_id = ? AND qp.can_delete = TRUE;
