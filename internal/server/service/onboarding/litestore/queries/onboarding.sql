-- name: CountAdminUsers :one
SELECT COUNT(*)
FROM user_roles ur
         INNER JOIN roles r ON ur.role_id = r.role_id
WHERE r.role_name = 'admin';

-- name: GetAdminRoleID :one
SELECT role_id
FROM roles
WHERE role_name = 'admin';

-- name: CreateUser :exec
INSERT INTO users (user_id, email, password, verified, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: AssignUserRole :exec
INSERT INTO user_roles (user_id, role_id, created_at)
VALUES (?, ?, ?);
