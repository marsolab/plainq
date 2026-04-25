-- name: CreateAccount :exec
INSERT INTO users (user_id, email, password, verified, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetAccountByID :one
SELECT user_id, email, password, verified, created_at, updated_at
FROM users
WHERE user_id = ?;

-- name: GetAccountByEmail :one
SELECT user_id, email, password, verified, created_at, updated_at
FROM users
WHERE email = ?;

-- name: SetAccountVerified :execrows
UPDATE users
SET verified   = ?,
    updated_at = current_timestamp
WHERE email = ?;

-- name: SetAccountPassword :execrows
UPDATE users
SET password   = ?,
    updated_at = current_timestamp
WHERE user_id = ?;

-- name: DeleteAccount :execrows
DELETE FROM users
WHERE user_id = ?;

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (id, aid, token, created_at, expires_at)
VALUES (?, ?, ?, ?, ?);

-- name: DeleteRefreshToken :exec
DELETE FROM refresh_tokens
WHERE token = ?;

-- name: DeleteRefreshTokenByTokenID :exec
DELETE FROM refresh_tokens
WHERE id = ?;

-- name: PurgeRefreshTokens :exec
DELETE FROM refresh_tokens
WHERE aid = ?;

-- name: DenyAccessToken :exec
INSERT INTO denylist (token, denied_until)
VALUES (?, ?);

-- name: GetUserRoles :many
SELECT r.role_name
FROM roles r
         INNER JOIN user_roles ur ON r.role_id = ur.role_id
WHERE ur.user_id = ?
ORDER BY r.role_name;
