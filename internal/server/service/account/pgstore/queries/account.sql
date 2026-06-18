-- name: CreateAccount :exec
INSERT INTO users (user_id, email, password, verified, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetAccountByID :one
SELECT user_id, email, password, verified, created_at, updated_at
FROM users
WHERE user_id = $1;

-- name: GetAccountByEmail :one
SELECT user_id, email, password, verified, created_at, updated_at
FROM users
WHERE email = $1;

-- name: SetAccountVerified :execrows
UPDATE users
SET verified   = $1,
    updated_at = now()
WHERE email = $2;

-- name: SetAccountPassword :execrows
UPDATE users
SET password   = $1,
    updated_at = now()
WHERE user_id = $2;

-- name: DeleteAccount :execrows
DELETE FROM users
WHERE user_id = $1;

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (id, aid, token, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- name: DeleteRefreshToken :exec
DELETE FROM refresh_tokens
WHERE token = $1;

-- name: DeleteRefreshTokenByTokenID :exec
DELETE FROM refresh_tokens
WHERE id = $1;

-- name: PurgeRefreshTokens :exec
DELETE FROM refresh_tokens
WHERE aid = $1;

-- name: DenyAccessToken :exec
INSERT INTO denylist (token, denied_until)
VALUES ($1, $2);

-- name: GetUserRoles :many
SELECT r.role_name
FROM roles r
         INNER JOIN user_roles ur ON r.role_id = ur.role_id
WHERE ur.user_id = $1
ORDER BY r.role_name;
