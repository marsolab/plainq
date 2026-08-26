-- name: GetQuotaIdempotency :one
SELECT request_hash, response_json
FROM agent_idempotency
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
  AND principal_kind = 'system'
  AND principal_id = 'quota'
  AND operation = cast(sqlc.arg('operation') AS text)
  AND idempotency_key = cast(sqlc.arg('idempotency_key') AS text)
  AND expires_at_ns > cast(sqlc.arg('now_ns') AS integer);

-- name: InsertQuotaWindow :one
INSERT INTO quota_windows (tenant_id, action, window_started_at_ns, used)
SELECT
    cast(sqlc.arg('tenant_id') AS text),
    cast(sqlc.arg('action') AS text),
    cast(sqlc.arg('window_started_at_ns') AS integer),
    cast(sqlc.arg('units') AS integer)
WHERE cast(sqlc.arg('units') AS integer) <= cast(sqlc.arg('quota_limit') AS integer)
ON CONFLICT (tenant_id, action, window_started_at_ns) DO NOTHING
RETURNING used;

-- name: IncrementQuotaWindow :one
UPDATE quota_windows
SET used = used + cast(sqlc.arg('units') AS integer)
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
  AND action = cast(sqlc.arg('action') AS text)
  AND window_started_at_ns = cast(sqlc.arg('window_started_at_ns') AS integer)
  AND used <= cast(sqlc.arg('quota_limit') AS integer) - cast(sqlc.arg('units') AS integer)
RETURNING used;

-- name: InsertQuotaIdempotency :exec
INSERT INTO agent_idempotency (
    tenant_id, principal_kind, principal_id, operation, idempotency_key,
    request_hash, response_json, created_at_ns, expires_at_ns
)
VALUES (
    cast(sqlc.arg('tenant_id') AS text),
    'system',
    'quota',
    cast(sqlc.arg('operation') AS text),
    cast(sqlc.arg('idempotency_key') AS text),
    sqlc.arg('request_hash'),
    cast(sqlc.arg('response_json') AS text),
    cast(sqlc.arg('created_at_ns') AS integer),
    cast(sqlc.arg('expires_at_ns') AS integer)
);
