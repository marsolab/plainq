-- name: GetQuotaIdempotency :one
SELECT request_hash, response_json
FROM agent_idempotency
WHERE tenant_id = sqlc.arg('tenant_id')::text
  AND principal_kind = 'system'
  AND principal_id = 'quota'
  AND operation = sqlc.arg('operation')::text
  AND idempotency_key = sqlc.arg('idempotency_key')::text
  AND expires_at_ns > sqlc.arg('now_ns')::bigint;

-- name: InsertQuotaWindow :one
INSERT INTO quota_windows (tenant_id, action, window_started_at_ns, used)
SELECT
    sqlc.arg('tenant_id')::text,
    sqlc.arg('action')::text,
    sqlc.arg('window_started_at_ns')::bigint,
    sqlc.arg('units')::bigint
WHERE sqlc.arg('units')::bigint <= sqlc.arg('quota_limit')::bigint
ON CONFLICT (tenant_id, action, window_started_at_ns) DO NOTHING
RETURNING used;

-- name: IncrementQuotaWindow :one
UPDATE quota_windows
SET used = used + sqlc.arg('units')::bigint
WHERE tenant_id = sqlc.arg('tenant_id')::text
  AND action = sqlc.arg('action')::text
  AND window_started_at_ns = sqlc.arg('window_started_at_ns')::bigint
  AND used <= sqlc.arg('quota_limit')::bigint - sqlc.arg('units')::bigint
RETURNING used;

-- name: InsertQuotaIdempotency :exec
INSERT INTO agent_idempotency (
    tenant_id, principal_kind, principal_id, operation, idempotency_key,
    request_hash, response_json, created_at_ns, expires_at_ns
)
VALUES (
    sqlc.arg('tenant_id')::text,
    'system',
    'quota',
    sqlc.arg('operation')::text,
    sqlc.arg('idempotency_key')::text,
    sqlc.arg('request_hash')::bytea,
    sqlc.arg('response_json')::jsonb,
    sqlc.arg('created_at_ns')::bigint,
    sqlc.arg('expires_at_ns')::bigint
);
