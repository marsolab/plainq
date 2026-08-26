-- name: InsertQueueProperties :exec
INSERT INTO queue_properties (queue_id,
                              queue_name,
                              retention_period_seconds,
                              visibility_timeout_seconds,
                              max_receive_attempts,
                              drop_policy,
                              dead_letter_queue_id,
                              tenant_id,
                              created_by_kind,
                              created_by_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: DeleteQueueProperties :execrows
DELETE FROM queue_properties
WHERE queue_id = sqlc.arg('queue_id')
  AND tenant_id = sqlc.arg('tenant_id')
  AND (NOT sqlc.arg('legacy_compat')::boolean
    OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1')));

-- name: CountQueueProperties :one
SELECT COUNT(*)
FROM queue_properties;

-- name: GetQueuePropertiesByID :one
SELECT queue_id,
       queue_name,
       created_at,
       gc_at,
       retention_period_seconds,
       visibility_timeout_seconds,
       max_receive_attempts,
       drop_policy,
       dead_letter_queue_id,
       tenant_id,
       created_by_kind,
       created_by_id
FROM queue_properties
WHERE queue_id = sqlc.arg('queue_id')
  AND tenant_id = sqlc.arg('tenant_id')
  AND (NOT sqlc.arg('legacy_compat')::boolean
    OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1')));

-- name: GetQueuePropertiesByName :one
SELECT queue_id,
       queue_name,
       created_at,
       gc_at,
       retention_period_seconds,
       visibility_timeout_seconds,
       max_receive_attempts,
       drop_policy,
       dead_letter_queue_id,
       tenant_id,
       created_by_kind,
       created_by_id
FROM queue_properties
WHERE queue_name = sqlc.arg('queue_name')
  AND tenant_id = sqlc.arg('tenant_id')
  AND (NOT sqlc.arg('legacy_compat')::boolean
    OR (created_by_kind = 'system' AND created_by_id IN ('migration', 'legacy-v1')));

-- name: UpdateQueuePropertiesGCAt :execrows
UPDATE queue_properties
SET gc_at = now()
WHERE queue_id = $1;

-- name: SelectQueuesForGC :many
SELECT queue_id
FROM queue_properties
WHERE gc_at < $1
ORDER BY gc_at
LIMIT $2 OFFSET $3;
