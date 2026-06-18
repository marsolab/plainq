-- name: InsertQueueProperties :exec
INSERT INTO queue_properties (queue_id,
                              queue_name,
                              retention_period_seconds,
                              visibility_timeout_seconds,
                              max_receive_attempts,
                              drop_policy,
                              dead_letter_queue_id)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: DeleteQueueProperties :execrows
DELETE FROM queue_properties
WHERE queue_id = $1;

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
       dead_letter_queue_id
FROM queue_properties
WHERE queue_id = $1;

-- name: GetQueuePropertiesByName :one
SELECT queue_id,
       queue_name,
       created_at,
       gc_at,
       retention_period_seconds,
       visibility_timeout_seconds,
       max_receive_attempts,
       drop_policy,
       dead_letter_queue_id
FROM queue_properties
WHERE queue_name = $1;

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
