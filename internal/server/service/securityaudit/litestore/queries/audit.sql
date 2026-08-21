-- name: InsertAuditEvent :exec
INSERT INTO security_audit_events (
    audit_id, tenant_id, principal_kind, principal_id, action,
    resource_kind, resource_id, outcome, request_id, reason,
    source_ip, user_agent, metadata_json, created_at_ns
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListAuditEvents :many
SELECT audit_id, tenant_id, principal_kind, principal_id, action,
       resource_kind, resource_id, outcome, request_id, reason,
       source_ip, user_agent, metadata_json, created_at_ns
FROM security_audit_events
WHERE tenant_id = cast(sqlc.arg('tenant_id') AS text)
  AND (cast(sqlc.arg('action') AS text) = '' OR action = cast(sqlc.arg('action') AS text))
  AND (cast(sqlc.arg('resource_kind') AS text) = '' OR resource_kind = cast(sqlc.arg('resource_kind') AS text))
  AND (cast(sqlc.arg('resource_id') AS text) = '' OR resource_id = cast(sqlc.arg('resource_id') AS text))
  AND (cast(sqlc.arg('after_time_ns') AS integer) = 0
       OR created_at_ns > cast(sqlc.arg('after_time_ns') AS integer)
       OR (created_at_ns = cast(sqlc.arg('after_time_ns') AS integer)
           AND audit_id > cast(sqlc.arg('after_id') AS text)))
ORDER BY created_at_ns, audit_id
LIMIT cast(sqlc.arg('page_limit') AS integer);
