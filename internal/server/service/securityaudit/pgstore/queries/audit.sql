-- name: InsertAuditEvent :exec
INSERT INTO security_audit_events (
    audit_id, tenant_id, principal_kind, principal_id, action,
    resource_kind, resource_id, outcome, request_id, reason,
    source_ip, user_agent, metadata_json, created_at_ns
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14);

-- name: ListAuditEvents :many
SELECT audit_id, tenant_id, principal_kind, principal_id, action,
       resource_kind, resource_id, outcome, request_id, reason,
       source_ip, user_agent, metadata_json, created_at_ns
FROM security_audit_events
WHERE tenant_id = @tenant_id::text
  AND (@action::text = '' OR action = @action::text)
  AND (@resource_kind::text = '' OR resource_kind = @resource_kind::text)
  AND (@resource_id::text = '' OR resource_id = @resource_id::text)
  AND (@after_time_ns::bigint = 0
       OR created_at_ns > @after_time_ns::bigint
       OR (created_at_ns = @after_time_ns::bigint AND audit_id > @after_id::text))
ORDER BY created_at_ns, audit_id
LIMIT @page_limit::bigint;
