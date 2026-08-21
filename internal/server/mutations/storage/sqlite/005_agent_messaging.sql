CREATE TABLE agents (
  agent_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  agent_name TEXT NOT NULL,
  status INTEGER NOT NULL CHECK (status IN (1, 2)),
  auth_version INTEGER NOT NULL DEFAULT 1,
  inbox_scan_cursor INTEGER NOT NULL DEFAULT 0,
  inbox_claim_version INTEGER NOT NULL DEFAULT 0,
  created_by_kind TEXT NOT NULL,
  created_by_id TEXT NOT NULL,
  created_at_ns INTEGER NOT NULL,
  updated_at_ns INTEGER NOT NULL,
  disabled_at_ns INTEGER,
  UNIQUE (tenant_id, agent_name),
  UNIQUE (tenant_id, agent_id),
  FOREIGN KEY (tenant_id) REFERENCES organizations (org_id)
);
CREATE INDEX agents_tenant_name_idx ON agents (tenant_id, agent_name, agent_id);

CREATE TABLE security_principals (
  tenant_id TEXT NOT NULL,
  principal_kind TEXT NOT NULL CHECK (principal_kind IN ('human', 'agent')),
  principal_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
  roles_json TEXT NOT NULL,
  auth_version INTEGER NOT NULL,
  updated_at_ns INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, principal_kind, principal_id)
);

CREATE TABLE agent_credentials (
  credential_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  credential_name TEXT NOT NULL,
  credential_prefix TEXT NOT NULL UNIQUE,
  secret_hash BLOB NOT NULL CHECK (length(secret_hash) = 32),
  created_at_ns INTEGER NOT NULL,
  expires_at_ns INTEGER,
  expired_accounted_at_ns INTEGER,
  revoked_at_ns INTEGER,
  last_used_at_ns INTEGER,
  FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, agent_id) ON DELETE CASCADE,
  UNIQUE (agent_id, credential_name)
);
CREATE INDEX agent_credentials_revoked_sweep_idx ON agent_credentials (revoked_at_ns, credential_id);
CREATE INDEX agent_credentials_expiry_sweep_idx ON agent_credentials (expires_at_ns, credential_id);

CREATE TABLE agent_resource_grants (
  grant_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  subject_kind TEXT NOT NULL CHECK (subject_kind IN ('human', 'agent')),
  subject_id TEXT NOT NULL,
  resource_kind TEXT NOT NULL CHECK (resource_kind IN ('tenant', 'agent', 'queue', 'topic', 'subscription')),
  resource_id TEXT NOT NULL,
  action TEXT NOT NULL,
  created_at_ns INTEGER NOT NULL,
  UNIQUE (tenant_id, subject_kind, subject_id, resource_kind, resource_id, action)
);

CREATE TABLE agent_idempotency (
  tenant_id TEXT NOT NULL,
  principal_kind TEXT NOT NULL CHECK (principal_kind IN ('human', 'agent', 'system')),
  principal_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
  response_json TEXT NOT NULL,
  created_at_ns INTEGER NOT NULL,
  expires_at_ns INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, principal_kind, principal_id, operation, idempotency_key)
);
CREATE INDEX agent_idempotency_expiry_idx ON agent_idempotency (expires_at_ns);

CREATE TABLE direct_messages (
  message_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  sender_principal_kind TEXT NOT NULL CHECK (sender_principal_kind IN ('human', 'agent')),
  sender_principal_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  content_type TEXT NOT NULL,
  attributes_json TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  causation_id TEXT NOT NULL,
  conversation_id TEXT NOT NULL,
  reply_to_agent_id TEXT NOT NULL,
  body BLOB NOT NULL,
  stored_bytes INTEGER NOT NULL CHECK (stored_bytes >= 0),
  created_at_ns INTEGER NOT NULL,
  deadline_at_ns INTEGER,
  UNIQUE (tenant_id, message_id),
  FOREIGN KEY (tenant_id, sender_principal_kind, sender_principal_id)
    REFERENCES security_principals (tenant_id, principal_kind, principal_id)
);

CREATE TABLE direct_deliveries (
  delivery_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  recipient_agent_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('available', 'leased', 'acked', 'dead_lettered')),
  delivery_attempt INTEGER NOT NULL DEFAULT 0,
  lease_generation INTEGER NOT NULL DEFAULT 0,
  lease_started_at_ns INTEGER,
  lease_expires_at_ns INTEGER,
  receipt_hash BLOB CHECK (receipt_hash IS NULL OR length(receipt_hash) = 32),
  available_at_ns INTEGER NOT NULL,
  acked_at_ns INTEGER,
  last_error TEXT NOT NULL DEFAULT '',
  UNIQUE (tenant_id, recipient_agent_id, delivery_id),
  FOREIGN KEY (tenant_id, message_id) REFERENCES direct_messages (tenant_id, message_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, recipient_agent_id) REFERENCES agents (tenant_id, agent_id)
);
CREATE INDEX direct_deliveries_claim_idx ON direct_deliveries
  (tenant_id, recipient_agent_id, state, available_at_ns, delivery_id);
CREATE INDEX direct_deliveries_live_lease_idx ON direct_deliveries
  (tenant_id, recipient_agent_id, state, lease_expires_at_ns, delivery_id);

CREATE TABLE agent_dead_letters (
  dead_letter_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  recipient_agent_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  original_delivery_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  delivery_attempt INTEGER NOT NULL,
  dead_lettered_at_ns INTEGER NOT NULL,
  replayed_at_ns INTEGER,
  UNIQUE (tenant_id, original_delivery_id),
  FOREIGN KEY (tenant_id, message_id) REFERENCES direct_messages (tenant_id, message_id),
  FOREIGN KEY (tenant_id, recipient_agent_id) REFERENCES agents (tenant_id, agent_id),
  FOREIGN KEY (tenant_id, recipient_agent_id, original_delivery_id)
    REFERENCES direct_deliveries (tenant_id, recipient_agent_id, delivery_id) ON DELETE CASCADE
);
CREATE INDEX agent_dead_letters_sweep_idx ON agent_dead_letters (dead_lettered_at_ns, dead_letter_id);
CREATE INDEX agent_dead_letters_recipient_idx ON agent_dead_letters (tenant_id, recipient_agent_id, dead_lettered_at_ns, dead_letter_id);

CREATE TABLE security_audit_events (
  audit_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  principal_kind TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_kind TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  outcome TEXT NOT NULL,
  request_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  user_agent TEXT NOT NULL,
  metadata_json TEXT NOT NULL,
  created_at_ns INTEGER NOT NULL
);
CREATE INDEX security_audit_tenant_time_idx ON security_audit_events (tenant_id, created_at_ns, audit_id);
CREATE INDEX security_audit_sweep_idx ON security_audit_events (created_at_ns, audit_id);

CREATE TABLE cluster_feature_state (
  feature_name TEXT PRIMARY KEY,
  state TEXT NOT NULL CHECK (state IN ('preparing', 'active')),
  activation_id TEXT NOT NULL UNIQUE,
  source_digest BLOB NOT NULL CHECK (length(source_digest) = 32),
  source_record_count INTEGER NOT NULL CHECK (source_record_count >= 0),
  source_byte_count INTEGER NOT NULL CHECK (source_byte_count >= 0),
  staging_receipts_digest BLOB NOT NULL CHECK (length(staging_receipts_digest) = 32),
  staging_receipts_bytes BLOB NOT NULL,
  coordinator_id TEXT NOT NULL,
  last_imported_ordinal INTEGER NOT NULL DEFAULT -1 CHECK (last_imported_ordinal >= -1),
  last_imported_kind TEXT NOT NULL DEFAULT '',
  last_imported_key TEXT NOT NULL DEFAULT '',
  updated_log_index INTEGER NOT NULL CHECK (updated_log_index >= 0),
  updated_at_ns INTEGER NOT NULL
);

CREATE TABLE cluster_activation_import_records (
  activation_id TEXT NOT NULL,
  record_ordinal INTEGER NOT NULL CHECK (record_ordinal >= 0),
  record_kind TEXT NOT NULL,
  record_key TEXT NOT NULL,
  record_hash BLOB NOT NULL CHECK (length(record_hash) = 32),
  record_bytes BLOB NOT NULL,
  PRIMARY KEY (activation_id, record_ordinal),
  UNIQUE (activation_id, record_kind, record_key)
);
CREATE INDEX cluster_activation_import_key_idx ON cluster_activation_import_records
  (activation_id, record_kind, record_key);
