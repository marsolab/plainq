-- sqlc-only schema for PostgreSQL type inference. Do NOT run this at runtime —
-- canonical migrations live in internal/server/mutations/storage/postgres/ and
-- are applied via pgevolver. This file captures the runtime schema in a form
-- sqlc's parser can consume (no seed data, no dialect ALTER sequences).

CREATE TABLE users
(
    user_id        varchar(26)               NOT NULL,
    email          text                      NOT NULL,
    password       text                      NOT NULL,
    verified       boolean     DEFAULT FALSE NOT NULL,
    created_at     timestamptz DEFAULT now() NOT NULL,
    updated_at     timestamptz DEFAULT now() NOT NULL,
    org_id         varchar(26)               NOT NULL,
    oauth_provider text,
    oauth_sub      text,
    last_sync_at   timestamptz,
    is_oauth_user  boolean     DEFAULT FALSE NOT NULL,
    auth_version   bigint      DEFAULT 1     NOT NULL,
    status         text        DEFAULT 'active' NOT NULL,
    CONSTRAINT users_pk PRIMARY KEY (user_id),
    FOREIGN KEY (org_id) REFERENCES organizations (org_id)
);

CREATE TABLE refresh_tokens
(
    id              varchar(26) NOT NULL,
    aid             varchar(26) NOT NULL,
    token_hash      bytea       NOT NULL,
    created_at_ns   bigint      NOT NULL,
    expires_at_ns   bigint      NOT NULL,
    last_used_at_ns bigint      NOT NULL,
    CONSTRAINT refresh_tokens_pk PRIMARY KEY (id),
    FOREIGN KEY (aid) REFERENCES users (user_id) ON DELETE CASCADE
);

CREATE TABLE denylist
(
    token_id      text   NOT NULL,
    aid           text   NOT NULL,
    expires_at_ns bigint NOT NULL,
    created_at_ns bigint NOT NULL,
    reason        text   NOT NULL,
    CONSTRAINT denylist_pk PRIMARY KEY (token_id),
    FOREIGN KEY (aid) REFERENCES users (user_id) ON DELETE CASCADE
);

CREATE TABLE roles
(
    role_id    varchar(26)               NOT NULL,
    role_name  text                      NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT roles_pk PRIMARY KEY (role_id)
);

CREATE TABLE user_roles
(
    user_id    varchar(26)               NOT NULL,
    role_id    varchar(26)               NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT user_roles_pk PRIMARY KEY (user_id, role_id)
);

CREATE TABLE queue_properties
(
    queue_id                   varchar(26)               NOT NULL,
    queue_name                 text                      NOT NULL,
    created_at                 timestamptz DEFAULT now() NOT NULL,
    gc_at                      timestamptz DEFAULT now() NOT NULL,
    retention_period_seconds   integer                   NOT NULL,
    visibility_timeout_seconds integer                   NOT NULL,
    max_receive_attempts       integer                   NOT NULL,
    drop_policy                integer     DEFAULT 0     NOT NULL,
    dead_letter_queue_id       varchar(26),
    tenant_id                  text        NOT NULL,
    created_by_kind            text        NOT NULL,
    created_by_id              text        NOT NULL,
    CONSTRAINT queue_properties_pk PRIMARY KEY (queue_id)
);

CREATE TABLE queue_permissions
(
    queue_id    varchar(26)               NOT NULL,
    role_id     varchar(26)               NOT NULL,
    can_send    boolean     DEFAULT FALSE NOT NULL,
    can_receive boolean     DEFAULT FALSE NOT NULL,
    can_purge   boolean     DEFAULT FALSE NOT NULL,
    can_delete  boolean     DEFAULT FALSE NOT NULL,
    created_at  timestamptz DEFAULT now() NOT NULL,
    updated_at  timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT queue_permissions_pk PRIMARY KEY (queue_id, role_id)
);

CREATE TABLE organizations
(
    org_id     varchar(26)               NOT NULL,
    org_code   text                      NOT NULL,
    org_name   text                      NOT NULL,
    org_domain text,
    is_active  boolean     DEFAULT TRUE  NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    updated_at timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT organizations_pk PRIMARY KEY (org_id)
);

CREATE TABLE teams
(
    team_id     varchar(26)               NOT NULL,
    org_id      varchar(26)               NOT NULL,
    team_name   text                      NOT NULL,
    team_code   text                      NOT NULL,
    description text,
    is_active   boolean     DEFAULT TRUE  NOT NULL,
    created_at  timestamptz DEFAULT now() NOT NULL,
    updated_at  timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT teams_pk PRIMARY KEY (team_id)
);

CREATE TABLE user_teams
(
    user_id    varchar(26)               NOT NULL,
    team_id    varchar(26)               NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT user_teams_pk PRIMARY KEY (user_id, team_id)
);

CREATE TABLE team_roles
(
    team_id    varchar(26)               NOT NULL,
    role_id    varchar(26)               NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT team_roles_pk PRIMARY KEY (team_id, role_id)
);

CREATE TABLE oauth_providers
(
    provider_id   varchar(26)               NOT NULL,
    provider_name text                      NOT NULL,
    org_id        varchar(26),
    config_json   text                      NOT NULL,
    is_active     boolean     DEFAULT TRUE  NOT NULL,
    created_at    timestamptz DEFAULT now() NOT NULL,
    updated_at    timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT oauth_providers_pk PRIMARY KEY (provider_id)
);

CREATE TABLE topic_properties (
  topic_id text PRIMARY KEY,
  topic_name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  tenant_id text NOT NULL,
  created_by_kind text NOT NULL,
  created_by_id text NOT NULL,
  UNIQUE (tenant_id, topic_name)
);

CREATE TABLE topic_subscriptions (
  subscription_id text PRIMARY KEY,
  topic_id text NOT NULL REFERENCES topic_properties (topic_id) ON DELETE CASCADE,
  queue_id text NOT NULL REFERENCES queue_properties (queue_id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (topic_id, queue_id)
);

-- Agent messaging tables. Runtime DDL remains in the numbered migrations.
CREATE TABLE agents (
  agent_id text PRIMARY KEY,
  tenant_id text NOT NULL,
  agent_name text NOT NULL,
  status smallint NOT NULL CHECK (status IN (1, 2)),
  auth_version bigint NOT NULL DEFAULT 1,
  inbox_scan_cursor bigint NOT NULL DEFAULT 0,
  inbox_claim_version bigint NOT NULL DEFAULT 0,
  created_by_kind text NOT NULL,
  created_by_id text NOT NULL,
  created_at_ns bigint NOT NULL,
  updated_at_ns bigint NOT NULL,
  disabled_at_ns bigint,
  UNIQUE (tenant_id, agent_name),
  UNIQUE (tenant_id, agent_id),
  FOREIGN KEY (tenant_id) REFERENCES organizations (org_id)
);
CREATE INDEX agents_tenant_name_idx ON agents (tenant_id, agent_name, agent_id);

CREATE TABLE security_principals (
  tenant_id text NOT NULL,
  principal_kind text NOT NULL CHECK (principal_kind IN ('human', 'agent')),
  principal_id text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'disabled')),
  roles_json jsonb NOT NULL,
  auth_version bigint NOT NULL,
  updated_at_ns bigint NOT NULL,
  PRIMARY KEY (tenant_id, principal_kind, principal_id)
);

CREATE TABLE agent_credentials (
  credential_id text PRIMARY KEY,
  tenant_id text NOT NULL,
  agent_id text NOT NULL,
  credential_name text NOT NULL,
  credential_prefix text NOT NULL UNIQUE,
  secret_hash bytea NOT NULL CHECK (octet_length(secret_hash) = 32),
  created_at_ns bigint NOT NULL,
  expires_at_ns bigint,
  expired_accounted_at_ns bigint,
  revoked_at_ns bigint,
  last_used_at_ns bigint,
  FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, agent_id) ON DELETE CASCADE,
  UNIQUE (agent_id, credential_name)
);
CREATE INDEX agent_credentials_revoked_sweep_idx ON agent_credentials (revoked_at_ns, credential_id);
CREATE INDEX agent_credentials_expiry_sweep_idx ON agent_credentials (expires_at_ns, credential_id);

CREATE TABLE agent_resource_grants (
  grant_id text PRIMARY KEY,
  tenant_id text NOT NULL,
  subject_kind text NOT NULL CHECK (subject_kind IN ('human', 'agent')),
  subject_id text NOT NULL,
  resource_kind text NOT NULL CHECK (resource_kind IN ('tenant', 'agent', 'queue', 'topic', 'subscription')),
  resource_id text NOT NULL,
  action text NOT NULL,
  created_at_ns bigint NOT NULL,
  UNIQUE (tenant_id, subject_kind, subject_id, resource_kind, resource_id, action)
);

CREATE TABLE agent_idempotency (
  tenant_id text NOT NULL,
  principal_kind text NOT NULL CHECK (principal_kind IN ('human', 'agent', 'system')),
  principal_id text NOT NULL,
  operation text NOT NULL,
  idempotency_key text NOT NULL,
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  response_json jsonb NOT NULL,
  created_at_ns bigint NOT NULL,
  expires_at_ns bigint NOT NULL,
  PRIMARY KEY (tenant_id, principal_kind, principal_id, operation, idempotency_key)
);
CREATE INDEX agent_idempotency_expiry_idx ON agent_idempotency (expires_at_ns);

CREATE TABLE direct_messages (
  message_id text PRIMARY KEY,
  tenant_id text NOT NULL,
  sender_principal_kind text NOT NULL CHECK (sender_principal_kind IN ('human', 'agent')),
  sender_principal_id text NOT NULL,
  kind text NOT NULL,
  schema_version integer NOT NULL,
  content_type text NOT NULL,
  attributes_json jsonb NOT NULL,
  correlation_id text NOT NULL,
  causation_id text NOT NULL,
  conversation_id text NOT NULL,
  reply_to_agent_id text NOT NULL,
  body bytea NOT NULL,
  stored_bytes bigint NOT NULL CHECK (stored_bytes >= 0),
  created_at_ns bigint NOT NULL,
  deadline_at_ns bigint,
  UNIQUE (tenant_id, message_id),
  FOREIGN KEY (tenant_id, sender_principal_kind, sender_principal_id)
    REFERENCES security_principals (tenant_id, principal_kind, principal_id)
);

CREATE TABLE direct_deliveries (
  delivery_id text PRIMARY KEY,
  tenant_id text NOT NULL,
  recipient_agent_id text NOT NULL,
  message_id text NOT NULL,
  state text NOT NULL CHECK (state IN ('available', 'leased', 'acked', 'dead_lettered')),
  delivery_attempt integer NOT NULL DEFAULT 0,
  lease_generation bigint NOT NULL DEFAULT 0,
  lease_started_at_ns bigint,
  lease_expires_at_ns bigint,
  receipt_hash bytea CHECK (receipt_hash IS NULL OR octet_length(receipt_hash) = 32),
  available_at_ns bigint NOT NULL,
  acked_at_ns bigint,
  last_error text NOT NULL DEFAULT '',
  UNIQUE (tenant_id, recipient_agent_id, delivery_id),
  FOREIGN KEY (tenant_id, message_id) REFERENCES direct_messages (tenant_id, message_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, recipient_agent_id) REFERENCES agents (tenant_id, agent_id)
);
CREATE INDEX direct_deliveries_claim_idx ON direct_deliveries
  (tenant_id, recipient_agent_id, state, available_at_ns, delivery_id);
CREATE INDEX direct_deliveries_live_lease_idx ON direct_deliveries
  (tenant_id, recipient_agent_id, state, lease_expires_at_ns, delivery_id);

CREATE TABLE agent_dead_letters (
  dead_letter_id text PRIMARY KEY,
  tenant_id text NOT NULL,
  recipient_agent_id text NOT NULL,
  message_id text NOT NULL,
  original_delivery_id text NOT NULL,
  reason text NOT NULL,
  delivery_attempt integer NOT NULL,
  dead_lettered_at_ns bigint NOT NULL,
  replayed_at_ns bigint,
  UNIQUE (tenant_id, original_delivery_id),
  FOREIGN KEY (tenant_id, message_id) REFERENCES direct_messages (tenant_id, message_id),
  FOREIGN KEY (tenant_id, recipient_agent_id) REFERENCES agents (tenant_id, agent_id),
  FOREIGN KEY (tenant_id, recipient_agent_id, original_delivery_id)
    REFERENCES direct_deliveries (tenant_id, recipient_agent_id, delivery_id) ON DELETE CASCADE
);
CREATE INDEX agent_dead_letters_sweep_idx ON agent_dead_letters (dead_lettered_at_ns, dead_letter_id);
CREATE INDEX agent_dead_letters_recipient_idx ON agent_dead_letters (tenant_id, recipient_agent_id, dead_lettered_at_ns, dead_letter_id);

CREATE TABLE security_audit_events (
  audit_id text PRIMARY KEY,
  tenant_id text NOT NULL,
  principal_kind text NOT NULL,
  principal_id text NOT NULL,
  action text NOT NULL,
  resource_kind text NOT NULL,
  resource_id text NOT NULL,
  outcome text NOT NULL,
  request_id text NOT NULL,
  reason text NOT NULL,
  source_ip text NOT NULL,
  user_agent text NOT NULL,
  metadata_json jsonb NOT NULL,
  created_at_ns bigint NOT NULL
);
CREATE INDEX security_audit_tenant_time_idx ON security_audit_events (tenant_id, created_at_ns, audit_id);
CREATE INDEX security_audit_sweep_idx ON security_audit_events (created_at_ns, audit_id);

CREATE TABLE cluster_feature_state (
  feature_name text PRIMARY KEY,
  state text NOT NULL CHECK (state IN ('preparing', 'active')),
  activation_id text NOT NULL UNIQUE,
  source_digest bytea NOT NULL CHECK (octet_length(source_digest) = 32),
  source_record_count bigint NOT NULL CHECK (source_record_count >= 0),
  source_byte_count bigint NOT NULL CHECK (source_byte_count >= 0),
  staging_receipts_digest bytea NOT NULL CHECK (octet_length(staging_receipts_digest) = 32),
  staging_receipts_bytes bytea NOT NULL,
  coordinator_id text NOT NULL,
  last_imported_ordinal bigint NOT NULL DEFAULT -1 CHECK (last_imported_ordinal >= -1),
  last_imported_kind text NOT NULL DEFAULT '',
  last_imported_key text NOT NULL DEFAULT '',
  updated_log_index bigint NOT NULL CHECK (updated_log_index >= 0),
  updated_at_ns bigint NOT NULL
);

CREATE TABLE cluster_activation_import_records (
  activation_id text NOT NULL,
  record_ordinal bigint NOT NULL CHECK (record_ordinal >= 0),
  record_kind text NOT NULL,
  record_key text NOT NULL,
  record_hash bytea NOT NULL CHECK (octet_length(record_hash) = 32),
  record_bytes bytea NOT NULL,
  PRIMARY KEY (activation_id, record_ordinal),
  UNIQUE (activation_id, record_kind, record_key)
);
CREATE INDEX cluster_activation_import_key_idx ON cluster_activation_import_records
  (activation_id, record_kind, record_key);

CREATE TABLE tenant_quotas (
  tenant_id text PRIMARY KEY,
  max_agents bigint NOT NULL,
  max_credentials_per_agent bigint NOT NULL,
  max_queues bigint NOT NULL,
  max_topics bigint NOT NULL,
  max_subscriptions bigint NOT NULL,
  max_message_bytes bigint NOT NULL,
  max_stored_bytes bigint NOT NULL,
  send_per_second bigint NOT NULL,
  publish_per_second bigint NOT NULL,
  updated_at_ns bigint NOT NULL
);

CREATE TABLE quota_windows (
  tenant_id text NOT NULL,
  action text NOT NULL,
  window_started_at_ns bigint NOT NULL,
  used bigint NOT NULL,
  PRIMARY KEY (tenant_id, action, window_started_at_ns)
);

CREATE TABLE tenant_resource_usage (
  tenant_id text PRIMARY KEY,
  agent_count bigint NOT NULL,
  topic_count bigint NOT NULL,
  subscription_count bigint NOT NULL,
  stored_messaging_bytes bigint NOT NULL,
  updated_at_ns bigint NOT NULL
);

CREATE TABLE agent_resource_usage (
  tenant_id text NOT NULL,
  agent_id text NOT NULL,
  pending_direct_count bigint NOT NULL,
  pending_direct_bytes bigint NOT NULL,
  subscription_count bigint NOT NULL,
  active_credential_count bigint NOT NULL,
  updated_at_ns bigint NOT NULL,
  PRIMARY KEY (tenant_id, agent_id)
);
