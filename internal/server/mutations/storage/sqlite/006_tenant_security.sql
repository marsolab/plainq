-- Migration 006 intentionally revokes every pre-v6 session. The old tables
-- stored clear bearer material, which SQLite cannot hash portably in-place.

-- The fixed legacy tenant is a protocol boundary. Refuse to reinterpret an
-- organization that already occupies its ID.
INSERT OR IGNORE INTO organizations (org_id, org_code, org_name, org_domain)
VALUES ('01HQ5RJNXS6TPXK89PQWY4N8JH', 'default', 'Default Organization', NULL);

CREATE TABLE tenant_security_guard_006 (
  ok INTEGER NOT NULL CHECK (ok = 1)
);
INSERT INTO tenant_security_guard_006 (ok)
SELECT CASE WHEN EXISTS (
  SELECT 1
  FROM organizations
  WHERE org_id = '01HQ5RJNXS6TPXK89PQWY4N8JH'
    AND org_code = 'default'
    AND org_name = 'Default Organization'
    AND org_domain IS NULL
) THEN 1 ELSE 0 END;

-- Rebuild users instead of relying on ADD COLUMN: org_id becomes genuinely
-- NOT NULL and gains the missing organization foreign key.
CREATE TABLE users_v6 (
  user_id TEXT NOT NULL,
  email TEXT NOT NULL,
  password TEXT NOT NULL,
  verified BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMP NOT NULL DEFAULT current_timestamp,
  updated_at TIMESTAMP NOT NULL DEFAULT current_timestamp,
  org_id TEXT NOT NULL,
  oauth_provider TEXT,
  oauth_sub TEXT,
  last_sync_at TIMESTAMP,
  is_oauth_user BOOLEAN NOT NULL DEFAULT false,
  auth_version INTEGER NOT NULL DEFAULT 1 CHECK (auth_version >= 1),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  CONSTRAINT users_pk PRIMARY KEY (user_id),
  CONSTRAINT users_org_fk FOREIGN KEY (org_id) REFERENCES organizations (org_id)
);

INSERT INTO users_v6 (
  user_id, email, password, verified, created_at, updated_at, org_id,
  oauth_provider, oauth_sub, last_sync_at, is_oauth_user, auth_version, status
)
SELECT user_id, email, password, verified, created_at, updated_at,
       coalesce(org_id, '01HQ5RJNXS6TPXK89PQWY4N8JH'),
       oauth_provider, oauth_sub, last_sync_at, is_oauth_user, 1, 'active'
FROM users;

DROP TABLE users;
ALTER TABLE users_v6 RENAME TO users;
CREATE UNIQUE INDEX users_user_id_uindex ON users (user_id);
CREATE UNIQUE INDEX users_email_uindex ON users (email);
CREATE INDEX users_org_index ON users (org_id);
CREATE INDEX users_oauth_index ON users (oauth_provider, oauth_sub);

DROP TABLE refresh_tokens;
CREATE TABLE refresh_tokens (
  id TEXT PRIMARY KEY,
  aid TEXT NOT NULL,
  token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
  created_at_ns INTEGER NOT NULL,
  expires_at_ns INTEGER NOT NULL,
  last_used_at_ns INTEGER NOT NULL,
  FOREIGN KEY (aid) REFERENCES users (user_id) ON DELETE CASCADE
);
CREATE INDEX refresh_tokens_expiry_idx ON refresh_tokens (expires_at_ns, id);

DROP TABLE denylist;
CREATE TABLE denylist (
  token_id TEXT PRIMARY KEY,
  aid TEXT NOT NULL,
  expires_at_ns INTEGER NOT NULL,
  created_at_ns INTEGER NOT NULL,
  reason TEXT NOT NULL,
  FOREIGN KEY (aid) REFERENCES users (user_id) ON DELETE CASCADE
);
CREATE INDEX denylist_expiry_idx ON denylist (expires_at_ns, token_id);

ALTER TABLE queue_properties ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '01HQ5RJNXS6TPXK89PQWY4N8JH';
ALTER TABLE queue_properties ADD COLUMN created_by_kind TEXT NOT NULL DEFAULT 'system';
ALTER TABLE queue_properties ADD COLUMN created_by_id TEXT NOT NULL DEFAULT 'migration';
DROP INDEX queue_name_uindex;
CREATE UNIQUE INDEX queue_tenant_name_uindex ON queue_properties (tenant_id, queue_name);
CREATE INDEX queue_tenant_id_idx ON queue_properties (tenant_id, queue_id);

ALTER TABLE topic_properties ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '01HQ5RJNXS6TPXK89PQWY4N8JH';
ALTER TABLE topic_properties ADD COLUMN created_by_kind TEXT NOT NULL DEFAULT 'system';
ALTER TABLE topic_properties ADD COLUMN created_by_id TEXT NOT NULL DEFAULT 'migration';
DROP INDEX topic_name_uindex;
CREATE UNIQUE INDEX topic_tenant_name_uindex ON topic_properties (tenant_id, topic_name);
CREATE INDEX topic_tenant_id_idx ON topic_properties (tenant_id, topic_id);

CREATE TABLE tenant_quotas (
  tenant_id TEXT PRIMARY KEY,
  max_agents INTEGER NOT NULL,
  max_credentials_per_agent INTEGER NOT NULL,
  max_queues INTEGER NOT NULL,
  max_topics INTEGER NOT NULL,
  max_subscriptions INTEGER NOT NULL,
  max_message_bytes INTEGER NOT NULL,
  max_stored_bytes INTEGER NOT NULL,
  send_per_second INTEGER NOT NULL,
  publish_per_second INTEGER NOT NULL,
  updated_at_ns INTEGER NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES organizations (org_id) ON DELETE CASCADE
);

CREATE TABLE quota_windows (
  tenant_id TEXT NOT NULL,
  action TEXT NOT NULL,
  window_started_at_ns INTEGER NOT NULL,
  used INTEGER NOT NULL CHECK (used >= 0),
  PRIMARY KEY (tenant_id, action, window_started_at_ns),
  FOREIGN KEY (tenant_id) REFERENCES organizations (org_id) ON DELETE CASCADE
);
CREATE INDEX quota_windows_sweep_idx ON quota_windows (window_started_at_ns, tenant_id, action);

CREATE TABLE tenant_resource_usage (
  tenant_id TEXT PRIMARY KEY,
  agent_count INTEGER NOT NULL DEFAULT 0,
  queue_count INTEGER NOT NULL DEFAULT 0,
  topic_count INTEGER NOT NULL DEFAULT 0,
  subscription_count INTEGER NOT NULL DEFAULT 0,
  stored_messaging_bytes INTEGER NOT NULL DEFAULT 0,
  updated_at_ns INTEGER NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES organizations (org_id) ON DELETE CASCADE,
  CHECK (agent_count >= 0 AND queue_count >= 0 AND topic_count >= 0 AND subscription_count >= 0 AND stored_messaging_bytes >= 0)
);

CREATE TABLE agent_resource_usage (
  tenant_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  pending_direct_count INTEGER NOT NULL DEFAULT 0,
  pending_direct_bytes INTEGER NOT NULL DEFAULT 0,
  subscription_count INTEGER NOT NULL DEFAULT 0,
  active_credential_count INTEGER NOT NULL DEFAULT 0,
  updated_at_ns INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, agent_id),
  FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, agent_id) ON DELETE CASCADE,
  CHECK (pending_direct_count >= 0 AND pending_direct_bytes >= 0 AND subscription_count >= 0 AND active_credential_count >= 0)
);

INSERT INTO security_principals (
  tenant_id, principal_kind, principal_id, status, roles_json, auth_version, updated_at_ns
)
SELECT u.org_id, 'human', u.user_id, u.status,
       coalesce((
         SELECT json_group_array(role_name)
         FROM (
           SELECT r.role_name AS role_name
           FROM user_roles ur
           JOIN roles r ON r.role_id = ur.role_id
           WHERE ur.user_id = u.user_id
           ORDER BY r.role_name
         )
       ), '[]'),
       u.auth_version,
       CAST(strftime('%s', 'now') AS INTEGER) * 1000000000
FROM users u;

INSERT INTO tenant_quotas (
  tenant_id, max_agents, max_credentials_per_agent, max_queues, max_topics,
  max_subscriptions, max_message_bytes, max_stored_bytes, send_per_second,
  publish_per_second, updated_at_ns
)
SELECT org_id, 10000, 2, 10000, 1000, 1000, 1048576, 10737418240,
       1000, 1000, CAST(strftime('%s', 'now') AS INTEGER) * 1000000000
FROM organizations;

INSERT INTO tenant_resource_usage (
  tenant_id, agent_count, queue_count, topic_count, subscription_count,
  stored_messaging_bytes, updated_at_ns
)
SELECT o.org_id,
       (SELECT count(*) FROM agents a WHERE a.tenant_id = o.org_id),
       (SELECT count(*) FROM queue_properties q WHERE q.tenant_id = o.org_id),
       (SELECT count(*) FROM topic_properties t WHERE t.tenant_id = o.org_id),
       (SELECT count(*) FROM topic_subscriptions s JOIN topic_properties t ON t.topic_id = s.topic_id WHERE t.tenant_id = o.org_id),
       coalesce((SELECT sum(stored_bytes) FROM direct_messages d WHERE d.tenant_id = o.org_id), 0),
       CAST(strftime('%s', 'now') AS INTEGER) * 1000000000
FROM organizations o;

INSERT INTO agent_resource_usage (
  tenant_id, agent_id, pending_direct_count, pending_direct_bytes,
  subscription_count, active_credential_count, updated_at_ns
)
SELECT a.tenant_id, a.agent_id,
       (SELECT count(*) FROM direct_deliveries d WHERE d.tenant_id = a.tenant_id AND d.recipient_agent_id = a.agent_id AND d.state IN ('available', 'leased')),
       coalesce((
         SELECT sum(m.stored_bytes)
         FROM direct_deliveries d
         JOIN direct_messages m ON m.tenant_id = d.tenant_id AND m.message_id = d.message_id
         WHERE d.tenant_id = a.tenant_id AND d.recipient_agent_id = a.agent_id AND d.state IN ('available', 'leased')
       ), 0),
       0,
       (SELECT count(*) FROM agent_credentials c WHERE c.tenant_id = a.tenant_id AND c.agent_id = a.agent_id AND c.revoked_at_ns IS NULL),
       CAST(strftime('%s', 'now') AS INTEGER) * 1000000000
FROM agents a;

-- Fail the migration if any ledger aggregate omitted or double-counted rows.
INSERT INTO tenant_security_guard_006 (ok)
SELECT CASE WHEN
  NOT EXISTS (
    SELECT 1
    FROM tenant_resource_usage u
    WHERE u.agent_count <> (SELECT count(*) FROM agents a WHERE a.tenant_id = u.tenant_id)
       OR u.queue_count <> (SELECT count(*) FROM queue_properties q WHERE q.tenant_id = u.tenant_id)
       OR u.topic_count <> (SELECT count(*) FROM topic_properties t WHERE t.tenant_id = u.tenant_id)
       OR u.subscription_count <> (
         SELECT count(*)
         FROM topic_subscriptions s
         JOIN topic_properties t ON t.topic_id = s.topic_id
         WHERE t.tenant_id = u.tenant_id
       )
       OR u.stored_messaging_bytes <> (
         SELECT coalesce(sum(d.stored_bytes), 0)
         FROM direct_messages d
         WHERE d.tenant_id = u.tenant_id
       )
       OR u.agent_count < 0
       OR u.queue_count < 0
       OR u.topic_count < 0
       OR u.subscription_count < 0
       OR u.stored_messaging_bytes < 0
  )
  AND NOT EXISTS (
    SELECT 1
    FROM agent_resource_usage u
    WHERE u.pending_direct_count <> (
         SELECT count(*)
         FROM direct_deliveries d
         WHERE d.tenant_id = u.tenant_id
           AND d.recipient_agent_id = u.agent_id
           AND d.state IN ('available', 'leased')
       )
       OR u.pending_direct_bytes <> (
         SELECT coalesce(sum(m.stored_bytes), 0)
         FROM direct_deliveries d
         JOIN direct_messages m ON m.tenant_id = d.tenant_id AND m.message_id = d.message_id
         WHERE d.tenant_id = u.tenant_id
           AND d.recipient_agent_id = u.agent_id
           AND d.state IN ('available', 'leased')
       )
       OR u.subscription_count <> 0
       OR u.active_credential_count <> (
         SELECT count(*)
         FROM agent_credentials c
         WHERE c.tenant_id = u.tenant_id
           AND c.agent_id = u.agent_id
           AND c.revoked_at_ns IS NULL
       )
       OR u.pending_direct_count < 0
       OR u.pending_direct_bytes < 0
       OR u.subscription_count < 0
       OR u.active_credential_count < 0
  )
  AND (SELECT count(*) FROM tenant_resource_usage) = (SELECT count(*) FROM organizations)
  AND (SELECT coalesce(sum(agent_count), 0) FROM tenant_resource_usage) = (SELECT count(*) FROM agents)
  AND (SELECT coalesce(sum(queue_count), 0) FROM tenant_resource_usage) = (SELECT count(*) FROM queue_properties)
  AND (SELECT coalesce(sum(topic_count), 0) FROM tenant_resource_usage) = (SELECT count(*) FROM topic_properties)
  AND (SELECT coalesce(sum(subscription_count), 0) FROM tenant_resource_usage) = (SELECT count(*) FROM topic_subscriptions)
  AND (SELECT coalesce(sum(stored_messaging_bytes), 0) FROM tenant_resource_usage) = (SELECT coalesce(sum(stored_bytes), 0) FROM direct_messages)
  AND (SELECT count(*) FROM agent_resource_usage) = (SELECT count(*) FROM agents)
THEN 1 ELSE 0 END;

DROP TABLE tenant_security_guard_006;
