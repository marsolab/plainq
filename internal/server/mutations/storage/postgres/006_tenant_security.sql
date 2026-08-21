-- Migration 006 intentionally revokes every pre-v6 session because the old
-- schema stored clear bearer material.
INSERT INTO organizations (org_id, org_code, org_name, org_domain)
VALUES ('01HQ5RJNXS6TPXK89PQWY4N8JH', 'default', 'Default Organization', NULL)
ON CONFLICT (org_id) DO NOTHING;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM organizations
    WHERE org_id = '01HQ5RJNXS6TPXK89PQWY4N8JH'
      AND org_code = 'default'
      AND org_name = 'Default Organization'
      AND org_domain IS NULL
  ) THEN
    RAISE EXCEPTION 'fixed legacy tenant id is occupied by a conflicting organization';
  END IF;
END $$;

ALTER TABLE users ADD COLUMN auth_version bigint NOT NULL DEFAULT 1 CHECK (auth_version >= 1);
ALTER TABLE users ADD COLUMN status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled'));
UPDATE users SET org_id = '01HQ5RJNXS6TPXK89PQWY4N8JH' WHERE org_id IS NULL;
ALTER TABLE users ADD CONSTRAINT users_org_fk FOREIGN KEY (org_id) REFERENCES organizations (org_id);
ALTER TABLE users ALTER COLUMN org_id SET NOT NULL;

DROP TABLE refresh_tokens;
CREATE TABLE refresh_tokens (
  id text PRIMARY KEY,
  aid text NOT NULL,
  token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  created_at_ns bigint NOT NULL,
  expires_at_ns bigint NOT NULL,
  last_used_at_ns bigint NOT NULL,
  FOREIGN KEY (aid) REFERENCES users (user_id) ON DELETE CASCADE
);
CREATE INDEX refresh_tokens_expiry_idx ON refresh_tokens (expires_at_ns, id);

DROP TABLE denylist;
CREATE TABLE denylist (
  token_id text PRIMARY KEY,
  aid text NOT NULL,
  expires_at_ns bigint NOT NULL,
  created_at_ns bigint NOT NULL,
  reason text NOT NULL,
  FOREIGN KEY (aid) REFERENCES users (user_id) ON DELETE CASCADE
);
CREATE INDEX denylist_expiry_idx ON denylist (expires_at_ns, token_id);

ALTER TABLE queue_properties ADD COLUMN tenant_id text NOT NULL DEFAULT '01HQ5RJNXS6TPXK89PQWY4N8JH';
ALTER TABLE queue_properties ADD COLUMN created_by_kind text NOT NULL DEFAULT 'system';
ALTER TABLE queue_properties ADD COLUMN created_by_id text NOT NULL DEFAULT 'migration';
DROP INDEX queue_name_uindex;
CREATE UNIQUE INDEX queue_tenant_name_uindex ON queue_properties (tenant_id, queue_name);
CREATE INDEX queue_tenant_id_idx ON queue_properties (tenant_id, queue_id);

ALTER TABLE topic_properties ADD COLUMN tenant_id text NOT NULL DEFAULT '01HQ5RJNXS6TPXK89PQWY4N8JH';
ALTER TABLE topic_properties ADD COLUMN created_by_kind text NOT NULL DEFAULT 'system';
ALTER TABLE topic_properties ADD COLUMN created_by_id text NOT NULL DEFAULT 'migration';
DROP INDEX topic_name_uindex;
CREATE UNIQUE INDEX topic_tenant_name_uindex ON topic_properties (tenant_id, topic_name);
CREATE INDEX topic_tenant_id_idx ON topic_properties (tenant_id, topic_id);

CREATE TABLE tenant_quotas (
  tenant_id text PRIMARY KEY REFERENCES organizations (org_id) ON DELETE CASCADE,
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
  tenant_id text NOT NULL REFERENCES organizations (org_id) ON DELETE CASCADE,
  action text NOT NULL,
  window_started_at_ns bigint NOT NULL,
  used bigint NOT NULL CHECK (used >= 0),
  PRIMARY KEY (tenant_id, action, window_started_at_ns)
);
CREATE INDEX quota_windows_sweep_idx ON quota_windows (window_started_at_ns, tenant_id, action);

CREATE TABLE tenant_resource_usage (
  tenant_id text PRIMARY KEY REFERENCES organizations (org_id) ON DELETE CASCADE,
  agent_count bigint NOT NULL DEFAULT 0,
  topic_count bigint NOT NULL DEFAULT 0,
  subscription_count bigint NOT NULL DEFAULT 0,
  stored_messaging_bytes bigint NOT NULL DEFAULT 0,
  updated_at_ns bigint NOT NULL,
  CHECK (agent_count >= 0 AND topic_count >= 0 AND subscription_count >= 0 AND stored_messaging_bytes >= 0)
);

CREATE TABLE agent_resource_usage (
  tenant_id text NOT NULL,
  agent_id text NOT NULL,
  pending_direct_count bigint NOT NULL DEFAULT 0,
  pending_direct_bytes bigint NOT NULL DEFAULT 0,
  subscription_count bigint NOT NULL DEFAULT 0,
  active_credential_count bigint NOT NULL DEFAULT 0,
  updated_at_ns bigint NOT NULL,
  PRIMARY KEY (tenant_id, agent_id),
  FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, agent_id) ON DELETE CASCADE,
  CHECK (pending_direct_count >= 0 AND pending_direct_bytes >= 0 AND subscription_count >= 0 AND active_credential_count >= 0)
);

INSERT INTO security_principals (
  tenant_id, principal_kind, principal_id, status, roles_json, auth_version, updated_at_ns
)
SELECT u.org_id, 'human', u.user_id, u.status,
       coalesce((
         SELECT jsonb_agg(r.role_name ORDER BY r.role_name)
         FROM user_roles ur JOIN roles r ON r.role_id = ur.role_id
         WHERE ur.user_id = u.user_id
       ), '[]'::jsonb),
       u.auth_version,
       floor(extract(epoch FROM clock_timestamp()) * 1000000000)::bigint
FROM users u;

INSERT INTO tenant_quotas (
  tenant_id, max_agents, max_credentials_per_agent, max_queues, max_topics,
  max_subscriptions, max_message_bytes, max_stored_bytes, send_per_second,
  publish_per_second, updated_at_ns
)
SELECT org_id, 10000, 2, 10000, 1000, 1000, 1048576, 10737418240,
       1000, 1000, floor(extract(epoch FROM clock_timestamp()) * 1000000000)::bigint
FROM organizations;

INSERT INTO tenant_resource_usage (
  tenant_id, agent_count, topic_count, subscription_count,
  stored_messaging_bytes, updated_at_ns
)
SELECT o.org_id,
       (SELECT count(*) FROM agents a WHERE a.tenant_id = o.org_id),
       (SELECT count(*) FROM topic_properties t WHERE t.tenant_id = o.org_id),
       (SELECT count(*) FROM topic_subscriptions s JOIN topic_properties t ON t.topic_id = s.topic_id WHERE t.tenant_id = o.org_id),
       coalesce((SELECT sum(stored_bytes) FROM direct_messages d WHERE d.tenant_id = o.org_id), 0),
       floor(extract(epoch FROM clock_timestamp()) * 1000000000)::bigint
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
       floor(extract(epoch FROM clock_timestamp()) * 1000000000)::bigint
FROM agents a;

DO $$
BEGIN
  IF EXISTS (
       SELECT 1
       FROM tenant_resource_usage u
       WHERE u.agent_count <> (SELECT count(*) FROM agents a WHERE a.tenant_id = u.tenant_id)
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
          OR u.topic_count < 0
          OR u.subscription_count < 0
          OR u.stored_messaging_bytes < 0
     )
     OR EXISTS (
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
     OR (SELECT count(*) FROM tenant_resource_usage) <> (SELECT count(*) FROM organizations)
     OR (SELECT coalesce(sum(agent_count), 0) FROM tenant_resource_usage) <> (SELECT count(*) FROM agents)
     OR (SELECT coalesce(sum(topic_count), 0) FROM tenant_resource_usage) <> (SELECT count(*) FROM topic_properties)
     OR (SELECT coalesce(sum(subscription_count), 0) FROM tenant_resource_usage) <> (SELECT count(*) FROM topic_subscriptions)
     OR (SELECT coalesce(sum(stored_messaging_bytes), 0) FROM tenant_resource_usage) <> (SELECT coalesce(sum(stored_bytes), 0) FROM direct_messages)
     OR (SELECT count(*) FROM agent_resource_usage) <> (SELECT count(*) FROM agents) THEN
    RAISE EXCEPTION 'tenant usage ledger backfill mismatch';
  END IF;
END $$;
