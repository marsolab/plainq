-- sqlc-only schema for SQLite type inference. Do NOT run this at runtime —
-- the canonical migrations live in internal/server/mutations/storage/sqlite/
-- and are applied via litekit.Evolver. This file captures the runtime schema
-- in a form sqlc's parser can consume (no non-standard syntax, no seed data).

CREATE TABLE users
(
    user_id        TEXT    NOT NULL,
    email          TEXT    NOT NULL,
    password       TEXT    NOT NULL,
    verified       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    org_id         TEXT,
    oauth_provider TEXT,
    oauth_sub      TEXT,
    last_sync_at   TIMESTAMP,
    is_oauth_user  BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT users_pk PRIMARY KEY (user_id)
);

CREATE TABLE refresh_tokens
(
    id         TEXT    NOT NULL,
    aid        TEXT    NOT NULL,
    token      TEXT    NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT refresh_tokens_pk PRIMARY KEY (id)
);

CREATE TABLE denylist
(
    token        TEXT    NOT NULL,
    denied_until INTEGER NOT NULL,
    CONSTRAINT denylist_pk PRIMARY KEY (token)
);

CREATE TABLE roles
(
    role_id    TEXT    NOT NULL,
    role_name  TEXT    NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT roles_pk PRIMARY KEY (role_id)
);

CREATE TABLE user_roles
(
    user_id    TEXT    NOT NULL,
    role_id    TEXT    NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT user_roles_pk PRIMARY KEY (user_id, role_id)
);

CREATE TABLE queue_properties
(
    queue_id                   TEXT    NOT NULL,
    queue_name                 TEXT    NOT NULL,
    created_at                 TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    gc_at                      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retention_period_seconds   INTEGER NOT NULL,
    visibility_timeout_seconds INTEGER NOT NULL,
    max_receive_attempts       INTEGER NOT NULL,
    drop_policy                INTEGER NOT NULL DEFAULT 0,
    dead_letter_queue_id       TEXT,
    CONSTRAINT queue_properties_pk PRIMARY KEY (queue_id)
);

CREATE TABLE queue_permissions
(
    queue_id    TEXT      NOT NULL,
    role_id     TEXT      NOT NULL,
    can_send    BOOLEAN   NOT NULL DEFAULT FALSE,
    can_receive BOOLEAN   NOT NULL DEFAULT FALSE,
    can_purge   BOOLEAN   NOT NULL DEFAULT FALSE,
    can_delete  BOOLEAN   NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT queue_permissions_pk PRIMARY KEY (queue_id, role_id)
);

CREATE TABLE organizations
(
    org_id     TEXT      NOT NULL,
    org_code   TEXT      NOT NULL,
    org_name   TEXT      NOT NULL,
    org_domain TEXT,
    is_active  BOOLEAN   NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT organizations_pk PRIMARY KEY (org_id)
);

CREATE TABLE teams
(
    team_id     TEXT      NOT NULL,
    org_id      TEXT      NOT NULL,
    team_name   TEXT      NOT NULL,
    team_code   TEXT      NOT NULL,
    description TEXT,
    is_active   BOOLEAN   NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT teams_pk PRIMARY KEY (team_id)
);

CREATE TABLE user_teams
(
    user_id    TEXT      NOT NULL,
    team_id    TEXT      NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT user_teams_pk PRIMARY KEY (user_id, team_id)
);

CREATE TABLE team_roles
(
    team_id    TEXT      NOT NULL,
    role_id    TEXT      NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT team_roles_pk PRIMARY KEY (team_id, role_id)
);

CREATE TABLE oauth_providers
(
    provider_id   TEXT      NOT NULL,
    provider_name TEXT      NOT NULL,
    org_id        TEXT,
    config_json   TEXT      NOT NULL,
    is_active     BOOLEAN   NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT oauth_providers_pk PRIMARY KEY (provider_id)
);
