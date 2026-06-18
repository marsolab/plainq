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
    org_id         varchar(26),
    oauth_provider text,
    oauth_sub      text,
    last_sync_at   timestamptz,
    is_oauth_user  boolean     DEFAULT FALSE NOT NULL,
    CONSTRAINT users_pk PRIMARY KEY (user_id)
);

CREATE TABLE refresh_tokens
(
    id         varchar(26)               NOT NULL,
    aid        varchar(26)               NOT NULL,
    token      text                      NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    expires_at timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT refresh_tokens_pk PRIMARY KEY (id)
);

CREATE TABLE denylist
(
    token        text   NOT NULL,
    denied_until bigint NOT NULL,
    CONSTRAINT denylist_pk PRIMARY KEY (token)
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
