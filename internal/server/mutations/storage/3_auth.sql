-- Fix the default admin user insert (column name mismatch)
-- The table has 'verified' but the insert uses 'is_email_verified'
-- This migration will be idempotent

-- Refresh tokens table for secure token management
create table if not exists "refresh_tokens"
(
    token_id       varchar(26)                         not null,
    user_id        varchar(26)                         not null,
    token_hash     text                                not null,
    expires_at     timestamp                           not null,
    revoked        boolean   default false             not null,
    revoked_at     timestamp,
    created_at     timestamp default current_timestamp not null,
    last_used_at   timestamp default current_timestamp not null,
    device_info    text,                                         -- User agent or device identifier
    ip_address     text,

    constraint refresh_tokens_pk
        primary key (token_id),
    constraint refresh_tokens_user_fk
        foreign key (user_id) references users (user_id)
            on delete cascade
);

create index if not exists refresh_tokens_user_id_index
    on refresh_tokens (user_id);

create index if not exists refresh_tokens_expires_at_index
    on refresh_tokens (expires_at);

-- Token deny list for invalidated access tokens (TTL+1 approach)
-- Tokens are stored here when explicitly revoked (logout, password change, etc.)
-- Cleanup happens automatically based on expires_at
create table if not exists "token_denylist"
(
    jti            varchar(64)                         not null, -- JWT ID from token claims
    user_id        varchar(26)                         not null,
    expires_at     timestamp                           not null, -- Original token expiry
    revoked_at     timestamp default current_timestamp not null,
    reason         text,                                         -- logout, password_change, admin_revoke, etc.

    constraint token_denylist_pk
        primary key (jti),
    constraint token_denylist_user_fk
        foreign key (user_id) references users (user_id)
            on delete cascade
);

create index if not exists token_denylist_expires_at_index
    on token_denylist (expires_at);

create index if not exists token_denylist_user_id_index
    on token_denylist (user_id);

-- OAuth provider connections
create table if not exists "oauth_providers"
(
    provider_id   varchar(26)                         not null,
    provider_name text                                not null, -- kinde, auth0, okta, workos, google, github, etc.
    provider_type text                                not null, -- oidc, oauth2, saml
    enabled       boolean   default false             not null,

    -- OAuth/OIDC configuration
    client_id     text,
    client_secret text,
    issuer_url    text,
    auth_url      text,
    token_url     text,
    userinfo_url  text,
    jwks_url      text,
    scopes        text,                                         -- JSON array of scopes

    -- SAML configuration
    saml_metadata_url text,
    saml_entity_id    text,

    -- Generic config
    config_json   text,                                         -- Additional provider-specific config as JSON

    created_at    timestamp default current_timestamp not null,
    updated_at    timestamp default current_timestamp not null,

    constraint oauth_providers_pk
        primary key (provider_id)
);

create unique index if not exists oauth_providers_name_uindex
    on oauth_providers (provider_name);

-- OAuth user connections (linked accounts)
create table if not exists "oauth_connections"
(
    connection_id  varchar(26)                         not null,
    user_id        varchar(26)                         not null,
    provider_id    varchar(26)                         not null,
    provider_user_id text                              not null, -- User ID from OAuth provider (sub claim)
    email          text,
    profile_data   text,                                         -- JSON data from provider (name, avatar, etc.)
    access_token   text,                                         -- Encrypted OAuth access token (optional)
    refresh_token  text,                                         -- Encrypted OAuth refresh token (optional)
    expires_at     timestamp,
    created_at     timestamp default current_timestamp not null,
    updated_at     timestamp default current_timestamp not null,

    constraint oauth_connections_pk
        primary key (connection_id),
    constraint oauth_connections_user_fk
        foreign key (user_id) references users (user_id)
            on delete cascade,
    constraint oauth_connections_provider_fk
        foreign key (provider_id) references oauth_providers (provider_id)
            on delete cascade,
    constraint oauth_connections_unique
        unique (provider_id, provider_user_id)
);

create index if not exists oauth_connections_user_id_index
    on oauth_connections (user_id);

create index if not exists oauth_connections_provider_id_index
    on oauth_connections (provider_id);

-- System settings table for first-time setup tracking
create table if not exists "system_state"
(
    key        text                                not null,
    value      text                                not null,
    updated_at timestamp default current_timestamp not null,

    constraint system_state_pk
        primary key (key)
);

-- Track if initial setup has been completed
insert or ignore into system_state (key, value)
values ('setup_completed', 'false');

-- Password reset tokens
create table if not exists "password_reset_tokens"
(
    token_id   varchar(26)                         not null,
    user_id    varchar(26)                         not null,
    token_hash text                                not null,
    expires_at timestamp                           not null,
    used       boolean   default false             not null,
    used_at    timestamp,
    created_at timestamp default current_timestamp not null,

    constraint password_reset_tokens_pk
        primary key (token_id),
    constraint password_reset_tokens_user_fk
        foreign key (user_id) references users (user_id)
            on delete cascade
);

create index if not exists password_reset_tokens_user_id_index
    on password_reset_tokens (user_id);

create index if not exists password_reset_tokens_expires_at_index
    on password_reset_tokens (expires_at);

-- Email verification tokens
create table if not exists "email_verification_tokens"
(
    token_id   varchar(26)                         not null,
    user_id    varchar(26)                         not null,
    token_hash text                                not null,
    expires_at timestamp                           not null,
    used       boolean   default false             not null,
    used_at    timestamp,
    created_at timestamp default current_timestamp not null,

    constraint email_verification_tokens_pk
        primary key (token_id),
    constraint email_verification_tokens_user_fk
        foreign key (user_id) references users (user_id)
            on delete cascade
);

create index if not exists email_verification_tokens_user_id_index
    on email_verification_tokens (user_id);

-- Audit log for authentication events
create table if not exists "auth_audit_log"
(
    log_id     varchar(26)                         not null,
    user_id    varchar(26),
    event_type text                                not null, -- login, logout, signup, password_change, token_refresh, etc.
    success    boolean                             not null,
    ip_address text,
    user_agent text,
    metadata   text,                                         -- JSON with additional context
    created_at timestamp default current_timestamp not null,

    constraint auth_audit_log_pk
        primary key (log_id)
);

create index if not exists auth_audit_log_user_id_index
    on auth_audit_log (user_id);

create index if not exists auth_audit_log_created_at_index
    on auth_audit_log (created_at);

create index if not exists auth_audit_log_event_type_index
    on auth_audit_log (event_type);
