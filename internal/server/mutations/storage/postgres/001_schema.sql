create table if not exists "settings"
(
    id         serial                                  not null,
    settings   jsonb       default '{}'::jsonb         not null,
    created_at timestamptz default now()               not null,
    updated_at timestamptz default now()               not null,

    constraint settings_pk primary key (id)
);

---

create table if not exists "accounts"
(
    account_id  varchar(26)                 not null,
    email       text                        not null,
    password    text                        not null,
    verified    boolean     default false   not null,
    created_at  timestamptz default now()   not null,
    updated_at  timestamptz default now()   not null,

    constraint accounts_pk primary key (account_id)
);

create unique index if not exists accounts_email_uindex on accounts (email);

---

create table if not exists refresh_tokens
(
    id         varchar(26)               not null,
    aid        varchar(26)               not null,
    token      text                      not null,
    created_at timestamptz default now() not null,
    expires_at timestamptz default now() not null,

    constraint session_pk primary key (id)
);

create unique index if not exists refresh_tokens_id_uindex
    on refresh_tokens (id);

create unique index if not exists refresh_tokens_token_uindex
    on refresh_tokens (token);

---

create table if not exists denylist
(
    token        text    not null,
    denied_until bigint  not null,
    constraint denylist_pk primary key (token)
);

create unique index if not exists denylist_token_uindex
    on denylist (token);

---

create table if not exists "queue_properties"
(
    queue_id                   varchar(26)               not null,
    queue_name                 text                      not null,
    created_at                 timestamptz default now() not null,
    gc_at                      timestamptz default now() not null,
    retention_period_seconds   integer                   not null,
    visibility_timeout_seconds integer                   not null,
    max_receive_attempts       integer                   not null,
    drop_policy                integer     default 0     not null,
    dead_letter_queue_id       varchar(26),

    constraint queue_pk primary key (queue_id)
);

create unique index if not exists queue_id_uindex
    on queue_properties (queue_id);

create unique index if not exists queue_name_uindex
    on queue_properties (queue_name);

create index if not exists queue_props_created_at_index
    on queue_properties (created_at);
