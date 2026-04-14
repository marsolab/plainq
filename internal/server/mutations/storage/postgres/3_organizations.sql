create table if not exists "organizations"
(
    org_id     varchar(26)               not null,
    org_code   text                      not null,
    org_name   text                      not null,
    org_domain text,
    is_active  boolean     default true  not null,
    created_at timestamptz default now() not null,
    updated_at timestamptz default now() not null,

    constraint organizations_pk primary key (org_id)
);

create unique index if not exists organizations_code_uindex on organizations (org_code);
create index if not exists organizations_domain_index on organizations (org_domain);

---

create table if not exists "teams"
(
    team_id     varchar(26)               not null,
    org_id      varchar(26)               not null,
    team_name   text                      not null,
    team_code   text                      not null,
    description text,
    is_active   boolean     default true  not null,
    created_at  timestamptz default now() not null,
    updated_at  timestamptz default now() not null,

    constraint teams_pk primary key (team_id),
    constraint teams_org_fk foreign key (org_id) references organizations (org_id) on delete cascade
);

create unique index if not exists teams_org_code_uindex on teams (org_id, team_code);
create index if not exists teams_org_index on teams (org_id);

---

alter table users add column if not exists org_id         varchar(26);
alter table users add column if not exists oauth_provider text;
alter table users add column if not exists oauth_sub      text;
alter table users add column if not exists last_sync_at   timestamptz;
alter table users add column if not exists is_oauth_user  boolean default false not null;

create index if not exists users_org_index on users (org_id);
create index if not exists users_oauth_index on users (oauth_provider, oauth_sub);

---

create table if not exists "user_teams"
(
    user_id    varchar(26)               not null,
    team_id    varchar(26)               not null,
    created_at timestamptz default now() not null,

    constraint user_teams_pk primary key (user_id, team_id),
    constraint user_teams_user_fk foreign key (user_id) references users (user_id) on delete cascade,
    constraint user_teams_team_fk foreign key (team_id) references teams (team_id) on delete cascade
);

---

create table if not exists "team_roles"
(
    team_id    varchar(26)               not null,
    role_id    varchar(26)               not null,
    created_at timestamptz default now() not null,

    constraint team_roles_pk primary key (team_id, role_id),
    constraint team_roles_team_fk foreign key (team_id) references teams (team_id) on delete cascade,
    constraint team_roles_role_fk foreign key (role_id) references roles (role_id) on delete cascade
);

---

create table if not exists "org_queue_permissions"
(
    org_id      varchar(26)               not null,
    queue_id    varchar(26)               not null,
    role_id     varchar(26)               not null,
    can_send    boolean     default false not null,
    can_receive boolean     default false not null,
    can_purge   boolean     default false not null,
    can_delete  boolean     default false not null,
    created_at  timestamptz default now() not null,
    updated_at  timestamptz default now() not null,

    constraint org_queue_permissions_pk primary key (org_id, queue_id, role_id),
    constraint org_queue_permissions_org_fk foreign key (org_id) references organizations (org_id) on delete cascade,
    constraint org_queue_permissions_queue_fk foreign key (queue_id) references queue_properties (queue_id) on delete cascade,
    constraint org_queue_permissions_role_fk foreign key (role_id) references roles (role_id) on delete cascade
);

---

create table if not exists "team_queue_permissions"
(
    team_id     varchar(26)               not null,
    queue_id    varchar(26)               not null,
    can_send    boolean     default false not null,
    can_receive boolean     default false not null,
    can_purge   boolean     default false not null,
    can_delete  boolean     default false not null,
    created_at  timestamptz default now() not null,
    updated_at  timestamptz default now() not null,

    constraint team_queue_permissions_pk primary key (team_id, queue_id),
    constraint team_queue_permissions_team_fk foreign key (team_id) references teams (team_id) on delete cascade,
    constraint team_queue_permissions_queue_fk foreign key (queue_id) references queue_properties (queue_id) on delete cascade
);

---

create table if not exists "oauth_providers"
(
    provider_id   varchar(26)               not null,
    provider_name text                      not null,
    org_id        varchar(26),
    config_json   text                      not null,
    is_active     boolean     default true  not null,
    created_at    timestamptz default now() not null,
    updated_at    timestamptz default now() not null,

    constraint oauth_providers_pk primary key (provider_id),
    constraint oauth_providers_org_fk foreign key (org_id) references organizations (org_id) on delete cascade
);

create unique index if not exists oauth_providers_name_org_uindex on oauth_providers (provider_name, org_id);

---

insert into organizations (org_id, org_code, org_name, org_domain)
values ('01HQ5RJNXS6TPXK89PQWY4N8JH', 'default', 'Default Organization', null)
on conflict (org_id) do nothing;

---

insert into teams (team_id, org_id, team_name, team_code, description)
values ('01HQ5RJNXS6TPXK89PQWY4N8JI', '01HQ5RJNXS6TPXK89PQWY4N8JH', 'Administrators', 'admin', 'System administrators'),
       ('01HQ5RJNXS6TPXK89PQWY4N8JJ', '01HQ5RJNXS6TPXK89PQWY4N8JH', 'Developers', 'dev', 'Development team'),
       ('01HQ5RJNXS6TPXK89PQWY4N8JK', '01HQ5RJNXS6TPXK89PQWY4N8JH', 'Operations', 'ops', 'Operations team')
on conflict (team_id) do nothing;

---

insert into team_roles (team_id, role_id)
values ('01HQ5RJNXS6TPXK89PQWY4N8JI', '01HQ5RJNXS6TPXK89PQWY4N8JD'),
       ('01HQ5RJNXS6TPXK89PQWY4N8JJ', '01HQ5RJNXS6TPXK89PQWY4N8JE'),
       ('01HQ5RJNXS6TPXK89PQWY4N8JK', '01HQ5RJNXS6TPXK89PQWY4N8JF')
on conflict (team_id, role_id) do nothing;
