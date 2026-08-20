-- Organizations table
create table if not exists "organizations"
(
    org_id      varchar(26)                         not null,
    org_code    text                                not null, -- Short code like "acme", "example-corp"
    org_name    text                                not null, -- Display name like "Acme Corporation"
    org_domain  text,                                         -- Domain for email-based org assignment
    is_active   boolean   default true              not null,
    created_at  timestamp default current_timestamp not null,
    updated_at  timestamp default current_timestamp not null,

    constraint organizations_pk primary key (org_id)
);

create unique index if not exists organizations_code_uindex on organizations (org_code);
create index if not exists organizations_domain_index on organizations (org_domain);

-- Teams table
create table if not exists "teams"
(
    team_id     varchar(26)                         not null,
    org_id      varchar(26)                         not null,
    team_name   text                                not null,
    team_code   text                                not null, -- Short code like "dev", "ops", "marketing"
    description text,
    is_active   boolean   default true              not null,
    created_at  timestamp default current_timestamp not null,
    updated_at  timestamp default current_timestamp not null,

    constraint teams_pk primary key (team_id),
    constraint teams_org_fk foreign key (org_id) references organizations (org_id) on delete cascade
);

create unique index if not exists teams_org_code_uindex on teams (org_id, team_code);
create index if not exists teams_org_index on teams (org_id);

-- Update users table to support organizations and OAuth
alter table users add column org_id varchar(26);
alter table users add column oauth_provider text;
alter table users add column oauth_sub text; -- OAuth subject identifier
alter table users add column last_sync_at timestamp;
alter table users add column is_oauth_user boolean default false not null;

create index if not exists users_org_index on users (org_id);
create index if not exists users_oauth_index on users (oauth_provider, oauth_sub);

-- User teams mapping
create table if not exists "user_teams"
(
    user_id    varchar(26)                         not null,
    team_id    varchar(26)                         not null,
    created_at timestamp default current_timestamp not null,

    constraint user_teams_pk primary key (user_id, team_id),
    constraint user_teams_user_fk foreign key (user_id) references users (user_id) on delete cascade,
    constraint user_teams_team_fk foreign key (team_id) references teams (team_id) on delete cascade
);

-- Team roles mapping (teams can have roles assigned)
create table if not exists "team_roles"
(
    team_id    varchar(26)                         not null,
    role_id    varchar(26)                         not null,
    created_at timestamp default current_timestamp not null,

    constraint team_roles_pk primary key (team_id, role_id),
    constraint team_roles_team_fk foreign key (team_id) references teams (team_id) on delete cascade,
    constraint team_roles_role_fk foreign key (role_id) references roles (role_id) on delete cascade
);

-- Organization-scoped queue permissions
create table if not exists "org_queue_permissions"
(
    org_id      varchar(26)                         not null,
    queue_id    varchar(26)                         not null,
    role_id     varchar(26)                         not null,
    can_send    boolean   default false             not null,
    can_receive boolean   default false             not null,
    can_purge   boolean   default false             not null,
    can_delete  boolean   default false             not null,
    created_at  timestamp default current_timestamp not null,
    updated_at  timestamp default current_timestamp not null,

    constraint org_queue_permissions_pk primary key (org_id, queue_id, role_id),
    constraint org_queue_permissions_org_fk foreign key (org_id) references organizations (org_id) on delete cascade,
    constraint org_queue_permissions_queue_fk foreign key (queue_id) references queue_properties (queue_id) on delete cascade,
    constraint org_queue_permissions_role_fk foreign key (role_id) references roles (role_id) on delete cascade
);

-- Team-scoped queue permissions (optional, for fine-grained control)
create table if not exists "team_queue_permissions"
(
    team_id     varchar(26)                         not null,
    queue_id    varchar(26)                         not null,
    can_send    boolean   default false             not null,
    can_receive boolean   default false             not null,
    can_purge   boolean   default false             not null,
    can_delete  boolean   default false             not null,
    created_at  timestamp default current_timestamp not null,
    updated_at  timestamp default current_timestamp not null,

    constraint team_queue_permissions_pk primary key (team_id, queue_id),
    constraint team_queue_permissions_team_fk foreign key (team_id) references teams (team_id) on delete cascade,
    constraint team_queue_permissions_queue_fk foreign key (queue_id) references queue_properties (queue_id) on delete cascade
);

-- OAuth provider configurations
create table if not exists "oauth_providers"
(
    provider_id   varchar(26)                         not null,
    provider_name text                                not null, -- "kinde", "auth0", etc.
    org_id        varchar(26),                                  -- null for global providers
    config_json   text                                not null, -- JSON configuration
    is_active     boolean   default true              not null,
    created_at    timestamp default current_timestamp not null,
    updated_at    timestamp default current_timestamp not null,

    constraint oauth_providers_pk primary key (provider_id),
    constraint oauth_providers_org_fk foreign key (org_id) references organizations (org_id) on delete cascade
);

create unique index if not exists oauth_providers_name_org_uindex on oauth_providers (provider_name, org_id);

-- Insert default organization for single-tenant setups
insert or ignore into organizations (org_id, org_code, org_name, org_domain)
values ('01HQ5RJNXS6TPXK89PQWY4N8JH', 'default', 'Default Organization', null);

-- Insert default teams
insert or ignore into teams (team_id, org_id, team_name, team_code, description)
values 
    ('01HQ5RJNXS6TPXK89PQWY4N8JI', '01HQ5RJNXS6TPXK89PQWY4N8JH', 'Administrators', 'admin', 'System administrators'),
    ('01HQ5RJNXS6TPXK89PQWY4N8JJ', '01HQ5RJNXS6TPXK89PQWY4N8JH', 'Developers', 'dev', 'Development team'),
    ('01HQ5RJNXS6TPXK89PQWY4N8JK', '01HQ5RJNXS6TPXK89PQWY4N8JH', 'Operations', 'ops', 'Operations team');

-- Assign admin role to admin team
insert or ignore into team_roles (team_id, role_id)
values ('01HQ5RJNXS6TPXK89PQWY4N8JI', '01HQ5RJNXS6TPXK89PQWY4N8JD');

-- Assign producer role to dev team
insert or ignore into team_roles (team_id, role_id)
values ('01HQ5RJNXS6TPXK89PQWY4N8JJ', '01HQ5RJNXS6TPXK89PQWY4N8JE');

-- Assign consumer role to ops team
insert or ignore into team_roles (team_id, role_id)
values ('01HQ5RJNXS6TPXK89PQWY4N8JK', '01HQ5RJNXS6TPXK89PQWY4N8JF');