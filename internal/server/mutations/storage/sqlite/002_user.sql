create table if not exists "users"
(
    user_id          varchar(26)                         not null,
    email            text                                not null,
    password         text                                not null,
    verified         boolean   default false             not null,
    created_at       timestamp default current_timestamp not null,
    updated_at       timestamp default current_timestamp not null,

    constraint users_pk
        primary key (user_id)
);

create unique index if not exists users_user_id_uindex
    on users (user_id);

create unique index if not exists users_email_uindex
    on users (email);

create table if not exists "roles"
(
    role_id    varchar(26)                         not null,
    role_name  text                                not null,
    created_at timestamp default current_timestamp not null,

    constraint roles_pk
        primary key (role_id)
);

create unique index if not exists roles_name_uindex
    on roles (role_name);

-- User roles mapping
create table if not exists "user_roles"
(
    user_id    varchar(26)                         not null,
    role_id    varchar(26)                         not null,
    created_at timestamp default current_timestamp not null,

    constraint user_roles_pk
        primary key (user_id, role_id),
        
    constraint user_roles_user_fk
        foreign key (user_id) references users (user_id)
            on delete cascade,
    constraint user_roles_role_fk
        foreign key (role_id) references roles (role_id)
            on delete cascade
);

-- Queue permissions table
create table if not exists "queue_permissions"
(
    queue_id   varchar(26)                         not null,
    role_id    varchar(26)                         not null,
    can_send   boolean   default false             not null,
    can_receive boolean   default false            not null,
    can_purge  boolean   default false            not null,
    can_delete boolean   default false            not null,
    created_at timestamp default current_timestamp not null,
    updated_at timestamp default current_timestamp not null,

    constraint queue_permissions_pk
        primary key (queue_id, role_id),
    constraint queue_permissions_queue_fk
        foreign key (queue_id) references queue_properties (queue_id)
            on delete cascade,
    constraint queue_permissions_role_fk
        foreign key (role_id) references roles (role_id)
            on delete cascade
);

-- Insert default roles
insert into roles (role_id, role_name)
values ('01HQ5RJNXS6TPXK89PQWY4N8JD', 'admin'),
       ('01HQ5RJNXS6TPXK89PQWY4N8JE', 'producer'),
       ('01HQ5RJNXS6TPXK89PQWY4N8JF', 'consumer');

-- No default admin user - onboarding process will handle initial admin creation
