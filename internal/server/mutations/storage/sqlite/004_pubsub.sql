create table if not exists "topic_properties"
(
    topic_id   varchar(26)                         not null,
    topic_name text                                not null,
    created_at timestamp default current_timestamp not null,

    constraint topic_pk primary key (topic_id)
);

create unique index if not exists topic_id_uindex
    on topic_properties (topic_id);

create unique index if not exists topic_name_uindex
    on topic_properties (topic_name);

create table if not exists "topic_subscriptions"
(
    subscription_id varchar(26)                         not null,
    topic_id        varchar(26)                         not null,
    queue_id        varchar(26)                         not null,
    created_at      timestamp default current_timestamp not null,

    constraint topic_subscription_pk primary key (subscription_id),
    constraint topic_subscription_topic_fk foreign key (topic_id) references topic_properties (topic_id) on delete cascade,
    constraint topic_subscription_queue_fk foreign key (queue_id) references queue_properties (queue_id) on delete cascade
);

create unique index if not exists topic_subscriptions_topic_queue_uindex
    on topic_subscriptions (topic_id, queue_id);
