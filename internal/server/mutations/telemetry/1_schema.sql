create table if not exists "schema_version"
(
    id         int       default 0                 not null,
    version    int       default 0                 not null,
    created_at timestamp default current_timestamp not null,
    updated_at timestamp default current_timestamp not null,

    constraint schema_version_pk
        primary key (id)
);

create unique index if not exists id_uindex
    on schema_version (id);

insert or ignore into schema_version (id, version)
values (0, 0);

---

create table if not exists "metrics"
(
    queue_id     text not null,
    metric_name  text not null,
    metric_value real not null,
    timestamp    real not null,
    labels       text not null
);

create index if not exists queue_index
    on metrics (queue_id);

create index if not exists metric_index
    on metrics (metric_name);

create index if not exists timestamp_index
    on metrics (timestamp);





create table if not exists "metrics_5m"
(
    queue_id         text not null,
    metric_name      text not null,
    metric_value_min real not null,
    metric_value_max real not null,
    metric_value_avg real not null,
    timestamp        real not null,
    labels           text not null
);

create index if not exists queue_index
    on metrics_5m (queue_id);

create index if not exists metric_index
    on metrics_5m (metric_name);

create index if not exists timestamp_index
    on metrics_5m (timestamp);
