package litestore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/marsolab/servekit/errkit"
)

func TestStoragePublishMissingTopic(t *testing.T) {
	ctx := context.Background()
	conn, err := litekit.New(filepath.Join(t.TempDir(), "plainq.db"))
	if err != nil {
		t.Fatalf("open litekit connection: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Fatalf("close connection: %v", err)
		}
	})
	setupPubSubTables(t, ctx, conn)

	storage, err := New(conn)
	if err != nil {
		t.Fatalf("create storage: %v", err)
	}
	t.Cleanup(func() {
		if err := storage.Close(); err != nil {
			t.Fatalf("close storage: %v", err)
		}
	})

	_, err = storage.Publish(ctx, "missing-topic-id", &queue.PublishRequest{
		Messages: []queue.PublishMessage{{Body: []byte("hello")}},
	})
	if !errors.Is(err, errkit.ErrNotFound) {
		t.Fatalf("publish missing topic error = %v, want %v", err, errkit.ErrNotFound)
	}
}

func setupPubSubTables(t *testing.T, ctx context.Context, conn *litekit.Conn) {
	t.Helper()

	const schema = `
create table if not exists "queue_properties"
(
    queue_id                   varchar(26)                         not null,
    queue_name                 text                                not null,
    created_at                 timestamp default current_timestamp not null,
    gc_at                      timestamp default current_timestamp not null,
    retention_period_seconds   integer                             not null,
    visibility_timeout_seconds integer                             not null,
    max_receive_attempts       integer                             not null,
    drop_policy                integer   default 0                 not null,
    dead_letter_queue_id       varchar(26),

    constraint queue_pk primary key (queue_id)
);

create table if not exists "topic_properties"
(
    topic_id   varchar(26)                         not null,
    topic_name text                                not null,
    created_at timestamp default current_timestamp not null,

    constraint topic_pk primary key (topic_id)
);

create table if not exists "topic_subscriptions"
(
    subscription_id varchar(26)                         not null,
    topic_id        varchar(26)                         not null,
    queue_id        varchar(26)                         not null,
    created_at      timestamp default current_timestamp not null,

    constraint topic_subscription_pk primary key (subscription_id)
);
`

	if _, err := conn.ExecContext(ctx, schema); err != nil {
		t.Fatalf("setup pubsub tables: %v", err)
	}
}
