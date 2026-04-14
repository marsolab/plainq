package litestore

import (
	"fmt"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
)

// queueCreateQueueTable returns SQLite DDL that creates the per-queue message
// table along with its indexes and the updated_at trigger. Each queue lives
// in its own table — DROP TABLE on purge/delete is O(metadata) which matters
// for tail latency under SQLite's single-writer lock.
func queryCreateQueueTable(queueID string) string {
	q := `create table ` + queueID +
		`(
			msg_id     text                                not null,
			msg_body   blob                                not null,
			created_at int 		 default current_timestamp not null,
			visible_at int 		 default current_timestamp not null,
			retries    int       default 0                 not null,

			constraint ` + queueID + `_queue_pk
				primary key (msg_id)
		);

		create index if not exists ` + queueID + `_created_at_index
			on ` + queueID + ` (created_at);

		create index if not exists ` + queueID + `_visible_at_index
			on ` + queueID + `(visible_at);

		create trigger if not exists ` + queueID + `_update_msg_updated_at
			after update on ` + queueID + `
			for each row
		begin
			update ` + queueID + ` set updated_at = current_timestamp where msg_id = old.msg_id;
		end;
	`

	return q
}

func queryInsertMessages(queueID string) string {
	return `insert into ` + queueID + ` (msg_id, msg_body) values (?, ?);`
}

func queryDeleteQueueTable(queueID string) string {
	return `drop table ` + queueID + `;`
}

func querySelectMessages(queueID string) string {
	return `select msg_id, msg_body from ` + queueID +
		` where visible_at <= current_timestamp and retries <= ? order by created_at limit ?;`
}

func queryUpdateMessages(queueID string) string {
	return `update ` + queueID + ` set visible_at = ?, retries = retries + 1 where msg_id = ?;`
}

func queryDeleteMessage(queueID string) string {
	return `delete from ` + queueID + ` where msg_id = ?;`
}

func queryPurgeQueue(queueID string) string {
	return `delete from ` + queueID + `;`
}

func queryCountMessages(queueID string) string {
	return `select count(*) from ` + queueID + `;`
}

func queryDropMessages(queueID string) string {
	return `delete from ` + queueID + ` where retries >= ? or datetime(created_at, '+? seconds') <= current_timestamp;`
}

func querySelectMoveToDLQ(queueID string) string {
	return `select * from ` + queueID + ` where retries >= ? or datetime(created_at, '+? seconds') <= current_timestamp;`
}

// queryListQueues builds a SQLite SELECT for the queue_properties table with
// dynamic ORDER BY and cursor-based WHERE. sqlc cannot generate this shape
// because the ORDER BY column and sort direction are chosen at runtime.
func queryListQueues(pageSize int32, cursor string, orderBy v1.ListQueuesRequest_OrderBy, sortBy v1.ListQueuesRequest_SortBy) string {
	var (
		orderByStr = "queue_id"
		sortByStr  = "desc"
		where      = ""
	)

	switch orderBy {
	case v1.ListQueuesRequest_ORDER_BY_ID:
		orderByStr = "queue_id"

	case v1.ListQueuesRequest_ORDER_BY_NAME:
		orderByStr = "queue_name"

	case v1.ListQueuesRequest_ORDER_BY_CREATED_AT:
		orderByStr = "created_at"
	}

	switch sortBy {
	case v1.ListQueuesRequest_SORT_BY_ASC:
		sortByStr = "asc"

		if cursor != "" {
			where = fmt.Sprintf("where %s > '%s'", orderByStr, cursor)
		}

	case v1.ListQueuesRequest_SORT_BY_DESC:
		sortByStr = "desc"

		if cursor != "" {
			where = fmt.Sprintf("where %s < '%s'", orderByStr, cursor)
		}
	}

	return fmt.Sprintf(`select * from queue_properties %s order by %s %s limit %d;`, where, orderByStr, sortByStr, pageSize)
}
