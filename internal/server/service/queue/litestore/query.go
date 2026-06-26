package litestore

import (
	"fmt"
	"strings"

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
	`

	return q
}

func queryInsertMessages(queueID string) string {
	return `insert into ` + queueID + ` (msg_id, msg_body) values (?, ?);`
}

// queryInsertMessagesBatch builds a single multi-row INSERT for n messages so
// an entire Send batch is one statement (and one trip through SQLite's
// single-writer lock) instead of n. Args are passed as (msg_id, msg_body)
// pairs.
func queryInsertMessagesBatch(queueID string, n int) string {
	var b strings.Builder

	b.WriteString(`insert into ` + queueID + ` (msg_id, msg_body) values `)

	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}

		b.WriteString("(?,?)")
	}

	b.WriteString(";")

	return b.String()
}

func queryDeleteQueueTable(queueID string) string {
	return `drop table ` + queueID + `;`
}

func querySelectMessages(queueID string) string {
	return `select msg_id, msg_body from ` + queueID +
		` where visible_at <= current_timestamp and retries <= ? order by created_at limit ?;`
}

// queryUpdateMessagesVisibility bumps visibility deadline and retry count for a
// claimed batch in one statement. The first placeholder is the new visible_at;
// the remaining n placeholders are the claimed message ids. SQLite has no
// SKIP LOCKED, but collapsing the per-message UPDATE loop into a single
// statement minimizes how long the receive holds the single-writer lock.
func queryUpdateMessagesVisibility(queueID string, n int) string {
	return `update ` + queueID + ` set visible_at = ?, retries = retries + 1 where msg_id in (` +
		placeholders(n) + `);`
}

// queryDeleteMessages deletes a batch of ids in one statement and RETURNs the
// ids actually removed so the caller can split successful from unknown ids.
func queryDeleteMessages(queueID string, n int) string {
	return `delete from ` + queueID + ` where msg_id in (` + placeholders(n) + `) returning msg_id;`
}

// placeholders returns "?,?,…" with n bind placeholders for an IN clause.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}

	return strings.Repeat("?,", n-1) + "?"
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

	default:
		// Use default orderByStr ("queue_id").
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

	default:
		// Use default sortByStr ("desc").
	}

	return fmt.Sprintf(`select * from queue_properties %s order by %s %s limit %d;`, where, orderByStr, sortByStr, pageSize)
}
