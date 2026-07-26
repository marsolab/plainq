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
//
// The created_at index carries msg_id as well, matching the (created_at,
// msg_id) order a receive claims messages in. Indexing created_at alone would
// leave SQLite to sort every candidate row before applying the LIMIT.
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
			on ` + queueID + ` (created_at, msg_id);

		create index if not exists ` + queueID + `_visible_at_index
			on ` + queueID + `(visible_at);
	`

	return q
}

// queryInsertMessages inserts one message with every timestamp supplied. It
// backs the dead-letter move, which reproduces a message rather than creating
// one, so its timestamps are never a column default.
func queryInsertMessages(queueID string) string {
	return `insert into ` + queueID + ` (msg_id, msg_body, created_at, visible_at) values (?, ?, ?, ?);`
}

// queryInsertMessagesBatch builds a single multi-row INSERT for n messages so
// an entire Send batch is one statement (and one trip through SQLite's
// single-writer lock) instead of n.
//
// A replicated write stamps its own timestamps: a column default reads the
// node's own clock, and two replicas applying the same Send would then
// disagree about when the message arrived. A standalone write leaves them to
// the default, because writing them costs two extra values per row — per
// message, per index entry — and buys a single node nothing.
//
// Args are (msg_id, msg_body) pairs, or (msg_id, msg_body, created_at,
// visible_at) tuples when stamped.
func queryInsertMessagesBatch(queueID string, n int, stamped bool) string {
	columns, row := `(msg_id, msg_body) values `, "(?,?)"
	if stamped {
		columns, row = `(msg_id, msg_body, created_at, visible_at) values `, "(?,?,?,?)"
	}

	var b strings.Builder

	b.WriteString(`insert into ` + queueID + ` ` + columns)

	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}

		b.WriteString(row)
	}

	b.WriteString(";")

	return b.String()
}

func queryDeleteQueueTable(queueID string) string {
	return `drop table ` + queueID + `;`
}

// queryStampQueueTimestamps overwrites the creation timestamps a column
// default filled in from the local clock. Placeholders: created_at, gc_at,
// queue id.
func queryStampQueueTimestamps() string {
	return `update queue_properties set created_at = ?, gc_at = ? where queue_id = ?;`
}

// queryStampQueueGCAt records when a queue was last swept, with an explicit
// instant rather than current_timestamp. Placeholders: gc_at, queue id.
func queryStampQueueGCAt() string {
	return `update queue_properties set gc_at = ? where queue_id = ?;`
}

// querySelectMessages claims the next visible batch. The visibility instant is
// a bind parameter rather than SQLite's current_timestamp so a replicated
// Receive selects the same rows on every node, and the tie-break on msg_id
// makes the order total — ordering by created_at alone leaves rows written in
// the same millisecond to the storage engine's discretion.
//
// retries comes back with the row because a non-zero count means this delivery
// is a redelivery — a message whose previous consumer never acknowledged it.
// That is the difference between consumers being busy and consumers being
// broken, and it is not visible anywhere else.
// Placeholders: now, max retries, limit.
func querySelectMessages(queueID string) string {
	return `select msg_id, msg_body, retries from ` + queueID +
		` where visible_at <= ? and retries <= ? order by created_at, msg_id limit ?;`
}

// queryPeekMessages reads a window of messages oldest-first WITHOUT touching
// visibility or retry count — it is a pure read used by the admin browser. The
// in_flight flag reuses the same `visible_at > current_timestamp` predicate as
// Receive so a peek reports exactly the rows a receiver would (not) see. The
// created_at index already backs the ORDER BY. Placeholders: limit, offset.
func queryPeekMessages(queueID string) string {
	return `select msg_id, msg_body, cast(created_at as text), cast(visible_at as text), retries, ` +
		`(visible_at > current_timestamp) from ` + queueID +
		` order by created_at limit ? offset ?;`
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

// queryDropMessages evicts messages that exhausted their retries or outlived
// their retention. Placeholders: max retries, retention cutoff.
//
// The cutoff is computed by the caller and bound as a value. The previous
// shape — `datetime(created_at, '+? seconds') <= current_timestamp` — put the
// placeholder inside a string literal, so SQLite read it as the literal text
// "+? seconds", datetime() returned NULL, and the retention half of this
// predicate never matched a single row.
func queryDropMessages(queueID string) string {
	return `delete from ` + queueID + ` where retries >= ? or created_at <= ?;`
}

// querySelectMoveToDLQ selects the same rows queryDropMessages would delete,
// for the dead-letter path. Placeholders: max retries, retention cutoff.
//
// The columns are listed rather than selected with `*`: the caller scans three
// values, and a `select *` on this table hands back five.
func querySelectMoveToDLQ(queueID string) string {
	return `select msg_id, msg_body, cast(created_at as text) from ` + queueID +
		` where retries >= ? or created_at <= ?;`
}

// queryDeleteMessagesNoReturning removes a batch of ids without reporting
// which ones existed. The dead-letter path already knows — it just read them.
func queryDeleteMessagesNoReturning(queueID string, n int) string {
	return `delete from ` + queueID + ` where msg_id in (` + placeholders(n) + `);`
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
