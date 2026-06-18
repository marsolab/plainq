package pgstore

import (
	"fmt"

	"github.com/jackc/pgx/v5"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
)

// quoteIdent quotes a SQL identifier for safe interpolation into a query.
// Queue IDs are XID-format (20-char base32, lowercase alphanumeric), but the
// PostgreSQL parser rejects unquoted identifiers that begin with a digit, so
// we unconditionally quote.
func quoteIdent(id string) string {
	return pgx.Identifier{id}.Sanitize()
}

// queryCreateQueueTable returns PostgreSQL DDL that provisions the per-queue
// message table. Each queue lives in its own table so DROP TABLE on purge /
// delete is O(metadata); that property is why plainq uses table-per-queue
// instead of a unified messages table.
func queryCreateQueueTable(queueID string) string {
	ident := quoteIdent(queueID)

	return fmt.Sprintf(`
		CREATE TABLE %[1]s (
			msg_id     text                      NOT NULL,
			msg_body   bytea                     NOT NULL,
			created_at timestamptz DEFAULT now() NOT NULL,
			visible_at timestamptz DEFAULT now() NOT NULL,
			retries    integer     DEFAULT 0     NOT NULL,
			CONSTRAINT %[2]s PRIMARY KEY (msg_id)
		);
		CREATE INDEX %[3]s ON %[1]s (created_at);
		CREATE INDEX %[4]s ON %[1]s (visible_at);
	`, ident,
		quoteIdent(queueID+"_queue_pk"),
		quoteIdent(queueID+"_created_at_index"),
		quoteIdent(queueID+"_visible_at_index"),
	)
}

func queryInsertMessages(queueID string) string {
	return fmt.Sprintf(`INSERT INTO %s (msg_id, msg_body) VALUES ($1, $2);`, quoteIdent(queueID))
}

func queryDeleteQueueTable(queueID string) string {
	return fmt.Sprintf(`DROP TABLE %s;`, quoteIdent(queueID))
}

func querySelectMessages(queueID string) string {
	return fmt.Sprintf(
		`SELECT msg_id, msg_body FROM %s WHERE visible_at <= now() AND retries <= $1 ORDER BY created_at LIMIT $2;`,
		quoteIdent(queueID),
	)
}

func queryUpdateMessages(queueID string) string {
	return fmt.Sprintf(
		`UPDATE %s SET visible_at = $1, retries = retries + 1 WHERE msg_id = $2;`,
		quoteIdent(queueID),
	)
}

func queryDeleteMessage(queueID string) string {
	return fmt.Sprintf(`DELETE FROM %s WHERE msg_id = $1;`, quoteIdent(queueID))
}

func queryPurgeQueue(queueID string) string {
	return fmt.Sprintf(`DELETE FROM %s;`, quoteIdent(queueID))
}

func queryCountMessages(queueID string) string {
	return fmt.Sprintf(`SELECT count(*) FROM %s;`, quoteIdent(queueID))
}

func queryDropMessages(queueID string) string {
	// $1 = max_receive_attempts, $2 = retention_period_seconds (int).
	return fmt.Sprintf(
		`DELETE FROM %s WHERE retries >= $1 OR created_at + make_interval(secs => $2) <= now();`,
		quoteIdent(queueID),
	)
}

func querySelectMoveToDLQ(queueID string) string {
	return fmt.Sprintf(
		`SELECT msg_id, msg_body FROM %s WHERE retries >= $1 OR created_at + make_interval(secs => $2) <= now();`,
		quoteIdent(queueID),
	)
}

// queryListQueues builds a dynamic-ORDER-BY cursor-paginated SELECT on
// queue_properties. sqlc cannot generate this because the ORDER BY column
// and sort direction are runtime inputs.
func queryListQueues(pageSize int32, cursor string, orderBy v1.ListQueuesRequest_OrderBy, sortBy v1.ListQueuesRequest_SortBy) string {
	orderByStr := "queue_id"
	sortByStr := "desc"
	where := ""

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
			where = fmt.Sprintf("WHERE %s > '%s'", orderByStr, cursor)
		}

	case v1.ListQueuesRequest_SORT_BY_DESC:
		sortByStr = "desc"

		if cursor != "" {
			where = fmt.Sprintf("WHERE %s < '%s'", orderByStr, cursor)
		}
	}

	return fmt.Sprintf(
		`SELECT queue_id, queue_name, created_at, gc_at, retention_period_seconds,
		        visibility_timeout_seconds, max_receive_attempts, drop_policy, dead_letter_queue_id
		   FROM queue_properties %s ORDER BY %s %s LIMIT %d;`,
		where, orderByStr, sortByStr, pageSize,
	)
}
