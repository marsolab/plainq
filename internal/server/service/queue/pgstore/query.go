package pgstore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/shared/pqerr"
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

// queryInsertMessagesBatch builds a single multi-row INSERT for n messages so
// an entire Send batch costs one round trip (and one implicit transaction)
// instead of n sequential INSERTs. Placeholders are laid out as
// ($1,$2),($3,$4),… — callers pass args in (msg_id, msg_body) pairs.
func queryInsertMessagesBatch(queueID string, n int) string {
	var b strings.Builder

	fmt.Fprintf(&b, `INSERT INTO %s (msg_id, msg_body) VALUES `, quoteIdent(queueID))

	for i := range n {
		sep := ""
		if i > 0 {
			sep = ","
		}

		fmt.Fprintf(&b, "%s($%d,$%d)", sep, i*2+1, i*2+2)
	}

	fmt.Fprint(&b, ";")

	return b.String()
}

func queryDeleteQueueTable(queueID string) string {
	return fmt.Sprintf(`DROP TABLE %s;`, quoteIdent(queueID))
}

// queryReceiveMessages atomically claims up to $3 messages in a single round
// trip. The `claimed` CTE picks the oldest visible, under-attempt-limit rows
// with FOR UPDATE SKIP LOCKED so concurrent consumers never block on — or
// fight over — the same rows; the `updated` CTE bumps their visibility
// deadline and retry count. This replaces the previous "SELECT then N× UPDATE"
// pattern, which both did N+1 round trips per call and, lacking row locks,
// handed the same messages to every concurrent receiver (forcing
// serialization-failure retries under SERIALIZABLE).
//
// The final SELECT re-imposes `ORDER BY created_at` because UPDATE … RETURNING
// has no defined row order — without it a batch could surface newer messages
// before older ones.
//
// retries comes back post-increment, so a value above one means the message
// had been delivered before and this is a redelivery.
//
// $1 = new visible_at, $2 = max_receive_attempts, $3 = batch size.
func queryReceiveMessages(queueID string) string {
	ident := quoteIdent(queueID)

	return fmt.Sprintf(`
		WITH claimed AS (
			SELECT msg_id FROM %[1]s
			WHERE visible_at <= now() AND retries < $2
			ORDER BY created_at
			LIMIT $3
			FOR UPDATE SKIP LOCKED
		),
		updated AS (
			UPDATE %[1]s SET visible_at = $1, retries = retries + 1
			WHERE msg_id IN (SELECT msg_id FROM claimed)
			RETURNING msg_id, msg_body, created_at, retries
		)
		SELECT msg_id, msg_body, retries FROM updated ORDER BY created_at;
	`, ident)
}

// queryDeleteMessages deletes every message whose id is in the $1 array in a
// single round trip and RETURNs the ids actually removed, so the caller can
// report found ids as successful and unknown ids as failed without N separate
// DELETEs.
func queryDeleteMessages(queueID string) string {
	return fmt.Sprintf(`DELETE FROM %s WHERE msg_id = ANY($1) RETURNING msg_id;`, quoteIdent(queueID))
}

// queryPeekMessages reads a window of messages oldest-first WITHOUT touching
// visibility or retry count — a pure read for the admin browser. The in_flight
// flag reuses the same `visible_at > now()` predicate as Receive so a peek
// reports exactly the rows a receiver would (not) see. The created_at index
// backs the ORDER BY. $1 = limit, $2 = offset.
func queryPeekMessages(queueID string) string {
	return fmt.Sprintf(
		`SELECT msg_id, msg_body, created_at, visible_at, retries, (visible_at > now()) `+
			`FROM %s ORDER BY created_at LIMIT $1 OFFSET $2;`,
		quoteIdent(queueID),
	)
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

func queryDeleteMessagesNoReturning(queueID string) string {
	return fmt.Sprintf(`DELETE FROM %s WHERE msg_id = ANY($1);`, quoteIdent(queueID))
}

type queueCursor struct {
	Version uint8  `json:"v"`
	Order   int32  `json:"o"`
	Value   string `json:"x"`
	ID      string `json:"id"`
}

func encodeQueueCursor(c queueCursor) string {
	b, err := json.Marshal(c)
	if err != nil {
		panic(fmt.Errorf("marshal queue cursor: %w", err))
	}

	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeQueueCursor(raw string) (queueCursor, error) {
	var c queueCursor

	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return c, fmt.Errorf("%w: invalid queue cursor", pqerr.ErrInvalidInput)
	}

	if err := json.Unmarshal(b, &c); err != nil || c.Version != 1 || c.ID == "" {
		return c, fmt.Errorf("%w: invalid queue cursor", pqerr.ErrInvalidInput)
	}

	return c, nil
}

// queryListQueues allows only the selected order column and direction into
// SQL. Prefixes and decoded cursor values are always PostgreSQL parameters.
func queryListQueues(
	pageSize int32,
	prefix, rawCursor string,
	orderBy v1.ListQueuesRequest_OrderBy,
	sortBy v1.ListQueuesRequest_SortBy,
) (string, []any, error) {
	column, direction := queueOrder(orderBy, sortBy)
	clauses := make([]string, 0, 2)
	args := make([]any, 0, 4)

	if prefix != "" {
		clauses = append(clauses, "queue_name like $1")
		args = append(args, prefix+"%")
	}

	if rawCursor != "" {
		cursor, err := decodeQueueCursor(rawCursor)
		if err != nil || cursor.Order != int32(orderBy) {
			return "", nil, fmt.Errorf("%w: invalid queue cursor", pqerr.ErrInvalidInput)
		}

		value, valueErr := queueCursorValue(cursor.Value, orderBy)
		if valueErr != nil {
			return "", nil, valueErr
		}

		comparison := ">"
		if direction == "desc" {
			comparison = "<"
		}

		position := len(args) + 1
		clauses = append(clauses, fmt.Sprintf("(%[1]s %[2]s $%[3]d OR (%[1]s = $%[4]d AND queue_id %[2]s $%[5]d))", column, comparison, position, position+1, position+2))
		args = append(args, value, value, cursor.ID)
	}

	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}

	args = append(args, pageSize)

	return fmt.Sprintf(
		`SELECT queue_id, queue_name, created_at, gc_at, retention_period_seconds,
		        visibility_timeout_seconds, max_receive_attempts, drop_policy, dead_letter_queue_id
		   FROM queue_properties%s ORDER BY %s %s, queue_id %s LIMIT $%d;`,
		where, column, direction, direction, len(args),
	), args, nil
}

func queryCountQueues(prefix string) (string, []any) {
	if prefix == "" {
		return "SELECT count(*) FROM queue_properties;", nil
	}

	return "SELECT count(*) FROM queue_properties WHERE queue_name LIKE $1;", []any{prefix + "%"}
}

func queueOrder(orderBy v1.ListQueuesRequest_OrderBy, sortBy v1.ListQueuesRequest_SortBy) (string, string) {
	column := "queue_id"
	switch orderBy {
	case v1.ListQueuesRequest_ORDER_BY_NAME:
		column = "queue_name"
	case v1.ListQueuesRequest_ORDER_BY_CREATED_AT:
		column = "created_at"
	}

	direction := "asc"
	if sortBy == v1.ListQueuesRequest_SORT_BY_DESC {
		direction = "desc"
	}

	return column, direction
}

func queueCursorValue(value string, orderBy v1.ListQueuesRequest_OrderBy) (any, error) {
	if orderBy != v1.ListQueuesRequest_ORDER_BY_CREATED_AT {
		return value, nil
	}

	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid queue cursor", pqerr.ErrInvalidInput)
	}

	return parsed.UTC(), nil
}

// queryQueueStats counts a queue's messages and how many of them are claimed
// but not yet visible again.
//
// One pass for both, because the pair is only meaningful read together: a
// depth of a thousand means something different when all of it is in flight.
// The in-flight half is an index range on visible_at.
func queryQueueStats(queueID string) string {
	return fmt.Sprintf(
		`SELECT count(*), count(*) FILTER (WHERE visible_at > now()) FROM %s;`,
		quoteIdent(queueID),
	)
}
