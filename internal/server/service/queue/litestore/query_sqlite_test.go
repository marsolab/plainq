package litestore

import (
	"database/sql"
	"testing"

	"github.com/maxatome/go-testdeep/td"
)

// openTestDB opens a shared in-memory SQLite database. The sqlite3 driver is
// registered transitively through litekit (imported by the package under
// test), so no direct driver import is needed. MaxOpenConns is pinned to 1 so
// the in-memory database persists across statements.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite3", ":memory:")
	td.Require(t).CmpNoError(err, "open in-memory sqlite")

	db.SetMaxOpenConns(1)

	t.Cleanup(func() { _ = db.Close() })

	return db
}

// Test_queryCreateQueueTable_executes guards the table DDL against a regression
// that previously made the SQLite backend's Receive fail on every non-empty
// receive: an update trigger referenced an updated_at column that the table
// never defined, so any UPDATE raised "no such column: updated_at". This test
// creates a queue table and runs an UPDATE to prove the DDL is self-consistent.
func Test_queryCreateQueueTable_executes(t *testing.T) {
	db := openTestDB(t)

	_, err := db.Exec(queryCreateQueueTable("qtable"))
	td.Require(t).CmpNoError(err, "create queue table")

	_, err = db.Exec(queryInsertMessagesBatch("qtable", 1), "id1", []byte("body"))
	td.Require(t).CmpNoError(err, "insert message")

	_, err = db.Exec(queryUpdateMessagesVisibility("qtable", 1), 1, "id1")
	td.CmpNoError(t, err, "update must not fail on a stray trigger")
}

// Test_messageBatchQueries_roundTrip exercises the full Send/Receive/Delete SQL
// flow against a real SQLite database: a multi-row INSERT, an ordered SELECT, a
// batched visibility UPDATE, and a batched DELETE … RETURNING.
func Test_messageBatchQueries_roundTrip(t *testing.T) {
	db := openTestDB(t)

	const queueID = "qround"

	_, err := db.Exec(queryCreateQueueTable(queueID))
	td.Require(t).CmpNoError(err, "create queue table")

	// Send: one multi-row INSERT for three messages.
	_, err = db.Exec(queryInsertMessagesBatch(queueID, 3),
		"m1", []byte("a"),
		"m2", []byte("b"),
		"m3", []byte("c"),
	)
	td.Require(t).CmpNoError(err, "batch insert")

	// Receive: ordered SELECT then a single batched visibility UPDATE.
	rows, err := db.Query(querySelectMessages(queueID), maxReceiveAttempts, 10)
	td.Require(t).CmpNoError(err, "select messages")

	var ids []string

	for rows.Next() {
		var (
			id   string
			body []byte
		)

		td.Require(t).CmpNoError(rows.Scan(&id, &body), "scan message")

		ids = append(ids, id)
	}

	td.Require(t).CmpNoError(rows.Err())
	td.Require(t).CmpNoError(rows.Close())

	// The ordered SELECT must preserve insertion (created_at) order.
	td.Cmp(t, ids, []string{"m1", "m2", "m3"})

	args := []any{42}
	for _, id := range ids {
		args = append(args, id)
	}

	_, err = db.Exec(queryUpdateMessagesVisibility(queueID, len(ids)), args...)
	td.Require(t).CmpNoError(err, "batched visibility update")

	// Delete: batched DELETE … RETURNING reports only ids that existed.
	delRows, err := db.Query(queryDeleteMessages(queueID, 2), "m1", "missing")
	td.Require(t).CmpNoError(err, "batched delete")

	var deleted []string

	for delRows.Next() {
		var id string

		td.Require(t).CmpNoError(delRows.Scan(&id), "scan deleted id")

		deleted = append(deleted, id)
	}

	td.Require(t).CmpNoError(delRows.Err())
	td.Require(t).CmpNoError(delRows.Close())

	td.Cmp(t, deleted, []string{"m1"}, "only the existing id is returned")
}

// Test_queryPeekMessages_browsesWithoutConsuming proves the peek query returns
// messages oldest-first, flags in-flight rows, and — unlike Receive — leaves
// visibility and retry counts untouched.
func Test_queryPeekMessages_browsesWithoutConsuming(t *testing.T) {
	db := openTestDB(t)

	const queueID = "qpeek"

	_, err := db.Exec(queryCreateQueueTable(queueID))
	td.Require(t).CmpNoError(err, "create queue table")

	_, err = db.Exec(queryInsertMessagesBatch(queueID, 3),
		"m1", []byte("a"),
		"m2", []byte("b"),
		"m3", []byte("c"),
	)
	td.Require(t).CmpNoError(err, "batch insert")

	// Hide m2 far into the future so it reads as in-flight.
	_, err = db.Exec(`update ` + queueID + ` set visible_at = '2999-01-01 00:00:00' where msg_id = 'm2';`)
	td.Require(t).CmpNoError(err, "hide m2")

	type peeked struct {
		id       string
		body     string
		retries  int
		inFlight int
	}

	browse := func(limit, offset int) []peeked {
		rows, qErr := db.Query(queryPeekMessages(queueID), limit, offset)
		td.Require(t).CmpNoError(qErr, "peek query")

		defer func() { _ = rows.Close() }()

		var out []peeked

		for rows.Next() {
			var (
				p                    peeked
				createdAt, visibleAt string
			)

			td.Require(t).CmpNoError(
				rows.Scan(&p.id, &p.body, &createdAt, &visibleAt, &p.retries, &p.inFlight),
				"scan peeked row",
			)

			out = append(out, p)
		}

		td.Require(t).CmpNoError(rows.Err())

		return out
	}

	all := browse(10, 0)
	td.Cmp(t, all, []peeked{
		{id: "m1", body: "a", retries: 0, inFlight: 0},
		{id: "m2", body: "b", retries: 0, inFlight: 1},
		{id: "m3", body: "c", retries: 0, inFlight: 0},
	}, "browse returns all rows oldest-first with the in-flight flag set for m2")

	// limit/offset paginate.
	page := browse(1, 1)
	td.Cmp(t, page, []peeked{{id: "m2", body: "b", retries: 0, inFlight: 1}}, "offset/limit window")

	// A peek must not consume: every row's retry count is still zero and the
	// not-hidden rows are still visible to a real Receive.
	rows, err := db.Query(querySelectMessages(queueID), maxReceiveAttempts, 10)
	td.Require(t).CmpNoError(err, "post-peek receive select")

	var receivable []string

	for rows.Next() {
		var (
			id   string
			body []byte
		)

		td.Require(t).CmpNoError(rows.Scan(&id, &body), "scan receivable")

		receivable = append(receivable, id)
	}

	td.Require(t).CmpNoError(rows.Err())
	td.Require(t).CmpNoError(rows.Close())

	td.Cmp(t, receivable, []string{"m1", "m3"}, "peek left m1/m3 visible and m2 hidden")
}

func Test_placeholders(t *testing.T) {
	td.Cmp(t, placeholders(0), "")
	td.Cmp(t, placeholders(1), "?")
	td.Cmp(t, placeholders(3), "?,?,?")
}
