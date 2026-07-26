package litestore

import (
	"context"
	"time"

	"github.com/marsolab/plainq/internal/server/service/queue"
)

// sqliteTimeLayout is how a timestamp is written into a SQLite column.
//
// SQLite has no date type: `current_timestamp` writes the text
// `2006-01-02 15:04:05` and every comparison on these columns is therefore a
// string comparison. Binding a Go time.Time directly produces
// `2006-01-02 15:04:05.999999999+00:00` — same prefix, different tail — so
// rows written the two ways sort against each other by accident rather than by
// design. Writing this layout, in UTC, with a fixed number of fractional
// digits, keeps the ordering lexicographic and therefore chronological.
const sqliteTimeLayout = "2006-01-02 15:04:05.000"

// sqliteTime renders t the way the storage layer writes timestamps.
func sqliteTime(t time.Time) string { return t.UTC().Format(sqliteTimeLayout) }

// writeTime returns the timestamp this write should record, as SQLite text.
// Under replication it is the instant the leader stamped on the command; on a
// standalone node it is the local clock.
func writeTime(ctx context.Context) string { return sqliteTime(queue.WriteTime(ctx)) }
