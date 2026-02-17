package litestore

import (
	"fmt"
	"strconv"
	"time"

	v1 "github.com/plainq/plainq/internal/server/schema/v1"
	"github.com/valyala/fasttemplate"
)

const (
	// sTag and eTag represents the fasttemplate start and end template tags.
	sTag, eTag = "{{", "}}"

	// queuePropsTable holds the name of the table with queue properties.
	queuePropsTable = "queue_properties"

	// querySelectQueueForGC returns queue_id from the queuePropsTable.
	querySelectQueueForGC = `select queue_id from queue_properties ` +
		`where gc_at < datetime('now', '{{gcTimeout}}') order by gc_at limit {{limit}} offset {{offset}};`

	// queryUpdateQueueAfterGC updates the gc_at in the queuePropsTable for given queue_id.
	queryUpdateQueueAfterGC = `update queue_properties set gc_at = current_timestamp where queue_id = ?;`

	// queryInsertQueuePropRecord creates a record in the queuePropsTable.
	queryInsertQueuePropRecord = `insert into queue_properties 
    (
		queue_id, 
    	queue_name, 
        retention_period_seconds, 
        visibility_timeout_seconds, 
        max_receive_attempts, 
        drop_policy, 
        dead_letter_queue_id
    ) 
	values (?, ?, ?, ?, ?, ?, ?);
	`

	// queryDeleteQueuePropRecord deletes records from the queuePropsTable for given queue_id.
	queryDeleteQueuePropRecord = `delete from queue_properties where queue_id = ?;`
)

type querier struct {
	tSelectQueuesForGC *fasttemplate.Template
}

func newQuerier() querier {
	q := querier{
		tSelectQueuesForGC: fasttemplate.New(querySelectQueueForGC, sTag, eTag),
	}

	return q
}

func (q *querier) selectQueuesForGC(gcTimeout time.Duration, limit, offset uint64) string {
	defer func() {
		if err := q.tSelectQueuesForGC.Reset(querySelectQueueForGC, sTag, eTag); err != nil {
			panic(fmt.Errorf("reset %q template: %w", querySelectQueueForGC, err))
		}
	}()

	sec := strconv.FormatFloat(gcTimeout.Seconds(), 'f', 0, 64)

	query := q.tSelectQueuesForGC.ExecuteString(map[string]any{
		"gcTimeout": "-" + sec + " seconds",
		"limit":     limit,
		"offset":    offset,
	})

	return query
}

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
	q := `insert into ` + queueID + ` (msg_id, msg_body) values (?, ?);`

	return q
}

func queryDeleteQueueTable(queueID string) string {
	q := `drop table ` + queueID + `;`

	return q
}

func querySelectMessages(queueID string) string {
	q := `select msg_id, msg_body from ` + queueID +
		` where visible_at <= current_timestamp and retries <= ? order by created_at limit ?;`

	return q
}

func queryUpdateMessages(queueID string) string {
	q := `update ` + queueID + ` set visible_at = ?, retries = retries + 1 where msg_id = ?;`

	return q
}

func queryDeleteMessage(queueID string) string {
	q := `delete from ` + queueID + ` where msg_id = ?;`

	return q
}

func queryPurgeQueue(queueID string) string {
	q := `delete from ` + queueID + `;`

	return q
}

func queryCountMessages(queueID string) string {
	q := `select count(*) from ` + queueID + `;`

	return q
}

func queryDropMessages(queueID string) string {
	q := `delete from ` + queueID + ` where retries >= ? or datetime(created_at, '+? seconds') <= current_timestamp;`

	return q
}

func querySelectMoveToDLQ(queueID string) string {
	q := `select * from ` + queueID + ` where retries >= ? or datetime(created_at, '+? seconds') <= current_timestamp;`

	return q
}

func queueDescribeQueueProps(where string) string {
	q := `select * from ` + queuePropsTable + ` where ` + where + `;`

	return q
}

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

	q := fmt.Sprintf(`select * from queue_properties %s order by %s %s limit %d;`, where, orderByStr, sortByStr, pageSize)

	return q
}
