package pgstore

import (
	"container/list"
	"fmt"
	"slices"
	"sync"
	"time"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/servekit/tern"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// QueueProps represents a cached set of queue properties.
type QueueProps struct {
	ID                       string
	Name                     string
	CreatedAt                time.Time
	RetentionPeriodSeconds   uint64
	VisibilityTimeoutSeconds uint64
	MaxReceiveAttempts       uint32
	EvictionPolicy           uint32
	DeadLetterQueueID        string
}

// QueuePropsCache is an in-memory LRU cache of QueueProps keyed by both id
// and name. Reads are RLock-protected; writes evict the least-recently-used
// entry when capacity is reached.
type QueuePropsCache struct {
	mu   sync.RWMutex
	size uint64

	byID   map[string]*list.Element
	byName map[string]*list.Element
	props  *list.List
}

// NewQueuePropsCache returns a pointer to a new instance of QueuePropsCache.
func NewQueuePropsCache(size uint64) *QueuePropsCache {
	if size == 0 {
		size = queuePropsCacheSize
	}

	cache := QueuePropsCache{
		size:   size,
		byID:   make(map[string]*list.Element, int(size)),
		byName: make(map[string]*list.Element, int(size)),
		props:  list.New(),
	}

	return &cache
}

func (c *QueuePropsCache) getByID(id string) (QueueProps, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	v, cached := c.byID[id]
	if !cached {
		return QueueProps{}, false
	}

	c.props.MoveToFront(v)

	props, ok := v.Value.(QueueProps)
	if !ok {
		panic(fmt.Errorf("invalid type in cache: %#v", v.Value))
	}

	return props, true
}

func (c *QueuePropsCache) getByName(name string) (QueueProps, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	v, cached := c.byName[name]
	if !cached {
		return QueueProps{}, false
	}

	c.props.MoveToFront(v)

	props, ok := v.Value.(QueueProps)
	if !ok {
		panic(fmt.Errorf("invalid type in cache: %#v", v.Value))
	}

	return props, true
}

func (c *QueuePropsCache) put(props QueueProps) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.props.Len() == int(c.size) {
		c.props.Remove(c.props.Back())
	}

	entry := c.props.PushBack(props)
	c.byID[props.ID] = entry
	c.byName[props.Name] = entry
}

func (c *QueuePropsCache) delete(id, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.byID[id]
	if !ok {
		return
	}

	c.props.Remove(e)
	delete(c.byID, id)
	delete(c.byName, name)
}

// sortProps orders a QueueProps slice according to the list options. Kept
// exported for future use but currently unused outside this package.
func sortProps(props []QueueProps, orderBy v1.ListQueuesRequest_OrderBy, sortBy v1.ListQueuesRequest_SortBy) {
	slices.SortFunc(props, func(a, b QueueProps) int {
		switch orderBy {
		case v1.ListQueuesRequest_ORDER_BY_ID:
			if a.ID == b.ID {
				return 0
			}

			if sortBy == v1.ListQueuesRequest_SORT_BY_ASC {
				return tern.OP(a.ID > b.ID, 1, -1)
			}
			return tern.OP(a.ID > b.ID, -1, 1)

		case v1.ListQueuesRequest_ORDER_BY_NAME:
			if a.Name == b.Name {
				return 0
			}

			if sortBy == v1.ListQueuesRequest_SORT_BY_ASC {
				return tern.OP(a.Name > b.Name, 1, -1)
			}
			return tern.OP(a.Name > b.Name, -1, 1)

		case v1.ListQueuesRequest_ORDER_BY_CREATED_AT:
			if a.CreatedAt.Equal(b.CreatedAt) {
				return 0
			}

			if sortBy == v1.ListQueuesRequest_SORT_BY_ASC {
				return tern.OP(a.CreatedAt.After(b.CreatedAt), 1, -1)
			}
			return tern.OP(a.CreatedAt.After(b.CreatedAt), -1, 1)

		default:
			return 0
		}
	})
}

func propsToProto(p QueueProps) *v1.DescribeQueueResponse {
	return &v1.DescribeQueueResponse{
		QueueId:                  p.ID,
		QueueName:                p.Name,
		CreatedAt:                timestamppb.New(p.CreatedAt.UTC()),
		RetentionPeriodSeconds:   p.RetentionPeriodSeconds,
		VisibilityTimeoutSeconds: p.VisibilityTimeoutSeconds,
		MaxReceiveAttempts:       p.MaxReceiveAttempts,
		EvictionPolicy:           v1.EvictionPolicy(p.EvictionPolicy),
		DeadLetterQueueId:        p.DeadLetterQueueID,
	}
}

func propsFromProto(p *v1.DescribeQueueResponse) QueueProps {
	return QueueProps{
		ID:                       p.QueueId,
		Name:                     p.QueueName,
		CreatedAt:                p.CreatedAt.AsTime().UTC(),
		RetentionPeriodSeconds:   p.RetentionPeriodSeconds,
		VisibilityTimeoutSeconds: p.VisibilityTimeoutSeconds,
		MaxReceiveAttempts:       p.MaxReceiveAttempts,
		EvictionPolicy:           uint32(p.EvictionPolicy),
		DeadLetterQueueID:        p.DeadLetterQueueId,
	}
}

// ensure sortProps is reachable for future callers / linters.
var _ = sortProps
