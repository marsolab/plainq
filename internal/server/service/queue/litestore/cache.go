package litestore

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

// QueuePropsCache represents in in-memory cache
// of QueueProps for each existing queue.
type QueuePropsCache struct {
	mu   sync.RWMutex
	size uint64

	byID   map[string]*list.Element
	byName map[string]*list.Element
	props  *list.List
}

type QueuePropsListOptions struct {
	orderBy v1.ListQueuesRequest_OrderBy
	sortBy  v1.ListQueuesRequest_SortBy
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
	if cached {
		c.props.MoveToFront(v)

		props, ok := v.Value.(QueueProps)
		if !ok {
			panic(fmt.Errorf("invalid type in cache: %#v", v.Value))
		}

		return props, true
	}

	return QueueProps{}, false
}

func (c *QueuePropsCache) getByName(name string) (QueueProps, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	v, cached := c.byName[name]
	if cached {
		c.props.MoveToFront(v)

		props, ok := v.Value.(QueueProps)
		if !ok {
			panic(fmt.Errorf("invalid type in cache: %#v", v.Value))
		}

		return props, true
	}

	return QueueProps{}, false
}

func (c *QueuePropsCache) list() []QueueProps {
	props := make([]QueueProps, len(c.byID))

	listOptions := QueuePropsListOptions{
		orderBy: v1.ListQueuesRequest_ORDER_BY_ID,
		sortBy:  v1.ListQueuesRequest_SORT_BY_ASC,
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	i := 0

	iter := func(k string, e *list.Element) bool {
		v, ok := e.Value.(QueueProps)
		if !ok {
			panic(fmt.Errorf("invalid type in queue props cache: %#v", e.Value))
		}

		props[i].ID = v.ID
		props[i].Name = v.Name
		props[i].VisibilityTimeoutSeconds = v.VisibilityTimeoutSeconds
		props[i].RetentionPeriodSeconds = v.RetentionPeriodSeconds
		props[i].MaxReceiveAttempts = v.MaxReceiveAttempts
		props[i].EvictionPolicy = v.EvictionPolicy
		props[i].DeadLetterQueueID = v.DeadLetterQueueID
		i++

		return true
	}

	for k, v := range c.byID {
		if !iter(k, v) {
			break
		}
	}

	sortProps(props, listOptions)

	return props
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

func sortProps(props []QueueProps, listOptions QueuePropsListOptions) {
	slices.SortFunc[[]QueueProps](props, func(a, b QueueProps) int {
		switch listOptions.orderBy {
		case v1.ListQueuesRequest_ORDER_BY_ID:
			if a.ID == b.ID {
				return 0
			}

			switch listOptions.sortBy {
			case v1.ListQueuesRequest_SORT_BY_ASC:
				return tern.OP[int](a.ID > b.ID, 1, -1)

			case v1.ListQueuesRequest_SORT_BY_DESC:
				return tern.OP[int](a.ID > b.ID, -1, 1)

			default:
				return tern.OP[int](a.ID > b.ID, 1, -1)
			}

		case v1.ListQueuesRequest_ORDER_BY_NAME:
			if a.Name == b.Name {
				return 0
			}

			switch listOptions.sortBy {
			case v1.ListQueuesRequest_SORT_BY_ASC:
				return tern.OP[int](a.Name > b.Name, 1, -1)

			case v1.ListQueuesRequest_SORT_BY_DESC:
				return tern.OP[int](a.Name > b.Name, -1, 1)

			default:
				return tern.OP[int](a.Name > b.Name, 1, -1)
			}

		case v1.ListQueuesRequest_ORDER_BY_CREATED_AT:
			if a.CreatedAt.Equal(b.CreatedAt) {
				return 0
			}

			switch listOptions.sortBy {
			case v1.ListQueuesRequest_SORT_BY_ASC:
				return tern.OP[int](a.CreatedAt.After(b.CreatedAt), 1, -1)

			case v1.ListQueuesRequest_SORT_BY_DESC:
				return tern.OP[int](a.CreatedAt.After(b.CreatedAt), -1, 1)

			default:
				return tern.OP[int](a.CreatedAt.After(b.CreatedAt), 1, -1)
			}

		default:
			if a.ID == b.ID {
				return 0
			}

			switch listOptions.sortBy {
			case v1.ListQueuesRequest_SORT_BY_ASC:
				return tern.OP[int](a.ID > b.ID, 1, -1)

			case v1.ListQueuesRequest_SORT_BY_DESC:
				return tern.OP[int](a.ID > b.ID, -1, 1)

			default:
				return tern.OP[int](a.ID > b.ID, 1, -1)
			}
		}
	})
}

func propsToProto(p QueueProps) *v1.DescribeQueueResponse {
	response := v1.DescribeQueueResponse{
		QueueId:                  p.ID,
		QueueName:                p.Name,
		CreatedAt:                timestamppb.New(p.CreatedAt.UTC()),
		RetentionPeriodSeconds:   p.RetentionPeriodSeconds,
		VisibilityTimeoutSeconds: p.VisibilityTimeoutSeconds,
		MaxReceiveAttempts:       p.MaxReceiveAttempts,
		EvictionPolicy:           v1.EvictionPolicy(p.EvictionPolicy),
		DeadLetterQueueId:        p.DeadLetterQueueID,
	}

	return &response
}

func propsFromProto(p *v1.DescribeQueueResponse) QueueProps {
	props := QueueProps{
		ID:                       p.QueueId,
		Name:                     p.QueueName,
		CreatedAt:                p.CreatedAt.AsTime().UTC(),
		RetentionPeriodSeconds:   p.RetentionPeriodSeconds,
		VisibilityTimeoutSeconds: p.VisibilityTimeoutSeconds,
		MaxReceiveAttempts:       p.MaxReceiveAttempts,
		EvictionPolicy:           uint32(p.EvictionPolicy),
		DeadLetterQueueID:        p.DeadLetterQueueId,
	}

	return props
}
