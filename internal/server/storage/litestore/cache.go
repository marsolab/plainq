package litestore

import (
	"container/list"
	"fmt"
	"sync"
	"time"

	"github.com/cockroachdb/swiss"
	v1 "github.com/plainq/plainq/internal/server/schema/v1"
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

	byID   *swiss.Map[string, *list.Element]
	byName *swiss.Map[string, *list.Element]
	props  *list.List
}

// NewQueuePropsCache returns a pointer to a new instance of QueuePropsCache.
func NewQueuePropsCache(size uint64) *QueuePropsCache {
	cacheSize := size
	if cacheSize == 0 {
		cacheSize = queuePropsCacheSize
	}

	cache := QueuePropsCache{
		size:   cacheSize,
		byID:   swiss.New[string, *list.Element](int(size)), //nolint:gosec // G115: size is bounded by queuePropsCacheSize (1000)
		byName: swiss.New[string, *list.Element](int(size)), //nolint:gosec // G115: size is bounded by queuePropsCacheSize (1000)
		props:  list.New(),
	}

	return &cache
}

func (c *QueuePropsCache) getByID(id string) (QueueProps, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	v, cached := c.byID.Get(id)
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

	v, cached := c.byName.Get(name)
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

func (c *QueuePropsCache) put(props QueueProps) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.props.Len() == int(c.size) { //nolint:gosec // G115: size is bounded by queuePropsCacheSize (1000)
		c.props.Remove(c.props.Back())
	}

	entry := c.props.PushBack(props)
	c.byID.Put(props.ID, entry)
	c.byName.Put(props.Name, entry)
}

func (c *QueuePropsCache) delete(id, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.byID.Get(id)
	if !ok {
		return
	}

	c.props.Remove(e)
	c.byID.Delete(id)
	c.byName.Delete(name)
}

func propsToProto(p QueueProps) *v1.DescribeQueueResponse {
	response := v1.DescribeQueueResponse{
		QueueId:                  p.ID,
		QueueName:                p.Name,
		CreatedAt:                timestamppb.New(p.CreatedAt.UTC()),
		RetentionPeriodSeconds:   p.RetentionPeriodSeconds,
		VisibilityTimeoutSeconds: p.VisibilityTimeoutSeconds,
		MaxReceiveAttempts:       p.MaxReceiveAttempts,
		EvictionPolicy:           v1.EvictionPolicy(p.EvictionPolicy), //nolint:gosec // G115: EvictionPolicy values are small enum constants
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
		EvictionPolicy:           uint32(p.EvictionPolicy), //nolint:gosec // G115: EvictionPolicy values are small enum constants
		DeadLetterQueueID:        p.DeadLetterQueueId,
	}

	return props
}
