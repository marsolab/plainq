package litestore

import (
	"testing"

	"github.com/maxatome/go-testdeep/td"
)

func Test_queuePropsCache_list(t *testing.T) {
	tests := map[string]struct {
		setup func(c *QueuePropsCache) *QueuePropsCache
		want  []QueueProps
	}{
		"Empty": {
			setup: func(c *QueuePropsCache) *QueuePropsCache { return c },
			want:  []QueueProps{},
		},

		"Single": {
			setup: func(c *QueuePropsCache) *QueuePropsCache {
				c.put(QueueProps{ID: "1"})
				return c
			},
			want: []QueueProps{
				{ID: "1"},
			},
		},

		"Many": {
			setup: func(c *QueuePropsCache) *QueuePropsCache {
				c.put(QueueProps{ID: "1"})
				c.put(QueueProps{ID: "2"})
				c.put(QueueProps{ID: "3"})
				return c
			},
			want: []QueueProps{
				{ID: "1"}, {ID: "2"}, {ID: "3"},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cache := tc.setup(NewQueuePropsCache(0))
			td.Cmp(t, cache.list(), tc.want)
		})
	}
}
