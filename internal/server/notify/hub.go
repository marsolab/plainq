package notify

import (
	"slices"
	"sync"
)

type Hub struct {
	mu      sync.Mutex
	waiters map[string]map[chan struct{}]struct{}
}

type Watch struct {
	ch   chan struct{}
	once sync.Once
	done func()
}

func NewHub() *Hub {
	return &Hub{waiters: make(map[string]map[chan struct{}]struct{})}
}

func (w *Watch) C() <-chan struct{} {
	return w.ch
}

func (w *Watch) Close() {
	w.once.Do(w.done)
}

func (h *Hub) Watch(keys ...string) *Watch {
	keys = slices.Compact(slices.Sorted(slices.Values(keys)))
	ch := make(chan struct{}, 1)

	h.mu.Lock()
	for _, key := range keys {
		if h.waiters[key] == nil {
			h.waiters[key] = make(map[chan struct{}]struct{})
		}

		h.waiters[key][ch] = struct{}{}
	}
	h.mu.Unlock()

	return &Watch{ch: ch, done: func() {
		h.mu.Lock()
		defer h.mu.Unlock()

		for _, key := range keys {
			delete(h.waiters[key], ch)

			if len(h.waiters[key]) == 0 {
				delete(h.waiters, key)
			}
		}
	}}
}

func (h *Hub) Notify(key string) {
	h.mu.Lock()
	for ch := range h.waiters[key] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	h.mu.Unlock()
}
