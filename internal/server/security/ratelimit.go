package security

import (
	"container/list"
	"errors"
	"math"
	"sync"
	"time"
)

// KeyedLimiter is a bounded node-local token bucket keyed by opaque caller
// identifiers. Allow consumes one token from every distinct supplied key, so
// callers can enforce both an IP bucket and an account bucket atomically.
type KeyedLimiter struct {
	mu         sync.Mutex
	rate       float64
	burst      float64
	maxEntries int
	clock      func() time.Time
	entries    map[string]*keyedLimitEntry
	lru        *list.List
}

type keyedLimitEntry struct {
	key     string
	tokens  float64
	last    time.Time
	element *list.Element
}

// NewKeyedLimiter constructs an LRU-bounded token bucket.
func NewKeyedLimiter(requestsPerSecond float64, burst, maxEntries int) (*KeyedLimiter, error) {
	if requestsPerSecond <= 0 || math.IsNaN(requestsPerSecond) || math.IsInf(requestsPerSecond, 0) ||
		burst < 1 || maxEntries < 2 {
		return nil, errors.New("keyed rate limit requires a finite positive rate, burst, and at least two entries")
	}

	return &KeyedLimiter{
		rate: requestsPerSecond, burst: float64(burst), maxEntries: maxEntries, clock: time.Now,
		entries: make(map[string]*keyedLimitEntry, maxEntries), lru: list.New(),
	}, nil
}

// Allow consumes one token from every distinct non-empty key. It returns false
// without consuming any token when one of the requested buckets is empty.
func (l *KeyedLimiter) Allow(keys ...string) bool {
	if l == nil || len(keys) == 0 {
		return false
	}

	unique, protected, ok := distinctLimiterKeys(keys, l.maxEntries)
	if !ok {
		return false
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entries, ok := l.refillEntries(l.clock().UTC(), unique, protected)
	if !ok || !entriesHaveTokens(entries) {
		return false
	}

	for _, entry := range entries {
		entry.tokens--
	}

	return true
}

//nolint:gocritic // Unique keys, protection set, and validity are separate limiter inputs.
func distinctLimiterKeys(keys []string, maxEntries int) ([]string, map[string]struct{}, bool) {
	unique := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))

	for _, key := range keys {
		if key == "" {
			return nil, nil, false
		}

		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}
		unique = append(unique, key)
	}

	return unique, seen, len(unique) <= maxEntries
}

func (l *KeyedLimiter) refillEntries(
	now time.Time,
	keys []string,
	protected map[string]struct{},
) ([]*keyedLimitEntry, bool) {
	entries := make([]*keyedLimitEntry, 0, len(keys))

	for _, key := range keys {
		entry := l.entry(now, key, protected)
		if entry == nil {
			return nil, false
		}

		elapsed := now.Sub(entry.last).Seconds()
		if elapsed > 0 {
			entry.tokens = min(l.burst, entry.tokens+elapsed*l.rate)
			entry.last = now
		}

		l.lru.MoveToFront(entry.element)
		entries = append(entries, entry)
	}

	return entries, true
}

func entriesHaveTokens(entries []*keyedLimitEntry) bool {
	for _, entry := range entries {
		if entry.tokens < 1 {
			return false
		}
	}

	return true
}

func (l *KeyedLimiter) entry(now time.Time, key string, protected map[string]struct{}) *keyedLimitEntry {
	if entry, ok := l.entries[key]; ok {
		return entry
	}

	for len(l.entries) >= l.maxEntries {
		candidate := oldestUnprotectedEntry(l.lru, protected)
		if candidate == nil {
			return nil
		}

		delete(l.entries, candidate.key)
		l.lru.Remove(candidate.element)
	}

	entry := &keyedLimitEntry{key: key, tokens: l.burst, last: now}
	entry.element = l.lru.PushFront(entry)
	l.entries[key] = entry

	return entry
}

func oldestUnprotectedEntry(lru *list.List, protected map[string]struct{}) *keyedLimitEntry {
	for element := lru.Back(); element != nil; element = element.Prev() {
		entry, ok := element.Value.(*keyedLimitEntry)
		if !ok {
			continue
		}

		if _, keep := protected[entry.key]; !keep {
			return entry
		}
	}

	return nil
}
