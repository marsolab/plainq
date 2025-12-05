package auth

import (
	"context"
	"sync"
	"time"
)

// TokenDenyList manages revoked/invalidated access tokens
// Uses an in-memory cache with database persistence for TTL+1 approach
type TokenDenyList struct {
	storage AuthStorage
	cache   map[string]time.Time // JTI -> expiry time
	mu      sync.RWMutex
	stopCh  chan struct{}
}

// NewTokenDenyList creates a new token deny list
func NewTokenDenyList(storage AuthStorage) *TokenDenyList {
	dl := &TokenDenyList{
		storage: storage,
		cache:   make(map[string]time.Time),
		stopCh:  make(chan struct{}),
	}

	// Start background cleanup goroutine
	go dl.cleanupLoop()

	return dl
}

// Add adds a token to the deny list
func (dl *TokenDenyList) Add(ctx context.Context, jti, userID string, expiresAt time.Time, reason string) error {
	// Add to database first
	if err := dl.storage.AddToDenyList(ctx, jti, userID, expiresAt, reason); err != nil {
		return err
	}

	// Add to in-memory cache
	dl.mu.Lock()
	dl.cache[jti] = expiresAt
	dl.mu.Unlock()

	return nil
}

// IsRevoked checks if a token is in the deny list
func (dl *TokenDenyList) IsRevoked(jti string) bool {
	dl.mu.RLock()
	defer dl.mu.RUnlock()

	expiresAt, exists := dl.cache[jti]
	if !exists {
		return false
	}

	// If token has expired, it's no longer relevant
	if time.Now().After(expiresAt) {
		return false
	}

	return true
}

// LoadFromStorage loads denied tokens from storage into memory
// This should be called on startup to populate the cache
func (dl *TokenDenyList) LoadFromStorage(ctx context.Context) error {
	tokens, err := dl.storage.GetActiveDeniedTokens(ctx)
	if err != nil {
		return err
	}

	dl.mu.Lock()
	defer dl.mu.Unlock()

	for jti, expiresAt := range tokens {
		dl.cache[jti] = expiresAt
	}

	return nil
}

// cleanupLoop periodically removes expired tokens from memory and database
func (dl *TokenDenyList) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dl.cleanup()
		case <-dl.stopCh:
			return
		}
	}
}

// cleanup removes expired tokens from memory and database
func (dl *TokenDenyList) cleanup() {
	now := time.Now()

	// Clean up memory cache
	dl.mu.Lock()
	for jti, expiresAt := range dl.cache {
		if now.After(expiresAt) {
			delete(dl.cache, jti)
		}
	}
	dl.mu.Unlock()

	// Clean up database (background operation, ignore errors)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = dl.storage.CleanupExpiredDeniedTokens(ctx)
}

// Stop stops the cleanup goroutine
func (dl *TokenDenyList) Stop() {
	close(dl.stopCh)
}
