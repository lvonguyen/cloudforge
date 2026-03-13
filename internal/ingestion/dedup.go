package ingestion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// DedupEntry records a previously seen finding for deduplication.
type DedupEntry struct {
	FindingID string    `json:"finding_id"`
	Key       string    `json:"key"`
	FirstSeen time.Time `json:"first_seen"`
}

// DedupCache is an in-memory deduplication cache backed by sync.RWMutex + map.
// Entries expire after the configured TTL.
type DedupCache struct {
	mu      sync.RWMutex
	entries map[string]DedupEntry
	ttl     time.Duration
}

// NewDedupCache creates a DedupCache with the given TTL.
func NewDedupCache(ttl time.Duration) *DedupCache {
	return &DedupCache{
		entries: make(map[string]DedupEntry),
		ttl:     ttl,
	}
}

// GenerateDedupKey produces a deterministic SHA-256 hex key from the canonical
// identity of a finding. A null-byte delimiter separates fields to prevent
// collision between different field-split combinations (e.g., source="ab" +
// id="cd" vs source="a" + id="bcd").
func GenerateDedupKey(source, sourceFindingID, resourceID, accountID string) string {
	h := sha256.New()
	for _, s := range []string{source, sourceFindingID, resourceID, accountID} {
		h.Write([]byte(s))
		h.Write([]byte{0}) // null delimiter
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CheckOrInsert atomically checks whether key exists and is not expired.
// If it exists, returns isDuplicate=true with the existing entry.
// If absent or expired, inserts a new entry and returns isDuplicate=false.
func (c *DedupCache) CheckOrInsert(key, findingID string) (isDuplicate bool, entry DedupEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if existing, ok := c.entries[key]; ok {
		if time.Since(existing.FirstSeen) < c.ttl {
			return true, existing
		}
		// Expired — fall through to re-insert.
	}

	e := DedupEntry{
		FindingID: findingID,
		Key:       key,
		FirstSeen: time.Now(),
	}
	c.entries[key] = e
	return false, e
}

// StartEviction runs a background goroutine that periodically removes expired
// entries from the cache. It stops when ctx is cancelled.
func (c *DedupCache) StartEviction(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.evictExpired()
			}
		}
	}()
}

func (c *DedupCache) evictExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		if time.Since(entry.FirstSeen) >= c.ttl {
			delete(c.entries, key)
		}
	}
}
