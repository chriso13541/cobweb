package dnsserver

import (
	"net"
	"sync"
	"time"
)

type cacheEntry struct {
	ips       []net.IP
	expiresAt time.Time
}

// recursiveCache holds resolved answers keyed by "name|qtype", so
// repeated lookups (which are extremely common - browsers, OSes, and
// apps all re-resolve the same handful of domains constantly) don't
// pay the full multi-hop referral-following cost every time.
type recursiveCache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
}

func newRecursiveCache() *recursiveCache {
	return &recursiveCache{entries: make(map[string]cacheEntry)}
}

func (c *recursiveCache) get(key string) ([]net.IP, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e.ips, true
}

func (c *recursiveCache) set(key string, ips []net.IP, ttl uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ttl == 0 {
		ttl = 30
	}
	// Cap how long anything is trusted, even if an upstream server
	// returns an unusually large TTL - keeps the cache from serving
	// very stale answers for a home network where devices come and go.
	const maxTTL = 6 * time.Hour
	ttlDuration := time.Duration(ttl) * time.Second
	if ttlDuration > maxTTL {
		ttlDuration = maxTTL
	}
	c.entries[key] = cacheEntry{ips: ips, expiresAt: time.Now().Add(ttlDuration)}
}
