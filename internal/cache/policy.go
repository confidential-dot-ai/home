// Package cache provides caching for the image digest allowlist.
package cache

import (
	"sync"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// PolicyCache caches the allowlist fetched from KBS.
type PolicyCache struct {
	mu        sync.RWMutex
	allowlist *allowlist.Allowlist
}

// NewPolicyCache creates a new policy cache.
func NewPolicyCache() *PolicyCache {
	return &PolicyCache{}
}

// GetAllowlist returns the cached allowlist.
func (c *PolicyCache) GetAllowlist() *allowlist.Allowlist {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.allowlist
}

// SetAllowlist stores the allowlist in the cache.
func (c *PolicyCache) SetAllowlist(wl *allowlist.Allowlist) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.allowlist = wl
}

// Clear removes the cached allowlist. Next CreateContainer triggers a fresh KBS fetch.
func (c *PolicyCache) Clear() {
	c.SetAllowlist(nil)
}
