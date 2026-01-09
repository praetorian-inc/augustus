// cache.go
package judge

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
)

// Cache stores judge results to avoid re-evaluating identical content.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]float64
}

// NewCache creates a new result cache.
func NewCache() *Cache {
	return &Cache{
		entries: make(map[string]float64),
	}
}

// cacheKey generates a unique key from prompt, output, and goal.
// Uses length-prefixed encoding to prevent collision attacks.
func cacheKey(prompt, output, goal string) string {
	h := sha256.New()
	// Use length-prefixed encoding to prevent collisions
	h.Write([]byte(fmt.Sprintf("%d:%s|%d:%s|%d:%s",
		len(prompt), prompt,
		len(output), output,
		len(goal), goal)))
	return hex.EncodeToString(h.Sum(nil))
}

// Set stores a judge result in the cache.
func (c *Cache) Set(prompt, output, goal string, score float64) {
	key := cacheKey(prompt, output, goal)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = score
}

// Get retrieves a cached result.
func (c *Cache) Get(prompt, output, goal string) (float64, bool) {
	key := cacheKey(prompt, output, goal)
	c.mu.RLock()
	defer c.mu.RUnlock()
	score, ok := c.entries[key]
	return score, ok
}

// Clear removes all entries from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]float64)
}

// Size returns the number of cached entries.
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
