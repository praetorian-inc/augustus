package registry

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// PluginMeta holds cached metadata about a plugin.
type PluginMeta struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Active      bool          `json:"active"`
	FileHash    string        `json:"file_hash"`
	LoadTime    time.Duration `json:"load_time"`
	CachedAt    time.Time     `json:"cached_at"`
}

// PluginCache manages cached plugin metadata for fast startup.
// It is safe for concurrent use.
type PluginCache struct {
	mu      sync.RWMutex
	path    string
	entries map[string]map[string]PluginMeta // category -> name -> metadata
}

// NewPluginCache creates a new plugin cache with the given file path.
func NewPluginCache(path string) *PluginCache {
	return &PluginCache{
		path:    path,
		entries: make(map[string]map[string]PluginMeta),
	}
}

// Set stores plugin metadata in the cache.
func (c *PluginCache) Set(category, name string, meta PluginMeta) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.entries[category] == nil {
		c.entries[category] = make(map[string]PluginMeta)
	}

	c.entries[category][name] = meta
	return nil
}

// Get retrieves plugin metadata from the cache.
// Returns false if the entry does not exist.
func (c *PluginCache) Get(category, name string) (PluginMeta, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.entries[category] == nil {
		return PluginMeta{}, false
	}

	meta, ok := c.entries[category][name]
	return meta, ok
}

// IsValid checks if a cached entry is still valid based on file hash.
// Returns false if the entry doesn't exist or the hash doesn't match.
func (c *PluginCache) IsValid(category, name, currentHash string) bool {
	meta, ok := c.Get(category, name)
	if !ok {
		return false
	}

	return meta.FileHash == currentHash
}

// List returns all cached metadata for a given category.
func (c *PluginCache) List(category string) []PluginMeta {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.entries[category] == nil {
		return nil
	}

	result := make([]PluginMeta, 0, len(c.entries[category]))
	for _, meta := range c.entries[category] {
		result = append(result, meta)
	}

	return result
}

// Clear removes all entries from the cache.
func (c *PluginCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]map[string]PluginMeta)
}

// Save writes the cache to disk as JSON.
func (c *PluginCache) Save() error {
	c.mu.RLock()
	data, err := json.MarshalIndent(c.entries, "", "  ")
	c.mu.RUnlock()

	if err != nil {
		return err
	}

	return os.WriteFile(c.path, data, 0644)
}

// Load reads the cache from disk.
func (c *PluginCache) Load() error {
	data, err := os.ReadFile(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			// Cache file doesn't exist yet, that's okay
			return nil
		}
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	return json.Unmarshal(data, &c.entries)
}
