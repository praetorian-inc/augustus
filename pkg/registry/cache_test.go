package registry

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPluginCache_SaveAndLoad(t *testing.T) {
	// Create temporary directory for cache file
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.json")

	// Create cache
	cache := NewPluginCache(cachePath)

	// Add some metadata
	meta1 := PluginMeta{
		Name:        "test-plugin-1",
		Description: "Test plugin 1",
		Active:      true,
		FileHash:    "abc123",
		LoadTime:    100 * time.Millisecond,
		CachedAt:    time.Now(),
	}

	meta2 := PluginMeta{
		Name:        "test-plugin-2",
		Description: "Test plugin 2",
		Active:      false,
		FileHash:    "def456",
		LoadTime:    200 * time.Millisecond,
		CachedAt:    time.Now(),
	}

	// Save metadata
	err := cache.Set("probes", "test-plugin-1", meta1)
	if err != nil {
		t.Fatalf("Set() error = %v, want nil", err)
	}

	err = cache.Set("probes", "test-plugin-2", meta2)
	if err != nil {
		t.Fatalf("Set() error = %v, want nil", err)
	}

	// Save to disk
	err = cache.Save()
	if err != nil {
		t.Fatalf("Save() error = %v, want nil", err)
	}

	// Verify file was created
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		t.Fatalf("cache file was not created at %s", cachePath)
	}

	// Load from disk
	cache2 := NewPluginCache(cachePath)
	err = cache2.Load()
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	// Verify loaded metadata
	loadedMeta1, ok := cache2.Get("probes", "test-plugin-1")
	if !ok {
		t.Fatal("Get(probes, test-plugin-1) = false, want true")
	}

	if loadedMeta1.Name != meta1.Name {
		t.Errorf("loaded meta1.Name = %q, want %q", loadedMeta1.Name, meta1.Name)
	}

	if loadedMeta1.FileHash != meta1.FileHash {
		t.Errorf("loaded meta1.FileHash = %q, want %q", loadedMeta1.FileHash, meta1.FileHash)
	}

	loadedMeta2, ok := cache2.Get("probes", "test-plugin-2")
	if !ok {
		t.Fatal("Get(probes, test-plugin-2) = false, want true")
	}

	if loadedMeta2.Name != meta2.Name {
		t.Errorf("loaded meta2.Name = %q, want %q", loadedMeta2.Name, meta2.Name)
	}
}

func TestPluginCache_IsValid_HashMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.json")

	cache := NewPluginCache(cachePath)

	// Add metadata with specific hash
	meta := PluginMeta{
		Name:        "test-plugin",
		Description: "Test plugin",
		Active:      true,
		FileHash:    "abc123",
		LoadTime:    100 * time.Millisecond,
		CachedAt:    time.Now(),
	}

	err := cache.Set("probes", "test-plugin", meta)
	if err != nil {
		t.Fatalf("Set() error = %v, want nil", err)
	}

	// Check validity with same hash
	if !cache.IsValid("probes", "test-plugin", "abc123") {
		t.Error("IsValid() with same hash = false, want true")
	}

	// Check validity with different hash (file changed)
	if cache.IsValid("probes", "test-plugin", "xyz789") {
		t.Error("IsValid() with different hash = true, want false")
	}
}

func TestPluginCache_IsValid_NotCached(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.json")

	cache := NewPluginCache(cachePath)

	// Check validity for non-existent entry
	if cache.IsValid("probes", "nonexistent", "abc123") {
		t.Error("IsValid() for non-existent plugin = true, want false")
	}
}

func TestPluginCache_ConcurrentAccess(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.json")

	cache := NewPluginCache(cachePath)

	const numGoroutines = 50

	// Concurrent writes
	done := make(chan bool)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			meta := PluginMeta{
				Name:        "plugin-" + string(rune('0'+id)),
				Description: "Test plugin",
				Active:      true,
				FileHash:    "hash-" + string(rune('0'+id)),
				LoadTime:    100 * time.Millisecond,
				CachedAt:    time.Now(),
			}
			err := cache.Set("probes", meta.Name, meta)
			if err != nil {
				t.Errorf("Set() error = %v", err)
			}
			done <- true
		}(i)
	}

	// Wait for all writes
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			name := "plugin-" + string(rune('0'+id))
			_, ok := cache.Get("probes", name)
			if !ok {
				t.Errorf("Get(probes, %s) = false, want true", name)
			}
			done <- true
		}(i)
	}

	// Wait for all reads
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func TestPluginCache_List(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.json")

	cache := NewPluginCache(cachePath)

	// Add several plugins
	plugins := []string{"plugin1", "plugin2", "plugin3"}
	for _, name := range plugins {
		meta := PluginMeta{
			Name:        name,
			Description: "Test plugin",
			Active:      true,
			FileHash:    "hash-" + name,
			LoadTime:    100 * time.Millisecond,
			CachedAt:    time.Now(),
		}
		err := cache.Set("probes", name, meta)
		if err != nil {
			t.Fatalf("Set() error = %v", err)
		}
	}

	// List all plugins in category
	list := cache.List("probes")
	if len(list) != len(plugins) {
		t.Errorf("List(probes) returned %d plugins, want %d", len(list), len(plugins))
	}

	// Verify all plugins are in list
	found := make(map[string]bool)
	for _, meta := range list {
		found[meta.Name] = true
	}

	for _, name := range plugins {
		if !found[name] {
			t.Errorf("plugin %q not found in List() results", name)
		}
	}
}

func TestPluginCache_Clear(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.json")

	cache := NewPluginCache(cachePath)

	// Add metadata
	meta := PluginMeta{
		Name:        "test-plugin",
		Description: "Test plugin",
		Active:      true,
		FileHash:    "abc123",
		LoadTime:    100 * time.Millisecond,
		CachedAt:    time.Now(),
	}

	err := cache.Set("probes", "test-plugin", meta)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Verify it's cached
	_, ok := cache.Get("probes", "test-plugin")
	if !ok {
		t.Fatal("Get() before Clear() = false, want true")
	}

	// Clear the cache
	cache.Clear()

	// Verify it's gone
	_, ok = cache.Get("probes", "test-plugin")
	if ok {
		t.Error("Get() after Clear() = true, want false")
	}
}
