// cache_test.go
package judge

import (
	"testing"
)

func TestCacheSetGet(t *testing.T) {
	c := NewCache()

	// Set a value
	c.Set("prompt1", "output1", "goal1", 7.0)

	// Get it back
	score, ok := c.Get("prompt1", "output1", "goal1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if score != 7.0 {
		t.Errorf("expected score 7.0, got %f", score)
	}
}

func TestCacheMiss(t *testing.T) {
	c := NewCache()

	_, ok := c.Get("nonexistent", "output", "goal")
	if ok {
		t.Error("expected cache miss")
	}
}

func TestCacheKeyUniqueness(t *testing.T) {
	c := NewCache()

	c.Set("prompt1", "output1", "goal1", 5.0)
	c.Set("prompt1", "output1", "goal2", 8.0) // Different goal

	score1, _ := c.Get("prompt1", "output1", "goal1")
	score2, _ := c.Get("prompt1", "output1", "goal2")

	if score1 == score2 {
		t.Error("different goals should have different cache entries")
	}
}

func TestCacheConcurrency(t *testing.T) {
	c := NewCache()
	done := make(chan bool, 100)

	// Concurrent writes
	for i := 0; i < 50; i++ {
		go func(i int) {
			c.Set("prompt", "output", "goal", float64(i))
			done <- true
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 50; i++ {
		go func() {
			c.Get("prompt", "output", "goal")
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}
