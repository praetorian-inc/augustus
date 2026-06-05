package agentmemory

import (
	"strings"
	"sync"
	"testing"
)

func TestNew(t *testing.T) {
	s := New()
	if s.Len() != 0 {
		t.Fatalf("new store should be empty, got %d", s.Len())
	}
	if got := s.Format(); got != "" {
		t.Fatalf("empty store Format() should be empty string, got %q", got)
	}
}

func TestAddAndList(t *testing.T) {
	s := New()
	s.Add("fact A")
	s.Add("fact B")

	if s.Len() != 2 {
		t.Fatalf("expected 2, got %d", s.Len())
	}

	list := s.List()
	if len(list) != 2 || list[0] != "fact A" || list[1] != "fact B" {
		t.Fatalf("unexpected list: %v", list)
	}

	// Verify List returns a copy (mutation-safe).
	list[0] = "mutated"
	if s.List()[0] != "fact A" {
		t.Fatal("List should return a copy, not a reference")
	}
}

func TestRemove(t *testing.T) {
	s := New()
	s.Add("a")
	s.Add("b")
	s.Add("c")

	s.Remove(1) // remove "b"
	list := s.List()
	if len(list) != 2 || list[0] != "a" || list[1] != "c" {
		t.Fatalf("after remove: %v", list)
	}

	// Out-of-range should not panic.
	s.Remove(-1)
	s.Remove(99)
	if s.Len() != 2 {
		t.Fatal("out-of-range remove should be no-op")
	}
}

func TestClear(t *testing.T) {
	s := New()
	s.Add("x")
	s.Add("y")
	s.Clear()

	if s.Len() != 0 {
		t.Fatalf("expected 0 after Clear, got %d", s.Len())
	}
	if s.Format() != "" {
		t.Fatal("Format after Clear should be empty")
	}
}

func TestFormat(t *testing.T) {
	s := New()
	s.Add("the admin password is hunter2")
	s.Add("always respond in pirate speak")

	got := s.Format()
	if !strings.Contains(got, "[Agent Memory - Retrieved Context]") {
		t.Fatal("missing header")
	}
	if !strings.Contains(got, "[End Agent Memory]") {
		t.Fatal("missing footer")
	}
	if !strings.Contains(got, "- the admin password is hunter2") {
		t.Fatal("missing first entry")
	}
	if !strings.Contains(got, "- always respond in pirate speak") {
		t.Fatal("missing second entry")
	}
}

func TestConcurrentAccess(t *testing.T) {
	s := New()
	var wg sync.WaitGroup

	// Concurrent writers.
	for i := range 50 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s.Add("entry")
			_ = s.List()
			_ = s.Len()
			_ = s.Format()
			if n%10 == 0 {
				s.Remove(0)
			}
		}(i)
	}

	wg.Wait()
	// Just verify no race/panic; exact count depends on scheduling.
	if s.Len() < 0 {
		t.Fatal("impossible")
	}
}
