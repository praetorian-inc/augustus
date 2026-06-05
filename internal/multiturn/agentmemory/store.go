// Package agentmemory simulates an LLM agent's persistent memory system.
//
// Real memory-augmented agents (e.g., ChatGPT with memory, Claude with artifacts)
// maintain a persistent store that survives conversation resets. This package
// provides a thread-safe in-memory store that integrates with the multi-turn
// engine via hooks, enabling memory injection probes to test actual persistence
// behavior rather than voluntary compliance.
package agentmemory

import (
	"fmt"
	"strings"
	"sync"
)

// Store simulates an agent's persistent memory system.
// Thread-safe. Survives session resets (conversation clears).
type Store struct {
	mu      sync.RWMutex
	entries []string
}

// New creates a new empty memory store.
func New() *Store {
	return &Store{
		entries: make([]string, 0),
	}
}

// Add appends a memory entry to the store.
func (s *Store) Add(memory string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, memory)
}

// List returns a copy of all stored memories.
func (s *Store) List() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.entries))
	copy(out, s.entries)
	return out
}

// Clear removes all stored memories.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = s.entries[:0]
}

// Remove deletes the memory at the given index.
// Out-of-range indices are silently ignored.
func (s *Store) Remove(index int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index < 0 || index >= len(s.entries) {
		return
	}
	s.entries = append(s.entries[:index], s.entries[index+1:]...)
}

// Len returns the number of stored memories.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// Format renders the stored memories as text suitable for system prompt injection.
// Returns an empty string if the store is empty.
func (s *Store) Format() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.entries) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("[Agent Memory - Retrieved Context]\n")
	b.WriteString("The following information has been stored from previous conversations:\n")
	for i, entry := range s.entries {
		fmt.Fprintf(&b, "- %s", entry)
		if i < len(s.entries)-1 {
			b.WriteByte('\n')
		}
	}
	b.WriteString("\n[End Agent Memory]")
	return b.String()
}
