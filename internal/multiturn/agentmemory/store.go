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
	"sort"
	"strings"
	"sync"
)

// Store simulates an agent's persistent memory system.
// Thread-safe. Survives session resets (conversation clears).
type Store struct {
	mu           sync.RWMutex
	entries      []string
	MaxRetrieved int // max memories to retrieve per query (0 = all)
}

// New creates a new empty memory store.
func New() *Store {
	return &Store{
		entries:      make([]string, 0),
		MaxRetrieved: 3,
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

// Retrieve returns the top-k most relevant memories for the given query,
// scored by keyword overlap. This simulates similarity-based retrieval in
// real memory-augmented agents (e.g., embedding cosine similarity).
// Returns all memories if MaxRetrieved is 0 or there are fewer entries.
func (s *Store) Retrieve(query string, k int) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.entries) == 0 {
		return nil
	}
	if k <= 0 || k >= len(s.entries) {
		out := make([]string, len(s.entries))
		copy(out, s.entries)
		return out
	}

	queryWords := tokenize(query)
	if len(queryWords) == 0 {
		out := make([]string, len(s.entries))
		copy(out, s.entries)
		return out
	}

	type scored struct {
		entry string
		score float64
	}
	items := make([]scored, len(s.entries))
	for i, entry := range s.entries {
		entryWords := tokenize(entry)
		items[i] = scored{entry: entry, score: wordOverlap(queryWords, entryWords)}
	}

	// Sort by score descending (simple selection of top-k)
	sort.Slice(items, func(i, j int) bool {
		return items[i].score > items[j].score
	})

	result := make([]string, k)
	for i := 0; i < k; i++ {
		result[i] = items[i].entry
	}
	return result
}

// FormatRetrieved renders the given memories as text for system prompt injection.
func FormatRetrieved(memories []string) string {
	if len(memories) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("[Agent Memory - Retrieved Context]\n")
	b.WriteString("The following information has been retrieved from previous conversations:\n")
	for i, entry := range memories {
		fmt.Fprintf(&b, "- %s", entry)
		if i < len(memories)-1 {
			b.WriteByte('\n')
		}
	}
	b.WriteString("\n[End Agent Memory]")
	return b.String()
}

// tokenize splits text into lowercase word tokens.
func tokenize(text string) map[string]bool {
	words := make(map[string]bool)
	for _, w := range strings.Fields(strings.ToLower(text)) {
		// Strip basic punctuation
		w = strings.Trim(w, ".,;:!?\"'()[]{}|")
		if len(w) > 1 { // skip single chars
			words[w] = true
		}
	}
	return words
}

// wordOverlap returns the fraction of query words found in the entry.
func wordOverlap(queryWords, entryWords map[string]bool) float64 {
	if len(queryWords) == 0 {
		return 0
	}
	overlap := 0
	for w := range queryWords {
		if entryWords[w] {
			overlap++
		}
	}
	return float64(overlap) / float64(len(queryWords))
}
