package recon

import (
	"sync"

	"github.com/praetorian-inc/augustus/pkg/output"
)

// Store is the shared assessment context for a scan: the single collection of
// observations gathered about the target. It is the one source of truth that
// recon modules write to, scan output reads from, and — via the public Observe
// API — external producers can inject into (the seam for callers that supply
// their own reconnaissance to augustus). Concurrency-safe.
type Store struct {
	mu  sync.Mutex
	obs []output.Observation
}

// NewStore returns an empty store.
func NewStore() *Store { return &Store{} }

// Observe records one observation.
func (s *Store) Observe(o output.Observation) {
	s.mu.Lock()
	s.obs = append(s.obs, o)
	s.mu.Unlock()
}

// Observations returns a copy of the recorded observations.
func (s *Store) Observations() []output.Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]output.Observation, len(s.obs))
	copy(out, s.obs)
	return out
}

// Len reports how many observations have been recorded.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.obs)
}
