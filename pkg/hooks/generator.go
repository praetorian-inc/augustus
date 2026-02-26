package hooks

import (
	"context"
	"fmt"
	"sync"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// Compile-time interface assertion.
var _ types.Generator = (*HookedGenerator)(nil)

// HookedGenerator wraps a generator with lifecycle hook support.
// It runs the prepare hook before each Generate() call, merging
// KEY=VALUE output into the variable map that gets injected via context.
type HookedGenerator struct {
	inner      types.Generator
	prepare    *Hook
	vars       map[string]string
	lastResp   []byte
	mu         sync.Mutex
	probeCount int
}

// NewHookedGenerator creates a generator wrapper with lifecycle hooks.
// initialVars typically comes from the setup hook's output.
func NewHookedGenerator(inner types.Generator, prepare *Hook, initialVars map[string]string) *HookedGenerator {
	vars := make(map[string]string)
	for k, v := range initialVars {
		vars[k] = v
	}
	return &HookedGenerator{
		inner:   inner,
		prepare: prepare,
		vars:    vars,
	}
}

// Generate runs the prepare hook (if set), merges its output variables,
// injects all variables into the context, and delegates to the inner generator.
func (h *HookedGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	h.mu.Lock()

	// Run prepare hook if set
	if h.prepare != nil && h.prepare.Command != "" {
		env := make(map[string]string)
		env["AUGUSTUS_GENERATOR"] = h.inner.Name()
		env["AUGUSTUS_PROBE_INDEX"] = fmt.Sprintf("%d", h.probeCount)
		if len(h.lastResp) > 0 {
			env["AUGUSTUS_LAST_RESPONSE"] = string(h.lastResp)
		}
		// Include current vars in env so prepare can reference them
		for k, v := range h.vars {
			env["AUGUSTUS_VAR_"+k] = v
		}

		result, err := h.prepare.Run(ctx, env)
		if err != nil {
			h.mu.Unlock()
			return nil, fmt.Errorf("prepare hook failed: %w", err)
		}
		// Merge new vars (overrides existing)
		for k, v := range result.Variables {
			h.vars[k] = v
		}
	}

	// Copy vars for context injection
	vars := make(map[string]string, len(h.vars))
	for k, v := range h.vars {
		vars[k] = v
	}
	h.probeCount++
	h.mu.Unlock()

	// Inject vars into context for the generator to use
	ctx = WithVars(ctx, vars)

	// Delegate to inner generator
	messages, err := h.inner.Generate(ctx, conv, n)
	if err != nil {
		return nil, err
	}

	// Capture raw response if available for the next prepare call
	if provider, ok := h.inner.(RawResponseProvider); ok {
		h.mu.Lock()
		h.lastResp = provider.LastRawResponse()
		h.mu.Unlock()
	}

	return messages, nil
}

// ClearHistory delegates to the inner generator.
func (h *HookedGenerator) ClearHistory() {
	h.inner.ClearHistory()
}

// Name returns the inner generator's name.
func (h *HookedGenerator) Name() string {
	return h.inner.Name()
}

// Description returns the inner generator's description.
func (h *HookedGenerator) Description() string {
	return h.inner.Description()
}
