package hooks

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

//go:generate go run gen_caps.go

// Compile-time interface assertions. The optional-interface wrappers and their
// assertions are generated (see hooked_caps_gen.go).
var (
	_ types.Generator     = (*HookedGenerator)(nil)
	_ types.UsageReporter = (*HookedGenerator)(nil)
)

// HookedGenerator wraps a generator with runtime hook support.
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

// NewHookedGenerator creates a generator wrapper with runtime hooks.
// initialVars typically comes from the setup hook's output.
func NewHookedGenerator(inner types.Generator, prepare *Hook, initialVars map[string]string) types.Generator {
	vars := make(map[string]string)
	for k, v := range initialVars {
		vars[k] = v
	}
	base := &HookedGenerator{
		inner:   inner,
		prepare: prepare,
		vars:    vars,
	}

	// Preserve exactly the optional interfaces the inner generator implements —
	// no more (a plain chat model must not appear MCP-capable), no less (an MCP
	// target must stay a ToolInvoker/MCPReconnaissance, a multimodal target must
	// stay VisionCapable/DocumentCapable, a raw-response target must stay a
	// RawResponseProvider). capMask + wrapCaps and the 2^N combination wrappers
	// are generated (gen_caps.go), so this stays correct as capabilities are added
	// without hand-writing a wrapper per combination.
	return wrapCaps(base, capMask(inner))
}

// hookedListTools, hookedCallTool and hookedMCPInventory forward one optional-
// interface call to the inner generator, first threading hook vars into the
// context via hookContext so credentials/session vars reach the request.

func hookedListTools(h *HookedGenerator, ctx context.Context) ([]map[string]any, error) {
	hctx, err := h.hookContext(ctx)
	if err != nil {
		return nil, err
	}
	return h.inner.(types.ToolInvoker).ListTools(hctx)
}

func hookedCallTool(h *HookedGenerator, ctx context.Context, name string, args map[string]any) (types.ToolResult, error) {
	hctx, err := h.hookContext(ctx)
	if err != nil {
		return types.ToolResult{}, err
	}
	return h.inner.(types.ToolInvoker).CallTool(hctx, name, args)
}

func hookedMCPInventory(h *HookedGenerator, ctx context.Context) (*types.MCPInventory, error) {
	hctx, err := h.hookContext(ctx)
	if err != nil {
		return nil, err
	}
	return h.inner.(types.MCPReconnaissance).MCPInventory(hctx)
}

// The optional-interface capability predicates (SupportsVision,
// SupportsDocuments, LastRawResponse) are pure pass-throughs to the inner
// generator — no hook context needed — and are forwarded directly by the
// generated combination wrappers (hooked_caps_gen.go).

// Generate runs the prepare hook (if set), merges its output variables,
// injects all variables into the context, and delegates to the inner generator.
func (h *HookedGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	hctx, err := h.hookContext(ctx)
	if err != nil {
		return nil, err
	}

	// Delegate to inner generator
	messages, err := h.inner.Generate(hctx, conv, n)
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

// hookContext runs the prepare hook (if configured), merges any variables it
// emits, and returns ctx carrying the current variable set so the inner
// generator can substitute them (into request headers, tool arguments, etc.).
// It is shared by Generate AND the forwarded MCP / tool-surface methods, so
// hook-provided credentials reach every call path — not just Generate.
func (h *HookedGenerator) hookContext(ctx context.Context) (context.Context, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Run prepare hook if set
	if h.prepare != nil && h.prepare.Command != "" {
		env := make(map[string]string)
		env["AUGUSTUS_GENERATOR"] = h.inner.Name()
		env["AUGUSTUS_PROBE_INDEX"] = fmt.Sprintf("%d", h.probeCount)
		if len(h.lastResp) > 0 {
			tmpFile, err := os.CreateTemp("", "augustus-response-*.json")
			if err != nil {
				return nil, fmt.Errorf("failed to create temp file for last response: %w", err)
			}
			// The path is consumed by prepare.Run below; safe to remove on return.
			defer func() { _ = os.Remove(tmpFile.Name()) }()
			if _, err := tmpFile.Write(h.lastResp); err != nil {
				_ = tmpFile.Close()
				return nil, fmt.Errorf("failed to write last response to temp file: %w", err)
			}
			_ = tmpFile.Close()
			env["AUGUSTUS_LAST_RESPONSE_FILE"] = tmpFile.Name()
		}
		// Include current vars in env so prepare can reference them
		for k, v := range h.vars {
			env["AUGUSTUS_VAR_"+k] = v
		}

		result, err := h.prepare.Run(ctx, env)
		if err != nil {
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

	return WithVars(ctx, vars), nil
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

// AccumulatedTokens forwards to the inner generator if it reports usage;
// otherwise returns 0. Without this forward, scans run through a prepare hook
// would assert UsageReporter against this wrapper and read 0 tokens.
func (h *HookedGenerator) AccumulatedTokens() int64 {
	if r, ok := h.inner.(types.UsageReporter); ok {
		return r.AccumulatedTokens()
	}
	return 0
}
