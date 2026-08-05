package mcptool

import (
	"context"
	"encoding/json"
	"testing"

	mcpx "github.com/praetorian-inc/augustus/internal/recon/mcp"
	"github.com/praetorian-inc/augustus/pkg/output"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// TestInjection_PrefersReconStore: when a shared recon inventory is supplied via
// SetContext, the probe must test the tools it describes and must NOT re-enumerate
// the target with ListTools (the Metasploit model: scan once, reuse everywhere).
func TestInjection_PrefersReconStore(t *testing.T) {
	p := newInjectionProbe(t)

	// The shared inventory advertises the real sink ("calc"); the live target's
	// ListTools would only reveal a decoy. If the probe honors recon, it tests
	// "calc"; if it re-enumerates, it tests "decoy" instead.
	inv := types.MCPInventory{Tools: []types.MCPTool{{
		Name:        "calc",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"expression":{"type":"string"}},"required":["expression"]}`),
	}}}
	data, err := json.Marshal(inv)
	if err != nil {
		t.Fatalf("marshal inventory: %v", err)
	}
	store := recon.NewStore()
	store.Observe(output.Observation{Type: mcpx.ObservationTypeInventory, Data: data})
	p.SetContext(recon.ProbeContext{Recon: store})

	listCalled := false
	target := &mockTarget{
		tools:    []map[string]any{stringTool("decoy", "q")},
		listHook: func() { listCalled = true },
		call: func(name string, args map[string]any) types.ToolResult {
			expr, _ := args["expression"].(string)
			if name == "calc" {
				if product, ok := evalMul(expr); ok {
					return types.ToolResult{Text: "Result: " + product}
				}
			}
			return types.ToolResult{Text: "nope"}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if listCalled {
		t.Error("Probe called ListTools despite shared recon inventory being available")
	}

	sawCalc := false
	for _, a := range attempts {
		if tool, _ := a.GetMetadata("mcptool.tool"); tool == "calc" {
			sawCalc = true
		}
		if tool, _ := a.GetMetadata("mcptool.tool"); tool == "decoy" {
			t.Errorf("probe tested decoy tool from ListTools instead of recon inventory")
		}
	}
	if !sawCalc {
		t.Error("probe did not test the 'calc' tool from the shared recon inventory")
	}
}

// TestSSRF_PrefersReconStore: SSRF also honors shared recon — it tests the
// URL-like tool from the inventory and does not re-enumerate via ListTools.
func TestSSRF_PrefersReconStore(t *testing.T) {
	p := newSSRFProbe(t)

	inv := types.MCPInventory{Tools: []types.MCPTool{{
		Name:        "fetch",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}`),
	}}}
	data, err := json.Marshal(inv)
	if err != nil {
		t.Fatalf("marshal inventory: %v", err)
	}
	store := recon.NewStore()
	store.Observe(output.Observation{Type: mcpx.ObservationTypeInventory, Data: data})
	p.SetContext(recon.ProbeContext{Recon: store})

	listCalled := false
	target := &mockTarget{
		tools:    []map[string]any{stringTool("note", "text")}, // decoy: no URL param
		listHook: func() { listCalled = true },
		call:     fetchTool(false),
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if listCalled {
		t.Error("SSRF called ListTools despite shared recon inventory being available")
	}
	if attemptFor(attempts, "fetch") == nil {
		t.Error("SSRF did not test the 'fetch' tool from the shared recon inventory")
	}
}

// TestInjection_FallsBackToListTools: with no recon context (or an empty store),
// the probe still enumerates the live target via ListTools.
func TestInjection_FallsBackToListTools(t *testing.T) {
	p := newInjectionProbe(t)
	p.SetContext(recon.ProbeContext{Recon: recon.NewStore()}) // empty store

	listCalled := false
	target := &mockTarget{
		tools:    []map[string]any{stringTool("calc", "expression")},
		listHook: func() { listCalled = true },
		call: func(_ string, args map[string]any) types.ToolResult {
			expr, _ := args["expression"].(string)
			if product, ok := evalMul(expr); ok {
				return types.ToolResult{Text: "Result: " + product}
			}
			return types.ToolResult{Text: "nope"}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !listCalled {
		t.Error("Probe did not fall back to ListTools when the recon store was empty")
	}
	if len(attempts) == 0 {
		t.Error("expected attempts from live enumeration")
	}
}

// TestInjection_IgnoresIncompleteReconInventory: the mirror of
// TestInjection_PrefersReconStore. Reusing a shared inventory is only sound when
// that inventory is COMPLETE. One whose catalog enumeration stopped early is a lower
// bound on the tool surface, so a server that halted recon after a benign prefix
// would otherwise have every probe score the prefix and report the target clean.
//
// The probe must ignore it and re-enumerate live instead.
func TestInjection_IgnoresIncompleteReconInventory(t *testing.T) {
	p := newInjectionProbe(t)

	// The stored inventory is marked incomplete and advertises only a benign tool.
	// The live target exposes the real sink. Honouring the stale inventory would test
	// "benign" and find nothing; re-enumerating finds "calc".
	inv := types.MCPInventory{
		Tools: []types.MCPTool{{
			Name:        "benign",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}`),
		}},
		Incomplete: []string{"tools"},
	}
	data, err := json.Marshal(inv)
	if err != nil {
		t.Fatalf("marshal inventory: %v", err)
	}
	store := recon.NewStore()
	store.Observe(output.Observation{Type: mcpx.ObservationTypeInventory, Data: data})
	p.SetContext(recon.ProbeContext{Recon: store})

	listCalled := false
	target := &mockTarget{
		tools:    []map[string]any{stringTool("calc", "expression")},
		listHook: func() { listCalled = true },
		call: func(name string, args map[string]any) types.ToolResult {
			expr, _ := args["expression"].(string)
			if name == "calc" {
				if product, ok := evalMul(expr); ok {
					return types.ToolResult{Text: "Result: " + product}
				}
			}
			return types.ToolResult{Text: "nope"}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !listCalled {
		t.Error("Probe reused an INCOMPLETE recon inventory instead of re-enumerating the tool surface")
	}

	sawCalc := false
	for _, a := range attempts {
		if tool, _ := a.GetMetadata("mcptool.tool"); tool == "calc" {
			sawCalc = true
		}
	}
	if !sawCalc {
		t.Error("the live tool surface was never probed after the incomplete inventory was rejected")
	}
}
