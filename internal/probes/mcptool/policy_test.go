package mcptool

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// annotatedTool returns a one-string-param tool map carrying safety annotations,
// as resolveTools produces for a tool the server annotated.
func annotatedTool(name, param string, ann types.MCPToolAnnotations) map[string]any {
	tm := stringTool(name, param)
	tm["annotations"] = ann
	return tm
}

func ptrBool(b bool) *bool { return &b }

// countingTarget records every tool it is asked to invoke, so a test can tell
// which tools the safety gate let through.
type countingTarget struct {
	*mockTarget
	called map[string]int
}

func newCountingTarget(tools []map[string]any) *countingTarget {
	ct := &countingTarget{called: map[string]int{}}
	ct.mockTarget = &mockTarget{
		tools: tools,
		call: func(name string, _ map[string]any) types.ToolResult {
			ct.called[name]++
			return types.ToolResult{Text: "ok"}
		},
	}
	return ct
}

func injectionWith(t *testing.T, cfg registry.Config) *Injection {
	t.Helper()
	p, err := NewInjection(cfg)
	if err != nil {
		t.Fatalf("NewInjection: %v", err)
	}
	return p.(*Injection)
}

// TestPolicy_SkipsDestructiveByDefault: a tool the server annotates as
// destructive must not be invoked unless the operator opts in.
func TestPolicy_SkipsDestructiveByDefault(t *testing.T) {
	destructive := annotatedTool("delete_account", "id", types.MCPToolAnnotations{Destructive: ptrBool(true)})
	target := newCountingTarget([]map[string]any{destructive})

	p := injectionWith(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 0 {
		t.Errorf("expected no attempts against a destructive tool by default, got %d", len(attempts))
	}
	if target.called["delete_account"] != 0 {
		t.Errorf("destructive tool was invoked %d times, want 0", target.called["delete_account"])
	}
}

// TestPolicy_AllowDestructiveOptIn: allow_destructive=true tests destructive tools.
func TestPolicy_AllowDestructiveOptIn(t *testing.T) {
	destructive := annotatedTool("delete_account", "id", types.MCPToolAnnotations{Destructive: ptrBool(true)})
	target := newCountingTarget([]map[string]any{destructive})

	p := injectionWith(t, registry.Config{"allow_destructive": true})
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 || target.called["delete_account"] == 0 {
		t.Errorf("with allow_destructive the destructive tool should be tested; attempts=%d calls=%d", len(attempts), target.called["delete_account"])
	}
}

// TestPolicy_UnannotatedAndReadOnlyAreTested: tools with no annotations (the
// common case, e.g. DVMCP) and read-only tools must be tested by default — a
// scanner's worst outcome is a silent false negative.
func TestPolicy_UnannotatedAndReadOnlyAreTested(t *testing.T) {
	plain := stringTool("search", "q") // no annotations
	readonly := annotatedTool("get_status", "id", types.MCPToolAnnotations{ReadOnly: true})
	target := newCountingTarget([]map[string]any{plain, readonly})

	p := injectionWith(t, registry.Config{})
	if _, err := p.Probe(context.Background(), target); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if target.called["search"] == 0 {
		t.Error("unannotated tool was not tested, want tested")
	}
	if target.called["get_status"] == 0 {
		t.Error("read-only tool was not tested, want tested")
	}
}

// TestPolicy_Allowlist: with an allow-list, only listed tools are tested.
func TestPolicy_Allowlist(t *testing.T) {
	target := newCountingTarget([]map[string]any{
		stringTool("keep", "q"),
		stringTool("drop", "q"),
	})

	p := injectionWith(t, registry.Config{"tool_allowlist": []string{"keep"}})
	if _, err := p.Probe(context.Background(), target); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if target.called["keep"] == 0 {
		t.Error("allow-listed tool was not tested")
	}
	if target.called["drop"] != 0 {
		t.Errorf("non-allow-listed tool was tested %d times, want 0", target.called["drop"])
	}
}

// TestPolicy_Denylist: deny-listed tools are never tested.
func TestPolicy_Denylist(t *testing.T) {
	target := newCountingTarget([]map[string]any{
		stringTool("safe", "q"),
		stringTool("forbidden", "q"),
	})

	p := injectionWith(t, registry.Config{"tool_denylist": []string{"forbidden"}})
	if _, err := p.Probe(context.Background(), target); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if target.called["safe"] == 0 {
		t.Error("non-denied tool was not tested")
	}
	if target.called["forbidden"] != 0 {
		t.Errorf("deny-listed tool was tested %d times, want 0", target.called["forbidden"])
	}
}
