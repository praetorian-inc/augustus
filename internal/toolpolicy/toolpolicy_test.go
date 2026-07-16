package toolpolicy_test

import (
	"testing"

	"github.com/praetorian-inc/augustus/internal/toolpolicy"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func ptrBool(b bool) *bool { return &b }

// stringTool returns a minimal tool map with a single string parameter.
func stringTool(name string) map[string]any {
	return map[string]any{
		"name": name,
		"parameters": map[string]any{
			"type":       "object",
			"properties": map[string]any{"q": map[string]any{"type": "string"}},
		},
	}
}

// annotatedTool attaches an MCPToolAnnotations VALUE under "annotations", exactly
// as the ListTools / ToolMaps paths produce.
func annotatedTool(name string, ann types.MCPToolAnnotations) map[string]any {
	tm := stringTool(name)
	tm["annotations"] = ann
	return tm
}

// TestNew_Allowlist: with an allow-list, only listed tools survive Skip.
func TestSkip_Allowlist(t *testing.T) {
	p := toolpolicy.New(registry.Config{"tool_allowlist": []string{"keep"}})

	if skip, _ := p.Skip("keep", nil); skip {
		t.Error("allow-listed tool must not be skipped")
	}
	skip, reason := p.Skip("other", nil)
	if !skip {
		t.Error("tool absent from allow-list must be skipped")
	}
	if reason == "" {
		t.Error("skip must carry a reason")
	}
}

// TestSkip_Denylist: deny-listed tools are always skipped.
func TestSkip_Denylist(t *testing.T) {
	p := toolpolicy.New(registry.Config{"tool_denylist": []string{"forbidden"}})

	if skip, _ := p.Skip("safe", nil); skip {
		t.Error("non-denied tool must not be skipped")
	}
	if skip, _ := p.Skip("forbidden", nil); !skip {
		t.Error("deny-listed tool must be skipped")
	}
}

// TestSkip_DestructiveAnnotation: a tool the server annotates destructive is
// skipped by default.
func TestSkip_DestructiveAnnotation(t *testing.T) {
	p := toolpolicy.New(registry.Config{})
	tm := map[string]any{"annotations": types.MCPToolAnnotations{Destructive: ptrBool(true)}}

	if skip, _ := p.Skip("delete_account", tm); !skip {
		t.Error("destructive-annotated tool must be skipped by default")
	}
}

// TestSkip_AllowDestructive: allow_destructive=true keeps a destructive tool.
func TestSkip_AllowDestructive(t *testing.T) {
	p := toolpolicy.New(registry.Config{"allow_destructive": true})
	tm := map[string]any{"annotations": types.MCPToolAnnotations{Destructive: ptrBool(true)}}

	if skip, _ := p.Skip("delete_account", tm); skip {
		t.Error("allow_destructive=true must keep a destructive tool")
	}
}

// TestSkip_NoAnnotationsKept: a tool with no annotations is kept (nil-safe), even
// with a destructive-sounding name — the policy gates on annotations, not names.
func TestSkip_NoAnnotationsKept(t *testing.T) {
	p := toolpolicy.New(registry.Config{})

	if skip, _ := p.Skip("delete_order", map[string]any{}); skip {
		t.Error("tool with no annotations must be kept")
	}
}

// TestSkip_NilMapAppliesAllowDenyOnly: Skip(name, nil) must not panic and must
// apply allow/deny but never the annotation check (a nil map read is zero/false).
func TestSkip_NilMapAppliesAllowDenyOnly(t *testing.T) {
	p := toolpolicy.New(registry.Config{"tool_denylist": []string{"forbidden"}})

	if skip, _ := p.Skip("anything", nil); skip {
		t.Error("nil tool map with no allow/deny hit must be kept")
	}
	if skip, _ := p.Skip("forbidden", nil); !skip {
		t.Error("nil tool map must still honor the deny-list")
	}
}

// TestFilter_DropsRightSubset: Filter keeps exactly the permitted tools.
func TestFilter_DropsRightSubset(t *testing.T) {
	p := toolpolicy.New(registry.Config{})
	tools := []map[string]any{
		stringTool("search"), // kept (no annotations)
		annotatedTool("get_status", types.MCPToolAnnotations{ReadOnly: true}),       // kept (read-only)
		annotatedTool("wipe", types.MCPToolAnnotations{Destructive: ptrBool(true)}), // dropped
	}

	kept := p.Filter("test", tools)
	got := map[string]bool{}
	for _, tm := range kept {
		got[tm["name"].(string)] = true
	}
	if !got["search"] || !got["get_status"] {
		t.Errorf("expected search + get_status kept, got %v", got)
	}
	if got["wipe"] {
		t.Error("destructive tool wipe must be dropped by Filter")
	}
	if len(kept) != 2 {
		t.Errorf("expected 2 kept tools, got %d", len(kept))
	}
}
