package toolsec

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// unixPasswdSample is a fixed excerpt of a real /etc/passwd that the mock
// vulnerable tool returns; the "root:x:0:0:" signature is what the detector
// hunts for.
const unixPasswdSample = "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/usr/sbin/nologin\n"

func newPathTraversalProbe(t *testing.T) *PathTraversal {
	t.Helper()
	p, err := NewPathTraversal(registry.Config{})
	if err != nil {
		t.Fatalf("NewPathTraversal: %v", err)
	}
	return p.(*PathTraversal)
}

// TestPathTraversal_DetectsRead: a tool that resolves the payload as a
// filesystem path and returns the file contents is flagged.
func TestPathTraversal_DetectsRead(t *testing.T) {
	p := newPathTraversalProbe(t)

	target := &mockTarget{
		tools: []map[string]any{stringTool("read", "filepath")},
		call: func(_ string, args map[string]any) types.ToolResult {
			path, _ := args["filepath"].(string)
			// Vulnerable: naive traversal, no canonicalisation, so any payload
			// ending in etc/passwd (with any prefix) reads the file.
			if strings.Contains(path, "etc/passwd") {
				return types.ToolResult{Text: unixPasswdSample}
			}
			return types.ToolResult{Text: "not found"}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("Probe produced no attempts")
	}

	det := &pathTraversalDetectorStub{}
	fired := false
	for _, a := range attempts {
		for _, s := range det.detect(a) {
			if s == 1.0 {
				fired = true
			}
		}
	}
	if !fired {
		t.Errorf("expected traversal to be flagged")
	}
}

// TestPathTraversal_NoFalsePositiveOnEcho: a tool that reflects the payload
// verbatim must not be flagged — the file-content signature never appears in
// any payload text.
func TestPathTraversal_NoFalsePositiveOnEcho(t *testing.T) {
	p := newPathTraversalProbe(t)

	target := &mockTarget{
		tools: []map[string]any{stringTool("read", "filepath")},
		call: func(_ string, args map[string]any) types.ToolResult {
			path, _ := args["filepath"].(string)
			return types.ToolResult{Text: "read " + path}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	det := &pathTraversalDetectorStub{}
	for _, a := range attempts {
		for _, s := range det.detect(a) {
			if s != 0.0 {
				t.Errorf("echo tool falsely flagged (score %v) for output %q", s, a.Outputs)
			}
		}
	}
}

// TestPathTraversal_SkipsNonPathParam: a tool whose only string param has no
// path-like name is skipped by default (allParams=false).
func TestPathTraversal_SkipsNonPathParam(t *testing.T) {
	p := newPathTraversalProbe(t)

	target := &mockTarget{
		tools: []map[string]any{stringTool("greet", "message")},
		call: func(_ string, args map[string]any) types.ToolResult {
			return types.ToolResult{Text: "hi"}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 0 {
		t.Errorf("expected non-path param to be skipped, got %d attempts", len(attempts))
	}
}

// TestPathTraversal_AllParamsMode: with pathtraversal_all_string_params=true
// every string param is exercised, including one whose name doesn't match the
// path-like regex.
func TestPathTraversal_AllParamsMode(t *testing.T) {
	pr, err := NewPathTraversal(registry.Config{"pathtraversal_all_string_params": true})
	if err != nil {
		t.Fatalf("NewPathTraversal: %v", err)
	}
	p := pr.(*PathTraversal)

	target := &mockTarget{
		tools: []map[string]any{stringTool("greet", "message")},
		call: func(_ string, args map[string]any) types.ToolResult {
			return types.ToolResult{Text: "hi"}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Errorf("all-params mode should have exercised the non-path param")
	}
}

// stringToolWithDescription builds a tool descriptor with a custom
// description — used to seed extractHintedPrefixes with a disclosed gate
// like "Only files in /tmp/safe/ are accessible".
func stringToolWithDescription(name, param, description string) map[string]any {
	t := stringTool(name, param)
	t["description"] = description
	return t
}

// TestPathTraversal_PrefixAppendDefeatsStartsWithGate: a tool whose
// description discloses the allowed prefix ("Only files in /tmp/safe/ are
// accessible") AND whose sink applies filename.startswith("/tmp/safe/")
// MUST be caught by the prefix-append payload variants. The base payload
// set on its own (bare "../../etc/passwd") fails the gate; only the
// description-derived prefix-append (/tmp/safe/..././etc/passwd) defeats
// it. This is the pathtraversal differentiator (see Mauro B3 review).
func TestPathTraversal_PrefixAppendDefeatsStartsWithGate(t *testing.T) {
	p := newPathTraversalProbe(t)

	target := &mockTarget{
		tools: []map[string]any{stringToolWithDescription(
			"read", "filename",
			"Read a file. Only files in /tmp/safe/ are accessible.",
		)},
		call: func(_ string, args map[string]any) types.ToolResult {
			path, _ := args["filename"].(string)
			// Vulnerable gate: literal startsWith with no canonicalisation.
			if !strings.HasPrefix(path, "/tmp/safe/") {
				return types.ToolResult{Text: "Error: access denied to " + path}
			}
			// Naive resolution: the payload resolves outside the gate.
			if strings.Contains(path, "etc/passwd") {
				return types.ToolResult{Text: unixPasswdSample}
			}
			return types.ToolResult{Text: "empty"}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	det := &pathTraversalDetectorStub{}
	// Split attempts into base (no prefix) and prefix-append (starts
	// with the disclosed /tmp/safe/) and confirm the differentiator:
	// base = all safe (gated), prefix = at least one VULN.
	baseFired, prefixFired := false, false
	for _, a := range attempts {
		hasPrefix := strings.HasPrefix(a.Prompt, "/tmp/safe/")
		fired := false
		for _, s := range det.detect(a) {
			if s == 1.0 {
				fired = true
			}
		}
		if hasPrefix && fired {
			prefixFired = true
		}
		if !hasPrefix && fired {
			baseFired = true
		}
	}
	if baseFired {
		t.Errorf("base payload set defeated a startsWith gate — that shouldn't happen and means this test doesn't validate the prefix-append path")
	}
	if !prefixFired {
		t.Errorf("prefix-append variant should have defeated the startsWith gate; the description-driven payload generation is broken")
	}
}

// TestPathTraversal_SkipsDestructiveTools: PathTraversal MUST NOT send
// payloads into tools whose name matches destructiveToolRE (save_report,
// delete_file, write_log, ...). Landing a traversal payload in a write
// sink could overwrite files outside the sandbox; we stay read-only.
// Opt-out via pathtraversal_all_string_params=true. Regression guard for
// Mauro S1.
func TestPathTraversal_SkipsDestructiveTools(t *testing.T) {
	p := newPathTraversalProbe(t)

	target := &mockTarget{
		tools: []map[string]any{
			stringTool("save_report", "filepath"), // destructive verb, path-like param
			stringTool("delete_file", "path"),     // ditto
			stringTool("write_log", "filename"),   // ditto
			stringToolWithDescription("read_file", "filename",
				"Read a file"), // read-only companion
		},
		call: func(name string, args map[string]any) types.ToolResult {
			return types.ToolResult{Text: "called " + name}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for _, a := range attempts {
		toolMeta, _ := a.GetMetadata("toolsec.tool")
		tool, _ := toolMeta.(string)
		switch tool {
		case "save_report", "delete_file", "write_log":
			t.Errorf("destructive tool %q was invoked with traversal payload — must be skipped", tool)
		case "read_file":
			// expected
		}
	}
}

// TestExtractHintedPrefixes covers the description-parsing helper directly.
func TestExtractHintedPrefixes(t *testing.T) {
	tests := []struct {
		desc string
		want []string
	}{
		{"", nil},
		{"no fs paths here", nil},
		{"URL routes like /api/v1/read should not be treated as fs prefixes", nil},
		{"Only files in /tmp/safe/ are accessible", []string{"/tmp/safe/"}},
		{"Files under /var/log/ and /tmp/uploads/ allowed", []string{"/var/log/", "/tmp/uploads/"}},
		{"Reads files from C:\\Users\\Public\\Reports\\", []string{`C:\Users\Public\Reports\`}},
	}
	for _, tt := range tests {
		got := extractHintedPrefixes(tt.desc)
		if len(got) != len(tt.want) {
			t.Errorf("extractHintedPrefixes(%q) = %v, want %v", tt.desc, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("extractHintedPrefixes(%q)[%d] = %q, want %q", tt.desc, i, got[i], tt.want[i])
			}
		}
	}
}

// TestPathTraversal_SkipsNonToolInvoker: a non-ToolInvoker target yields no
// attempts.
func TestPathTraversal_SkipsNonToolInvoker(t *testing.T) {
	p := newPathTraversalProbe(t)
	attempts, err := p.Probe(context.Background(), plainGen{})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if attempts != nil {
		t.Errorf("expected nil attempts for non-ToolInvoker target, got %d", len(attempts))
	}
}

// pathTraversalDetectorStub re-implements the signature check locally so the
// probe test does not depend on the detector package.
type pathTraversalDetectorStub struct{}

func (pathTraversalDetectorStub) detect(a *attempt.Attempt) []float64 {
	scores := make([]float64, len(a.Outputs))
	raw, ok := a.GetMetadata(attempt.MetadataKeyPathTraversalSignatures)
	if !ok {
		return scores
	}
	sigs, _ := raw.([]string)
	for i, out := range a.Outputs {
		for _, s := range sigs {
			if s != "" && strings.Contains(out, s) {
				scores[i] = 1.0
			}
		}
	}
	return scores
}
