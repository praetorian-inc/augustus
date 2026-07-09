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
