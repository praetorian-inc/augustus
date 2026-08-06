package mcptool

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// Regression tests for the review findings on this branch.

// TestFunctionAuthorization_DoesNotInvokeUnannotatedDestructiveTools is the most
// consequential fix on this branch.
//
// The probe proves a missing authorization boundary by PERFORMING the privileged
// operation, and its privileged-name vocabulary deliberately includes delete,
// shutdown, restart and revoke. internal/toolpolicy keeps unannotated tools on
// purpose — "a scanner's worst outcome is a silent false negative" — which is the
// right trade for a probe sending an inert payload and the wrong one here, because
// the evidence-gathering IS the damage.
//
// Measured: most real MCP servers ship no annotations at all, so an unannotated
// `delete_user` is the common case rather than an edge case.
func TestFunctionAuthorization_DoesNotInvokeUnannotatedDestructiveTools(t *testing.T) {
	destructive := []string{"delete_user_account", "shutdown_admin_service", "revoke_user_token", "reset_admin_password"}
	for _, name := range destructive {
		t.Run(name, func(t *testing.T) {
			var called []string
			tool := map[string]any{
				"name":        name,
				"description": "Args:\n    role: The role to act as (user, admin)\n",
				"parameters": map[string]any{
					"type":       "object",
					"properties": map[string]any{"role": map[string]any{"type": "string", "enum": []any{"user", "admin"}}},
					"required":   []any{"role"},
				},
			}
			target := &mockTarget{
				tools: []map[string]any{tool},
				call: func(n string, _ map[string]any) types.ToolResult {
					called = append(called, n)
					return types.ToolResult{Text: "done"}
				},
			}
			if _, err := newFunctionAuthzProbe(t, nil).Probe(context.Background(), target); err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if len(called) != 0 {
				t.Errorf("invoked %v; an irreversible unannotated operation must not be performed to prove a boundary", called)
			}
		})
	}
}

// TestFunctionAuthorization_InvokesWhenAnnotatedReadOnly is the paired positive: a
// server annotation is authoritative, so a read-only-annotated tool with a
// destructive-sounding name is still assessed. The gate narrows the sweep on
// UNKNOWN tools only.
func TestFunctionAuthorization_InvokesWhenAnnotatedReadOnly(t *testing.T) {
	tool := map[string]any{
		"name":        "delete_preview",
		"description": "Args:\n    role: The role to act as (user, admin)\n",
		"annotations": types.MCPToolAnnotations{ReadOnly: true},
		"parameters": map[string]any{
			"type":       "object",
			"properties": map[string]any{"role": map[string]any{"type": "string", "enum": []any{"user", "admin"}}},
			"required":   []any{"role"},
		},
	}
	var called int
	target := &mockTarget{
		tools: []map[string]any{tool},
		call: func(string, map[string]any) types.ToolResult {
			called++
			return types.ToolResult{Text: "previewed"}
		},
	}
	if _, err := newFunctionAuthzProbe(t, nil).Probe(context.Background(), target); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if called == 0 {
		t.Error("a ReadOnly-annotated tool was skipped; the annotation is authoritative and must re-admit it")
	}
}

// TestFunctionAuthorization_DestructiveOptInRestoresSweep proves the escape hatch
// works, so an operator who accepts the risk is not silently blocked.
func TestFunctionAuthorization_DestructiveOptInRestoresSweep(t *testing.T) {
	tool := map[string]any{
		"name":        "delete_user_account",
		"description": "Args:\n    role: The role to act as (user, admin)\n",
		"parameters": map[string]any{
			"type":       "object",
			"properties": map[string]any{"role": map[string]any{"type": "string", "enum": []any{"user", "admin"}}},
			"required":   []any{"role"},
		},
	}
	var called int
	target := &mockTarget{
		tools: []map[string]any{tool},
		call: func(string, map[string]any) types.ToolResult {
			called++
			return types.ToolResult{Text: "done"}
		},
	}
	p := newFunctionAuthzProbe(t, registry.Config{"authz_allow_destructive": true})
	if _, err := p.Probe(context.Background(), target); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if called == 0 {
		t.Error("authz_allow_destructive=true did not restore the sweep")
	}
}

// TestTokenValidation_SkipsGetterNamedIssuers covers a false positive arriving
// through the name vocabulary rather than the read-only gate.
//
// issuerToolNameRE matches `token` and `session` as segments, so `get_session_token`
// qualified as an issuing surface. A getter that correctly returns the caller's
// stable current credential returns the SAME value to two reads, which is exactly
// the signal the predictability check reads as derivable issuance — so correct
// behaviour scored 1.0. This is the same shape already measured on a configuration
// reader.
func TestTokenValidation_SkipsGetterNamedIssuers(t *testing.T) {
	for _, name := range []string{"get_session_token", "get_current_token", "read_session", "describe_token"} {
		t.Run(name, func(t *testing.T) {
			var calls int
			tool := map[string]any{
				"name":        name,
				"description": name,
				"parameters":  map[string]any{"type": "object", "properties": map[string]any{}},
			}
			target := &mockTarget{
				tools: []map[string]any{tool},
				call: func(string, map[string]any) types.ToolResult {
					calls++
					// A stable current credential: correct, deterministic behaviour.
					return types.ToolResult{Text: "session token: 4f9a2c7e1b8d3056"}
				},
			}
			attempts, err := newTokenValidationProbe(t, registry.Config{}).Probe(context.Background(), target)
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if got := maxTokenScore(t, attempts); got >= 0.5 {
				t.Errorf("top score = %v; returning the same current credential to two reads is correct behaviour, not derivable issuance", got)
			}
			if calls >= 2 {
				t.Errorf("getter was sampled %d times; it should not be sampled for predictability at all", calls)
			}
		})
	}
}

// TestTokenValidation_IssuedCredentialsAreNotStoredVerbatim covers a finding whose
// consequence is the report itself: the two sampled values are LIVE credentials the
// target just issued, so recording them put working credentials into attempt
// metadata, the JSONL report and every downstream consumer.
//
// The probe now compares in memory and records only the relation plus redacted
// evidence.
func TestTokenValidation_IssuedCredentialsAreNotStoredVerbatim(t *testing.T) {
	const issued = "tok_live_9f2b7c1de4a05836bb17c9e2f4d80a51"
	tool := map[string]any{
		"name":        "issue_session",
		"description": "issue_session",
		"parameters":  map[string]any{"type": "object", "properties": map[string]any{}},
	}
	target := &mockTarget{
		tools: []map[string]any{tool},
		call: func(string, map[string]any) types.ToolResult {
			return types.ToolResult{Text: "session token: " + issued}
		},
	}
	attempts, err := newTokenValidationProbe(t, registry.Config{}).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	found := false
	for _, a := range attempts {
		for k, v := range a.Metadata {
			if s, ok := v.(string); ok && strings.Contains(s, issued) {
				t.Errorf("metadata %q carries the issued credential verbatim", k)
			}
		}
		for _, out := range a.Outputs {
			if strings.Contains(out, issued) {
				t.Error("attempt output carries the issued credential verbatim")
			}
		}
		if rel, ok := a.Metadata[mcpprobe.MetaAuthIssuedRelation].(string); ok && rel != "" {
			found = true
			// Identical values from two samples: the verdict must survive redaction.
			if rel != mcpprobe.RelationIdentical {
				t.Errorf("relation = %q, want %q", rel, mcpprobe.RelationIdentical)
			}
		}
	}
	if !found {
		t.Fatal("no issuance relation recorded; the predictability verdict was lost, not just redacted")
	}
	if got := maxTokenScore(t, attempts); got != 1.0 {
		t.Errorf("top score = %v, want 1.0; a surface handing every caller the same credential is predictable", got)
	}
}
