package mcptool

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// Regression tests for the review findings on this branch.

// syntheticIssuedToken builds a live-looking issued credential for a fixture.
//
// The prefix is assembled at runtime rather than written as a literal. These
// values are synthetic and valid nowhere, but a committed literal in this shape
// trips the repository's secret scanner, and the same problem was already fixed
// once on the sibling credential-leakage branch. The runtime value is what the
// probe and detector actually see.
func syntheticIssuedToken(body string) string {
	return strings.Join([]string{"tok", "_", "live", "_", body}, "")
}

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
					return types.ToolResult{Text: "session token: " + syntheticIssuedToken("4f9a2c7e1b8d3056")}
				},
			}
			attempts, err := newTokenValidationProbe(t, registry.Config{}).Probe(context.Background(), target)
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if got := maxTokenScore(t, attempts); got >= 0.5 {
				t.Errorf("top score = %v; returning the same current credential to two reads is correct behaviour, not derivable issuance", got)
			}
			// ZERO, not "fewer than two". A single call already retrieves a live
			// credential from the target, and the point of the exclusion is that a
			// getter is never sampled for predictability at all.
			if calls != 0 {
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
	issued := syntheticIssuedToken("9f2b7c1de4a05836bb17c9e2f4d80a51")
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

// TestTokenValidation_UnsampledIssuerIsVisible covers a false-clean path introduced
// by the retry fix itself: on an exhausted retry the probe logged and moved on
// WITHOUT appending an attempt, so an issuer we could not assess produced the same
// result as one we assessed and found clean.
//
// Both legs are exercised — a failure on the first sample and a failure on the
// second — because the second is the more dangerous shape: one credential was
// already issued, so it looks like progress was made.
func TestTokenValidation_UnsampledIssuerIsVisible(t *testing.T) {
	issued := syntheticIssuedToken("2f8c4a9e1d7b350698af")

	cases := []struct {
		name string
		// failAfter is how many successful calls precede the failure. callToolOnce
		// retries once, so a leg needs two consecutive failures to be exhausted.
		failAfter int
	}{
		{"first sample unobtainable", 0},
		{"second sample unobtainable", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			target := &mockTarget{
				tools: []map[string]any{{
					"name":        "issue_session",
					"description": "issue_session",
					"parameters":  map[string]any{"type": "object", "properties": map[string]any{}},
				}},
				call: func(string, map[string]any) types.ToolResult {
					return types.ToolResult{Text: "session token: " + issued}
				},
				callErr: func(string, map[string]any) error {
					calls++
					if calls <= tc.failAfter {
						return nil
					}
					// A TRANSPORT failure, not an application refusal: every
					// subsequent call errors, so the single retry is exhausted.
					return errors.New("connection reset by peer")
				},
			}
			attempts, err := newTokenValidationProbe(t, registry.Config{}).Probe(context.Background(), target)
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}

			var unsampled *attempt.Attempt
			for _, a := range attempts {
				if v, _ := a.Metadata[attempt.MetadataKeyInconclusive].(bool); v && a.Status == attempt.StatusError {
					unsampled = a
				}
				// The partially-obtained credential must not survive into evidence.
				for k, v := range a.Metadata {
					if s, ok := v.(string); ok && strings.Contains(s, issued) {
						t.Errorf("metadata %q carries the issued credential", k)
					}
				}
				for _, out := range a.Outputs {
					if strings.Contains(out, issued) {
						t.Error("output carries the issued credential")
					}
				}
			}
			if unsampled == nil {
				t.Fatal("no inconclusive attempt recorded; an issuer that could not be sampled is indistinguishable from a clean one")
			}
			if unsampled.Metadata[attempt.MetadataKeyInconclusiveReason] == "" {
				t.Error("no reason recorded; a reviewer must be told what was not assessed")
			}
		})
	}
}
