package mcptool

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// nestedAdminTool is adminTool with both interesting parameters moved one level
// down, inside an object. Nothing else changes.
//
// This is the shape the flat parser could not read at all: it looked at
// top-level "properties", found only "auth", and reported a tool with no
// credential argument and no authority selector. The probe then had nothing to
// compare and returned a clean result for a tool it had never tested.
func nestedAdminTool() map[string]any {
	return map[string]any{
		"name": "manage_access",
		"description": "Manage access to a system\n" +
			"            Args:\n" +
			"                system: The system to access (e.g., \"database\", \"webserver\")\n" +
			"                auth_token: Optional authentication token for privileged operations\n",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"auth": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"system":     map[string]any{"type": "string"},
						"auth_token": map[string]any{"type": "string"},
					},
					"required": []any{"system"},
				},
			},
			"required": []any{"auth"},
		},
	}
}

// TestFunctionAuthorization_ReachesNestedCredentialArgument is the migration's
// reason for existing: a credential argument nested inside an object must be
// found, and the forged value must be written INSIDE that object rather than
// beside it. A payload placed at the top level is silently ignored by the
// server, so the two legs of the differential become the same request and a
// vulnerable target reports clean.
func TestFunctionAuthorization_ReachesNestedCredentialArgument(t *testing.T) {
	var sawNestedToken bool
	target := &mockTarget{
		tools: []map[string]any{nestedAdminTool()},
		call: func(_ string, args map[string]any) types.ToolResult {
			auth, _ := args["auth"].(map[string]any)
			if _, stray := args["auth_token"]; stray {
				t.Error("the credential was written at the top level, where this server does not read it")
			}
			if tok, ok := auth["auth_token"].(string); ok && tok != "" {
				sawNestedToken = true
				return types.ToolResult{Text: "privileged access granted; admin console attached"}
			}
			return types.ToolResult{Text: "access denied: authentication required"}
		},
	}
	p := newFunctionAuthzProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !sawNestedToken {
		t.Fatal("no call ever carried a value at auth.auth_token; the nested credential argument was not reached")
	}
	if got := maxAuthzScore(t, attempts); got != 1.0 {
		t.Errorf("presence-mistaken-for-validity on a nested credential scored %v, want 1.0", got)
	}
	// The finding must name the parameter by its PATH. A bare leaf name cannot
	// tell a reader which of two same-named arguments was tested, and cannot be
	// replayed.
	var sawPath bool
	for _, a := range attempts {
		if a.Metadata[mcpprobe.MetaAuthParam] == "auth.auth_token" {
			sawPath = true
		}
	}
	if !sawPath {
		t.Error("no attempt recorded the parameter as auth.auth_token; a finding cannot say which argument was tested")
	}
}

// TestTokenValidation_ReachesNestedCredentialArgument is the same regression for
// the credential-verification probe: a token parameter nested inside an object
// must receive the candidate values, at its own path.
func TestTokenValidation_ReachesNestedCredentialArgument(t *testing.T) {
	tool := map[string]any{
		"name":        "verify_session",
		"description": "Verify a session credential",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"credentials": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"session_token": map[string]any{"type": "string"},
					},
					"required": []any{"session_token"},
				},
			},
			"required": []any{"credentials"},
		},
	}
	var nested int
	target := &mockTarget{
		tools: []map[string]any{tool},
		call: func(_ string, args map[string]any) types.ToolResult {
			creds, _ := args["credentials"].(map[string]any)
			tok, _ := creds["session_token"].(string)
			if tok == "" {
				return types.ToolResult{Text: "missing session token"}
			}
			nested++
			// Format-only validation: any 32-char hex value is accepted.
			if len(tok) == 32 {
				return types.ToolResult{Text: "session valid; welcome back"}
			}
			return types.ToolResult{Text: "invalid session token"}
		},
	}
	p, err := NewTokenValidation(registry.Config{})
	if err != nil {
		t.Fatalf("NewTokenValidation: %v", err)
	}
	if _, err := p.Probe(context.Background(), target); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if nested == 0 {
		t.Fatal("no call ever carried a value at credentials.session_token; the nested credential parameter was not reached")
	}
}
