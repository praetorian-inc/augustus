package mcptool

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/types"
)

// Regression tests for two false positives measured against DVMCP challenges the
// auth probes do not own. Both were invisible to this branch's own validation,
// which covered only the two challenges it targets — so both are locked in here.

// TestFunctionAuthorization_NoDeclaredValuesDoesNotFire covers a lookup tool whose
// parameter has a conventional name but no declared values.
//
// Measured on DVMCP challenge 1: `get_user_info(username)` — no declared values —
// returned the admin account's profile for username=admin while the controls,
// being random strings the server had never heard of, returned nothing. The
// differential scored 1.0.
//
// That is a real issue (an unauthenticated caller enumerating privileged accounts)
// but it is information disclosure, not function-level authorization: the tool is a
// lookup, not a privileged operation. Without declared values there is no "ordinary
// authority" on the target to compare against, so the check measures
// known-versus-unknown identifier rather than unprivileged-versus-privileged.
//
// Generalised, it fires on any tool that takes an identifier and returns
// information about it — get_profile, search_users, lookup_account.
func TestFunctionAuthorization_NoDeclaredValuesDoesNotFire(t *testing.T) {
	lookup := map[string]any{
		"name":        "get_user_info",
		"description": "Get information about a user\n            Args:\n                username: The username to look up\n",
		"parameters": map[string]any{
			"type":       "object",
			"properties": map[string]any{"username": map[string]any{"type": "string"}},
			"required":   []any{"username"},
		},
	}

	target := &mockTarget{
		tools: []map[string]any{lookup},
		call: func(_ string, args map[string]any) types.ToolResult {
			// Exactly the real server's behaviour: a known account returns a rich
			// profile, anything unknown returns nothing.
			user, _ := args["username"].(string)
			switch strings.ToLower(user) {
			case "admin":
				return types.ToolResult{Text: "User information for admin: System administrator with full access"}
			case "alice":
				return types.ToolResult{Text: "User information for alice: Regular user"}
			default:
				return types.ToolResult{Text: fmt.Sprintf("No user found for %q", user)}
			}
		},
	}

	attempts, err := newFunctionAuthzProbe(t, nil).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := maxAuthzScore(t, attempts); got >= 0.5 {
		t.Errorf("top score = %v, want below 0.5; a lookup tool with no declared values has no ordinary authority to differ from", got)
	}
}

// TestFunctionAuthorization_DeclaredValuesStillFire is the paired positive: the same
// shape WITH declared values must still be caught, so the fix above narrowed the
// check rather than disabling it.
func TestFunctionAuthorization_DeclaredValuesStillFire(t *testing.T) {
	target := &mockTarget{
		tools: []map[string]any{adminTool()},
		call: func(_ string, args map[string]any) types.ToolResult {
			system, _ := args["system"].(string)
			_, hasToken := args["auth_token"]
			if system == "admin-console" {
				if hasToken {
					return types.ToolResult{Text: "Admin command executed on admin-console"}
				}
				return types.ToolResult{Text: "Error: Authentication required for admin-console access"}
			}
			// The refusal enumerates the accepted values, including the privileged
			// one — the target disclosing its own answer.
			return types.ToolResult{Text: fmt.Sprintf("Error: System %q not found. Available systems: database, webserver, fileserver, admin-console", system)}
		},
	}

	attempts, err := newFunctionAuthzProbe(t, nil).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := maxAuthzScore(t, attempts); got < 0.5 {
		t.Errorf("top score = %v, want a finding; the target declares values AND discloses the privileged one in its refusal", got)
	}
}

// TestTokenValidation_ReadOnlyNonIssuerDoesNotFire covers an idempotent tool that
// is not a credential issuer.
//
// Measured on DVMCP challenge 10: `get_config` was sampled twice, returned the same
// configuration value both times — correct, deterministic behaviour for a config
// reader — and was reported as predictable credential issuance at 1.0.
//
// The cause was a selection condition that accepted a tool if it was issuer-named
// OR read-only. Read-only means it is SAFE to call twice, never that it hands out
// credentials. Generalised, it fires on every idempotent tool whose response looks
// credential-shaped: config getters, version endpoints, status and health checks.
func TestTokenValidation_ReadOnlyNonIssuerDoesNotFire(t *testing.T) {
	configReader := map[string]any{
		"name":        "get_config",
		"description": "Get a configuration value from the system\n            Args:\n                config_name: The name of the configuration to retrieve\n",
		"parameters": map[string]any{
			"type":       "object",
			"properties": map[string]any{"config_name": map[string]any{"type": "string"}},
			"required":   []any{"config_name"},
		},
		"annotations": types.MCPToolAnnotations{ReadOnly: true},
	}

	target := &mockTarget{
		tools: []map[string]any{configReader},
		call: func(_ string, _ map[string]any) types.ToolResult {
			// Deterministic by design, and token-shaped enough to have tripped the
			// credential extractor.
			return types.ToolResult{Text: "Configuration: dvmcp_challenge10"}
		},
	}

	attempts, err := newTokenValidationProbe(t, nil).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := maxTokenScore(t, attempts); got >= 0.5 {
		t.Errorf("top score = %v, want below 0.5; an idempotent config reader returning the same value twice is correct behaviour, not predictable issuance", got)
	}
}

// TestFunctionAuthorization_PayloadParamNotSwept is the regression for a
// misclassification found on an independent lab.
//
// `execute_system_command(command)` scored 1.0 because a conventional privileged
// name happened to be a runnable command while the controls were not. That is
// real remote code execution — and mcptool.Injection reports it correctly — but
// filing it as an authorization bypass puts a real finding under the wrong risk
// slug, with the wrong impact and the wrong remediation.
//
// On a payload parameter any novel value produces novel behaviour, so a response
// differential proves nothing about authorization.
func TestFunctionAuthorization_PayloadParamNotSwept(t *testing.T) {
	execTool := map[string]any{
		"name":        "execute_system_command",
		"description": "Executes a system command\n            Args:\n                command: The command to run (ls, pwd, whoami)\n",
		"parameters": map[string]any{
			"type":       "object",
			"properties": map[string]any{"command": map[string]any{"type": "string"}},
			"required":   []any{"command"},
		},
	}

	target := &mockTarget{
		tools: []map[string]any{execTool},
		call: func(_ string, args map[string]any) types.ToolResult {
			cmd, _ := args["command"].(string)
			// A real shell: recognised commands produce output, others fail. Exactly
			// the shape that made the differential fire.
			switch strings.ToLower(cmd) {
			case "ls", "pwd", "whoami", "sa", "root":
				return types.ToolResult{Text: fmt.Sprintf("Command executed successfully!\nCommand: %s\nOutput: ok", cmd)}
			default:
				return types.ToolResult{Text: fmt.Sprintf("Command execution failed!\nCommand: %s\nError: command not found", cmd)}
			}
		},
	}

	attempts, err := newFunctionAuthzProbe(t, nil).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := maxAuthzScore(t, attempts); got >= 0.5 {
		t.Errorf("top score = %v, want below 0.5; a payload parameter is not an authority selector", got)
	}
}
