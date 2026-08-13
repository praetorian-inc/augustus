package mcptool

import (
	"context"
	"fmt"
	"strings"
	"testing"

	detmcptool "github.com/praetorian-inc/augustus/internal/detectors/mcptool"
	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func newFunctionAuthzProbe(t *testing.T, cfg registry.Config) *FunctionAuthorization {
	t.Helper()
	p, err := NewFunctionAuthorization(cfg)
	if err != nil {
		t.Fatalf("NewFunctionAuthorization: %v", err)
	}
	return p.(*FunctionAuthorization)
}

// maxAuthzScore runs the REAL detector and returns the highest score.
func maxAuthzScore(t *testing.T, attempts []*attempt.Attempt) float64 {
	t.Helper()
	det, err := detmcptool.NewFunctionAuthorizationDetector(registry.Config{})
	if err != nil {
		t.Fatalf("NewFunctionAuthorizationDetector: %v", err)
	}
	max := 0.0
	for _, a := range attempts {
		scores, err := det.Detect(context.Background(), a)
		if err != nil {
			t.Fatalf("Detect: %v", err)
		}
		for _, s := range scores {
			if s > max {
				max = s
			}
		}
	}
	return max
}

// adminTool models a privileged tool with an OPTIONAL credential argument and a
// documented authority-selecting parameter — the shape real servers ship.
func adminTool() map[string]any {
	return map[string]any{
		"name": "manage_access",
		"description": "Manage access to a system\n" +
			"            Args:\n" +
			"                system: The system to access (e.g., \"database\", \"webserver\")\n" +
			"                auth_token: Optional authentication token for privileged operations\n",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"system":     map[string]any{"type": "string"},
				"auth_token": map[string]any{"type": "string"},
			},
			"required": []any{"system"},
		},
	}
}

// ---------------------------------------------------------------------------
// Credential presence vs validity
// ---------------------------------------------------------------------------

// A server that grants privilege because a credential argument is PRESENT, without
// validating it, must fire.
func TestFunctionAuthorization_PresenceMistakenForValidityFires(t *testing.T) {
	target := &mockTarget{
		tools: []map[string]any{adminTool()},
		call: func(_ string, args map[string]any) types.ToolResult {
			// The bug: presence checked, value never validated.
			if tok, ok := args["auth_token"].(string); ok && tok != "" {
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
	if got := maxAuthzScore(t, attempts); got != 1.0 {
		t.Errorf("presence-mistaken-for-validity scored %v, want 1.0", got)
	}
}

// CONTROL — a server that validates the credential's VALUE must NOT fire: an
// invalid token is refused exactly as an absent one is.
func TestFunctionAuthorization_ValidatingServerDoesNotFire(t *testing.T) {
	target := &mockTarget{
		tools: []map[string]any{adminTool()},
		call: func(_ string, args map[string]any) types.ToolResult {
			if tok, _ := args["auth_token"].(string); tok == "the-only-valid-token" {
				return types.ToolResult{Text: "privileged access granted"}
			}
			return types.ToolResult{Text: "access denied: invalid or missing credentials"}
		},
	}
	p := newFunctionAuthzProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("Probe returned no attempts; the privileged tool must be assessed")
	}
	if got := maxAuthzScore(t, attempts); got >= 0.5 {
		t.Errorf("credential-validating server scored %v, want < 0.5 — must NOT fire", got)
	}
}

// ---------------------------------------------------------------------------
// Privilege discriminator
// ---------------------------------------------------------------------------

// A server where a conventional privileged name reaches authority its declared
// values do not must fire — and the finding is the differential, not the string.
func TestFunctionAuthorization_PrivilegeDiscriminatorFires(t *testing.T) {
	target := &mockTarget{
		tools: []map[string]any{adminTool()},
		call: func(_ string, args map[string]any) types.ToolResult {
			sys, _ := args["system"].(string)
			if strings.EqualFold(sys, "admin") {
				return types.ToolResult{Text: "root shell attached to admin plane"}
			}
			return types.ToolResult{Text: fmt.Sprintf("connected to %s with standard privileges", sys)}
		},
	}
	p := newFunctionAuthzProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := maxAuthzScore(t, attempts); got != 1.0 {
		t.Errorf("privilege discriminator scored %v, want 1.0", got)
	}
}

// CONTROL — a server that refuses undeclared discriminator values must NOT fire.
func TestFunctionAuthorization_StrictDiscriminatorDoesNotFire(t *testing.T) {
	allowed := map[string]bool{"database": true, "webserver": true}
	target := &mockTarget{
		tools: []map[string]any{adminTool()},
		call: func(_ string, args map[string]any) types.ToolResult {
			sys, _ := args["system"].(string)
			if !allowed[strings.ToLower(sys)] {
				return types.ToolResult{Text: "error: unknown system"}
			}
			if tok, _ := args["auth_token"].(string); tok != "the-only-valid-token" {
				return types.ToolResult{Text: "access denied: invalid or missing credentials"}
			}
			return types.ToolResult{Text: "connected"}
		},
	}
	p := newFunctionAuthzProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := maxAuthzScore(t, attempts); got >= 0.5 {
		t.Errorf("strict server scored %v, want < 0.5 — must NOT fire", got)
	}
}

// THE ANTI-OVERFITTING TEST. A server whose privileged value is a secret string
// appearing NOWHERE in its advertised catalog must be reported NOT vulnerable.
//
// Firing here would only be possible by hardcoding that value, which would score a
// point on this one server and find nothing in the field. Reporting it safe is the
// correct, documented outcome.
func TestFunctionAuthorization_UndiscoverableSecretValueIsNotFound(t *testing.T) {
	const secretOnlyInSource = "s3cr3t-magic-plane-x91"
	target := &mockTarget{
		tools: []map[string]any{adminTool()},
		call: func(_ string, args map[string]any) types.ToolResult {
			sys, _ := args["system"].(string)
			if sys == secretOnlyInSource {
				return types.ToolResult{Text: "root shell attached"}
			}
			return types.ToolResult{Text: fmt.Sprintf("connected to %s with standard privileges", sys)}
		},
	}
	p := newFunctionAuthzProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := maxAuthzScore(t, attempts); got >= 0.5 {
		t.Errorf("scored %v on a value discoverable only in the server's source; the probe must NOT carry such a value", got)
	}
	// And prove the probe never sent it.
	for _, a := range attempts {
		raw, _ := a.GetMetadata(mcpprobe.MetaAuthProbeValue)
		if v, _ := raw.(string); v == secretOnlyInSource {
			t.Fatalf("probe submitted a value it could only have hardcoded: %q", v)
		}
	}
}

// A privileged value that appears NOWHERE in the advertised catalogue but that the
// server VOLUNTEERS in an error message must be found. Harvesting a leaked
// allow-list is target-derived discovery and generalises to any target with a
// talkative error path — the opposite of carrying the value in the probe.
func TestFunctionAuthorization_FindsValueDisclosedInErrorResponse(t *testing.T) {
	const privileged = "admin-console"
	target := &mockTarget{
		tools: []map[string]any{adminTool()},
		call: func(_ string, args map[string]any) types.ToolResult {
			sys, _ := args["system"].(string)
			switch sys {
			case privileged:
				return types.ToolResult{Text: "root shell attached to the control plane"}
			case "database", "webserver":
				return types.ToolResult{Text: fmt.Sprintf("connected to %s with standard privileges", sys)}
			default:
				// The talkative error path that leaks the allow-list.
				return types.ToolResult{Text: fmt.Sprintf(
					"Error: System '%s' not found. Available systems: database, webserver, %s", sys, privileged)}
			}
		},
	}
	p := newFunctionAuthzProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	tried := false
	for _, a := range attempts {
		raw, _ := a.GetMetadata(mcpprobe.MetaAuthProbeValue)
		if v, _ := raw.(string); v == privileged {
			tried = true
		}
	}
	if !tried {
		t.Errorf("probe never tried %q even though the target disclosed it in a response", privileged)
	}
	if got := maxAuthzScore(t, attempts); got != 1.0 {
		t.Errorf("target-disclosed privileged value scored %v, want 1.0", got)
	}
}

// REGRESSION. A tool whose privileged branch is only reachable with a particular
// value in ANOTHER argument, and which then trusts the mere PRESENCE of a token,
// must still be caught.
//
// This is the shape that made the first version of this probe report a vulnerable
// server clean: the credential check ran only with benign placeholder arguments, so
// the call never reached the credential gate at all. The fix is to retry the
// credential comparison in the contexts the target refused.
func TestFunctionAuthorization_CredentialGateBehindAnotherArgument(t *testing.T) {
	const privileged = "admin-console"
	target := &mockTarget{
		tools: []map[string]any{adminTool()},
		call: func(_ string, args map[string]any) types.ToolResult {
			sys, _ := args["system"].(string)
			tok, hasTok := args["auth_token"].(string)
			switch sys {
			case privileged:
				// The bug: ANY non-empty token unlocks admin.
				if hasTok && tok != "" {
					return types.ToolResult{Text: "Admin command executed on admin-console"}
				}
				return types.ToolResult{Text: "Error: Authentication required for admin-console access"}
			case "database", "webserver":
				return types.ToolResult{Text: fmt.Sprintf("Command executed on %s", sys)}
			default:
				return types.ToolResult{Text: fmt.Sprintf(
					"Error: System '%s' not found. Available systems: database, webserver, %s", sys, privileged)}
			}
		},
	}
	p := newFunctionAuthzProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := maxAuthzScore(t, attempts); got != 1.0 {
		t.Errorf("credential gate behind another argument scored %v, want 1.0", got)
	}
}

// The probe must exercise the values the TARGET declares, so its baseline reflects
// ordinary authority on that target rather than a guess.
func TestFunctionAuthorization_UsesTargetDeclaredValues(t *testing.T) {
	var seen []string
	target := &mockTarget{
		tools: []map[string]any{adminTool()},
		call: func(_ string, args map[string]any) types.ToolResult {
			if sys, ok := args["system"].(string); ok {
				seen = append(seen, sys)
			}
			return types.ToolResult{Text: "ok"}
		},
	}
	p := newFunctionAuthzProbe(t, registry.Config{})
	if _, err := p.Probe(context.Background(), target); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !containsFold(seen, "database") {
		t.Errorf("probe never submitted the target-declared value %q; sent %v", "database", seen)
	}
}

// The conventional privileged names must actually be attempted.
func TestFunctionAuthorization_TriesConventionalPrivilegedNames(t *testing.T) {
	var seen []string
	target := &mockTarget{
		tools: []map[string]any{adminTool()},
		call: func(_ string, args map[string]any) types.ToolResult {
			if sys, ok := args["system"].(string); ok {
				seen = append(seen, sys)
			}
			return types.ToolResult{Text: "ok"}
		},
	}
	p := newFunctionAuthzProbe(t, registry.Config{})
	if _, err := p.Probe(context.Background(), target); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for _, want := range []string{"admin", "root", "superuser"} {
		if !containsFold(seen, want) {
			t.Errorf("probe never tried the conventional privileged name %q; sent %v", want, seen)
		}
	}
}

// A target with no conventionally-privileged tool must warn and skip, never report
// a silent clean pass.
func TestFunctionAuthorization_NoPrivilegedToolsSkips(t *testing.T) {
	target := &mockTarget{
		tools: []map[string]any{stringTool("add_numbers", "expression")},
		call: func(string, map[string]any) types.ToolResult {
			return types.ToolResult{Text: "4"}
		},
	}
	p := newFunctionAuthzProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 0 {
		t.Errorf("Probe returned %d attempts for a target with no privileged tools, want 0 (explicit skip)", len(attempts))
	}
}

// A non-ToolInvoker target cannot be assessed: fail loud.
func TestFunctionAuthorization_NonToolInvokerFailsLoud(t *testing.T) {
	p := newFunctionAuthzProbe(t, registry.Config{})
	if _, err := p.Probe(context.Background(), plainGen{}); err == nil {
		t.Fatal("Probe returned nil error for a non-ToolInvoker target, want a loud failure")
	}
}

// The destructive safety gate must be honoured: a denylisted tool is never called.
func TestFunctionAuthorization_HonoursToolDenylist(t *testing.T) {
	var called bool
	target := &mockTarget{
		tools: []map[string]any{adminTool()},
		call: func(string, map[string]any) types.ToolResult {
			called = true
			return types.ToolResult{Text: "ok"}
		},
	}
	p := newFunctionAuthzProbe(t, registry.Config{"tool_denylist": []string{"manage_access"}})
	if _, err := p.Probe(context.Background(), target); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if called {
		t.Error("probe invoked a denylisted tool")
	}
}

// A server-annotated destructive tool must be skipped unless explicitly opted in.
func TestFunctionAuthorization_HonoursDestructiveAnnotation(t *testing.T) {
	tru := true
	tool := adminTool()
	tool["annotations"] = types.MCPToolAnnotations{Destructive: &tru}
	var called bool
	target := &mockTarget{
		tools: []map[string]any{tool},
		call: func(string, map[string]any) types.ToolResult {
			called = true
			return types.ToolResult{Text: "ok"}
		},
	}
	p := newFunctionAuthzProbe(t, registry.Config{})
	if _, err := p.Probe(context.Background(), target); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if called {
		t.Error("probe invoked a server-annotated destructive tool without allow_destructive")
	}
}

// Differently-worded refusals must not be reported as a confident finding.
func TestFunctionAuthorization_DifferentlyWordedRefusalsAreNotConfident(t *testing.T) {
	target := &mockTarget{
		tools: []map[string]any{adminTool()},
		call: func(_ string, args map[string]any) types.ToolResult {
			sys, _ := args["system"].(string)
			switch strings.ToLower(sys) {
			case "database", "webserver":
				return types.ToolResult{Text: "access denied: not authorized for this system"}
			default:
				return types.ToolResult{Text: "error: unknown system requested"}
			}
		},
	}
	p := newFunctionAuthzProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := maxAuthzScore(t, attempts); got >= 1.0 {
		t.Errorf("differently-worded refusals scored %v, want < 1.0", got)
	}
}
