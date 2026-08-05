package mcptool

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	detmcptool "github.com/praetorian-inc/augustus/internal/detectors/mcptool"
	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func newTokenValidationProbe(t *testing.T, cfg registry.Config) *TokenValidation {
	t.Helper()
	p, err := NewTokenValidation(cfg)
	if err != nil {
		t.Fatalf("NewTokenValidation: %v", err)
	}
	return p.(*TokenValidation)
}

// maxTokenScore runs the REAL detector over the probe's attempts and returns the
// highest score. Using the production detector rather than re-implementing its
// rules is what makes these tests fail if the scoring contract breaks.
func maxTokenScore(t *testing.T, attempts []*attempt.Attempt) float64 {
	t.Helper()
	det, err := detmcptool.NewTokenValidationDetector(registry.Config{})
	if err != nil {
		t.Fatalf("NewTokenValidationDetector: %v", err)
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

// tokenTool builds a tool with one credential-shaped parameter.
func tokenTool(name, param string) map[string]any {
	return stringTool(name, param)
}

// ---------------------------------------------------------------------------
// MANDATORY non-corpus controls
// ---------------------------------------------------------------------------

// CONTROL — a stub that validates tokens against a REAL store must NOT fire. It
// answers a well-formed-but-unissued value exactly as it answers garbage, so
// there is no shape differential to find.
func TestTokenValidation_RealTokenStoreDoesNotFire(t *testing.T) {
	issued := map[string]bool{"a1b2c3d4e5f60718293a4b5c6d7e8f90": true}
	target := &mockTarget{
		tools: []map[string]any{tokenTool("verify_token", "token")},
		call: func(_ string, args map[string]any) types.ToolResult {
			tok, _ := args["token"].(string)
			if issued[tok] {
				return types.ToolResult{Text: "session valid for user alice"}
			}
			// Same answer for malformed and well-formed-but-unissued: a real lookup.
			return types.ToolResult{Text: fmt.Sprintf("token %s is invalid", tok)}
		},
	}

	p := newTokenValidationProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("Probe returned no attempts; the verification surface must be assessed")
	}
	if got := maxTokenScore(t, attempts); got >= 0.5 {
		t.Errorf("real token store scored %v, want < 0.5 — must NOT fire", got)
	}
}

// CONTROL — a stub that validates only the FORMAT must fire. This is the
// DVMCP-challenge-7 class expressed generically: any 32-hex value is accepted
// though none was ever issued.
func TestTokenValidation_FormatOnlyValidationFires(t *testing.T) {
	target := &mockTarget{
		tools: []map[string]any{tokenTool("verify_token", "token")},
		call: func(_ string, args map[string]any) types.ToolResult {
			tok, _ := args["token"].(string)
			if len(tok) == 32 && isAllHex(tok) {
				return types.ToolResult{Text: fmt.Sprintf("Token %s appears to be valid", tok)}
			}
			return types.ToolResult{Text: fmt.Sprintf("Token %s is invalid (incorrect format)", tok)}
		},
	}

	p := newTokenValidationProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := maxTokenScore(t, attempts); got != 1.0 {
		t.Errorf("format-only validation scored %v, want 1.0", got)
	}
}

// A verifier that accepts EVERY value, including malformed ones, has no shape
// differential — it is not validating at all. That is a different weakness and
// must not be reported as format-only validation.
func TestTokenValidation_AcceptsEverythingIsNotFormatOnly(t *testing.T) {
	target := &mockTarget{
		tools: []map[string]any{tokenTool("verify_token", "token")},
		call: func(_ string, _ map[string]any) types.ToolResult {
			return types.ToolResult{Text: "ok"}
		},
	}
	p := newTokenValidationProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := maxTokenScore(t, attempts); got >= 1.0 {
		t.Errorf("uniform-response verifier scored %v, want < 1.0 (no shape differential)", got)
	}
}

// The probe must never send the same value twice: the two same-shape samples have
// to be independent, or the replica corroborates nothing.
func TestTokenValidation_SubmitsIndependentSameShapeValues(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	target := &mockTarget{
		tools: []map[string]any{tokenTool("verify_token", "token")},
		call: func(_ string, args map[string]any) types.ToolResult {
			tok, _ := args["token"].(string)
			mu.Lock()
			seen[tok]++
			mu.Unlock()
			return types.ToolResult{Text: "checked"}
		},
	}
	p := newTokenValidationProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	for _, a := range attempts {
		raw, _ := a.GetMetadata(mcpprobe.MetaAuthProbeValue)
		probeVal, _ := raw.(string)
		raw2, _ := a.GetMetadata(mcpprobe.MetaAuthReplicaValue)
		replicaVal, _ := raw2.(string)
		if probeVal != "" && probeVal == replicaVal {
			t.Errorf("probe and replica values are identical (%q); they must be independently generated", probeVal)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for tok, n := range seen {
		if tok != malformedControlValue && n > 1 {
			t.Errorf("value %q was submitted %d times; candidate values must be freshly generated", tok, n)
		}
	}
}

// The CANDIDATE values must be freshly randomised per run, never fixed strings a
// signature-based defence could blocklist or a reviewer could recognise as
// benchmark-specific. Only the recorded candidates are asserted: the malformed
// control is a deliberate constant, and benign placeholder arguments for
// unrelated required parameters are meant to be stable.
func TestTokenValidation_CandidateValuesAreRandomisedAcrossRuns(t *testing.T) {
	collect := func() map[string]bool {
		target := &mockTarget{
			tools: []map[string]any{tokenTool("verify_token", "token")},
			call: func(string, map[string]any) types.ToolResult {
				return types.ToolResult{Text: "checked"}
			},
		}
		p := newTokenValidationProbe(t, registry.Config{})
		attempts, err := p.Probe(context.Background(), target)
		if err != nil {
			t.Fatalf("Probe: %v", err)
		}
		got := map[string]bool{}
		for _, a := range attempts {
			for _, key := range []string{mcpprobe.MetaAuthProbeValue, mcpprobe.MetaAuthReplicaValue} {
				raw, _ := a.GetMetadata(key)
				if v, _ := raw.(string); v != "" {
					got[v] = true
				}
			}
		}
		return got
	}
	first, second := collect(), collect()
	if len(first) == 0 {
		t.Fatal("no candidate values recorded")
	}
	for v := range first {
		if second[v] {
			t.Errorf("candidate value %q repeated across runs; candidates must be randomised per run", v)
		}
	}
}

// When the target DECLARES its accepted values, the probe must use those rather
// than sweep generic shapes: it should exercise the documented interface.
func TestTokenValidation_PrefersTargetDeclaredValues(t *testing.T) {
	tool := map[string]any{
		"name": "check_role_token",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"token": map[string]any{"type": "string", "enum": []any{"alpha-declared", "beta-declared"}},
			},
			"required": []any{"token"},
		},
	}
	var got []string
	target := &mockTarget{
		tools: []map[string]any{tool},
		call: func(_ string, args map[string]any) types.ToolResult {
			tok, _ := args["token"].(string)
			got = append(got, tok)
			return types.ToolResult{Text: "checked"}
		},
	}
	p := newTokenValidationProbe(t, registry.Config{})
	if _, err := p.Probe(context.Background(), target); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !contains(got, "alpha-declared") {
		t.Errorf("probe did not submit the target's declared value; submitted %v", got)
	}
}

// A target with no credential-shaped parameter must warn and skip, never report a
// silent clean pass (mcptool.SSRF precedent).
func TestTokenValidation_NoCredentialParamsSkips(t *testing.T) {
	target := &mockTarget{
		tools: []map[string]any{stringTool("add_numbers", "expression")},
		call: func(string, map[string]any) types.ToolResult {
			return types.ToolResult{Text: "4"}
		},
	}
	p := newTokenValidationProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 0 {
		t.Errorf("Probe returned %d attempts for a target with no credential surface, want 0", len(attempts))
	}
}

// A non-ToolInvoker target cannot be assessed: fail loud rather than return a
// clean-looking empty result.
func TestTokenValidation_NonToolInvokerFailsLoud(t *testing.T) {
	p := newTokenValidationProbe(t, registry.Config{})
	if _, err := p.Probe(context.Background(), plainGen{}); err == nil {
		t.Fatal("Probe returned nil error for a non-ToolInvoker target, want a loud failure")
	}
}

// ---------------------------------------------------------------------------
// Predictable issuance
// ---------------------------------------------------------------------------

// A surface issuing sequential credentials must fire.
func TestTokenValidation_PredictableIssuanceFires(t *testing.T) {
	n := 1040
	target := &mockTarget{
		tools: []map[string]any{stringTool("authenticate", "username")},
		call: func(string, map[string]any) types.ToolResult {
			n++
			return types.ToolResult{Text: fmt.Sprintf("session token: sess0000000000%d", n)}
		},
	}
	p := newTokenValidationProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := maxTokenScore(t, attempts); got != 1.0 {
		t.Errorf("sequential issuance scored %v, want 1.0", got)
	}
}

// CONTROL — a surface issuing properly random credentials must NOT fire.
func TestTokenValidation_RandomIssuanceDoesNotFire(t *testing.T) {
	target := &mockTarget{
		tools: []map[string]any{stringTool("authenticate", "username")},
		call: func(string, map[string]any) types.ToolResult {
			return types.ToolResult{Text: "session token: " + randHex(32)}
		},
	}
	p := newTokenValidationProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for _, a := range attempts {
		raw, _ := a.GetMetadata(mcpprobe.MetaAuthClass)
		if class, _ := raw.(string); class != mcpprobe.AuthClassTokenPredictable {
			continue
		}
		det, _ := detmcptool.NewTokenValidationDetector(registry.Config{})
		scores, _ := det.Detect(context.Background(), a)
		for _, s := range scores {
			if s >= 0.5 {
				t.Errorf("random issuance scored %v, want < 0.5", s)
			}
		}
	}
}

// Prose in a tool response must not be mistaken for an issued credential —
// otherwise every server returning an error sentence would look like it issues
// predictable tokens.
func TestTokenValidation_ProseIsNotMistakenForACredential(t *testing.T) {
	if got := extractCredentialLike("Authentication failed: Invalid username or password"); got != "" {
		t.Errorf("extractCredentialLike matched prose: %q", got)
	}
	if got := extractCredentialLike("session token: a1b2c3d4e5f60718293a4b5c6d7e8f90"); got != "a1b2c3d4e5f60718293a4b5c6d7e8f90" {
		t.Errorf("extractCredentialLike = %q, want the hex credential", got)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}
