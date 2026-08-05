package mcpprimitive

import (
	"context"
	"fmt"
	"strings"
	"testing"

	// Registers the mcpsecrets.Credential detector this probe scores with.
	_ "github.com/praetorian-inc/augustus/internal/detectors/mcpsecrets"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func newContentLeakProbe(t *testing.T, cfg registry.Config) *ContentLeak {
	t.Helper()
	if cfg == nil {
		cfg = registry.Config{}
	}
	p, err := NewContentLeak(cfg)
	if err != nil {
		t.Fatalf("NewContentLeak: %v", err)
	}
	return p.(*ContentLeak)
}

// scoreCredentials scores every attempt with the REAL mcpsecrets.Credential
// detector, so the tests assert the verdict the scanner would produce rather than
// a stub's.
func scoreCredentials(t *testing.T, attempts []*attempt.Attempt) float64 {
	t.Helper()
	return scoreWith(t, "mcpsecrets.Credential", attempts)
}

// leakyResourceBody is the shape DVMCP challenge 1 serves from its advertised
// internal://credentials resource: an admin password and a database connection
// string, returned to an unauthenticated client with no exploit involved.
const leakyResourceBody = `# Internal service credentials
admin_password = Adm1n-S3cr3t-P@ssw0rd
db_dsn = postgres://reporting:Tr0ub4dor-3xample@db.internal:5432/analytics
`

// benignResourceBody is the false-positive control: realistic NON-secret content
// of exactly the kinds that tempt a naive credential scanner — documentation
// prose, a plain endpoint URL, a path that POINTS at a secret rather than being
// one, and an obvious placeholder token.
const benignResourceBody = `# Onboarding notes
docs_url = https://api.example.test/v1
api_key_file = /etc/app/credentials.json
api_key = your_api_key_here
sample_password = changeme
tokenizer = huggingface/tokenizer-base
Read the quickstart guide, then ask the platform team for a scoped token.
`

// leakCatalog is an inventory covering every non-tool surface this probe reads:
// an advertised resource, a resource template, a prompt template with a required
// argument, the server instructions, and catalog metadata on a tool.
func leakCatalog() *types.MCPInventory {
	return &types.MCPInventory{
		Instructions: "Call get_user for lookups.\nservice_token = Zx9-QwErTy-4821-Kf",
		Tools: []types.MCPTool{{
			Name:        "run_query",
			Description: "Runs a read-only query. Connects as postgres://reporting:Tr0ub4dor-3xample@db.internal:5432/analytics",
		}},
		Resources: []types.MCPResource{
			{URI: "internal://credentials", Name: "credentials"},
			{URI: "notes://readme", Name: "readme"},
		},
		// Expands to a URI distinct from the advertised resources above, so the
		// template read is not deduplicated away.
		ResourceTemplates: []types.MCPResourceTemplate{{
			URITemplate: "notes://topic/{name}",
			Name:        "note",
		}},
		Prompts: []types.MCPPrompt{{
			Name:      "handover",
			Arguments: []types.MCPPromptArgument{{Name: "topic", Required: true}},
		}},
	}
}

// TestContentLeak_AdvertisedResourceLeak is the ticket's core case: the server
// publishes a credentials resource in its own catalog and serves it on request.
func TestContentLeak_AdvertisedResourceLeak(t *testing.T) {
	target := &mockTarget{
		inv: &types.MCPInventory{
			Resources: []types.MCPResource{{URI: "internal://credentials", Name: "credentials"}},
		},
		read: func(uri string) (types.MCPResourceResult, error) {
			if uri == "internal://credentials" {
				return types.MCPResourceResult{URI: uri, Text: leakyResourceBody, MIMEType: "text/plain", Blocks: 1}, nil
			}
			return types.MCPResourceResult{}, fmt.Errorf("resource not found: %s", uri)
		},
	}

	attempts, err := newContentLeakProbe(t, nil).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("Probe produced no attempts for an advertised resource")
	}
	if got := scoreCredentials(t, attempts); got != 1.0 {
		t.Errorf("top score = %v, want 1.0; the advertised resource serves an admin password and a DSN", got)
	}
	if cls := metaString(t, attempts[0], attempt.MetadataKeyPrimitiveClass); cls != classResourceContent {
		t.Errorf("class = %q, want %q", cls, classResourceContent)
	}
	if tgt := metaString(t, attempts[0], attempt.MetadataKeyPrimitiveTarget); tgt != "internal://credentials" {
		t.Errorf("target = %q, want the advertised URI", tgt)
	}
}

// TestContentLeak_BenignContentScoresZero is the false-positive control: a server
// whose surfaces serve documentation, endpoint URLs and placeholders must stay SAFE.
func TestContentLeak_BenignContentScoresZero(t *testing.T) {
	target := &mockTarget{
		inv: &types.MCPInventory{
			Instructions: "Use the read_notes tool. See https://api.example.test/v1 for the API reference.",
			Tools: []types.MCPTool{{
				Name:        "read_notes",
				Title:       "Read notes",
				Description: "Reads a note by name and returns its text. Requires a scoped token supplied by the operator.",
			}},
			Resources:         []types.MCPResource{{URI: "notes://readme", Name: "readme"}},
			ResourceTemplates: []types.MCPResourceTemplate{{URITemplate: "notes://{topic}"}},
			Prompts:           []types.MCPPrompt{{Name: "onboard"}},
		},
		read: func(uri string) (types.MCPResourceResult, error) {
			return types.MCPResourceResult{URI: uri, Text: benignResourceBody, Blocks: 1}, nil
		},
		prompt: func(string, map[string]string) (types.MCPPromptResult, error) {
			return types.MCPPromptResult{Text: benignResourceBody, Messages: 1}, nil
		},
	}

	attempts, err := newContentLeakProbe(t, nil).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("Probe produced no attempts; the benign control must still exercise every surface")
	}
	if got := scoreCredentials(t, attempts); got != 0.0 {
		t.Errorf("top score = %v, want 0.0; documentation, endpoint URLs and placeholders are not credentials", got)
	}
}

// TestContentLeak_PromptRenderLeak covers the prompts/get surface: the rendered
// template carries a credential, and the render must reach the server with benign
// arguments rather than failing validation.
func TestContentLeak_PromptRenderLeak(t *testing.T) {
	target := &mockTarget{
		inv: &types.MCPInventory{
			Prompts: []types.MCPPrompt{{
				Name: "handover",
				Arguments: []types.MCPPromptArgument{
					{Name: "topic", Required: true},
					{Name: "audience", Required: true},
					{Name: "tone"},
				},
			}},
		},
		prompt: func(_ string, args map[string]string) (types.MCPPromptResult, error) {
			if args["topic"] == "" || args["audience"] == "" {
				return types.MCPPromptResult{}, fmt.Errorf("missing required argument")
			}
			return types.MCPPromptResult{Text: "Handover notes\n" + leakyResourceBody, Messages: 1}, nil
		},
	}

	attempts, err := newContentLeakProbe(t, nil).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(target.promptCalls) != 1 {
		t.Fatalf("got %d prompts/get calls, want exactly one benign render", len(target.promptCalls))
	}
	if got := len(target.promptCalls[0].args); got != 2 {
		t.Errorf("render carried %d args, want both required arguments populated: %v", got, target.promptCalls[0].args)
	}
	if got := scoreCredentials(t, attempts); got != 1.0 {
		t.Errorf("top score = %v, want 1.0; the rendered template exposes credentials", got)
	}
}

// TestContentLeak_ServerInstructionsScored covers the initialize→instructions
// surface, which recon captures today and nothing scores.
func TestContentLeak_ServerInstructionsScored(t *testing.T) {
	target := &mockTarget{inv: &types.MCPInventory{
		Instructions: "Call get_user for lookups.\nservice_token = Zx9-QwErTy-4821-Kf",
	}}

	attempts, err := newContentLeakProbe(t, nil).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("got %d attempts, want one for the server instructions", len(attempts))
	}
	if cls := metaString(t, attempts[0], attempt.MetadataKeyPrimitiveClass); cls != classInstructions {
		t.Errorf("class = %q, want %q", cls, classInstructions)
	}
	if got := scoreCredentials(t, attempts); got != 1.0 {
		t.Errorf("top score = %v, want 1.0; the server instructions embed a service token", got)
	}
}

// TestContentLeak_CatalogMetadataNotScored locks in a deliberate exclusion.
//
// Catalog descriptions and titles reach every client without a call, so scoring
// them looks attractive — but mcpsecrets.Credential identifies a credential by a
// credential-shaped KEY followed by a colon and a value, and the "Args:" block of
// a docstring-derived description is also "name: description". Measured against
// DVMCP challenges 7 and 9, that collision scored 1.0 on nothing but parameter
// documentation ("password: The password for authentication"). The shape is
// near-universal in MCP descriptions, so the surface is excluded until the
// detector can require a credential-shaped VALUE rather than just a key.
//
// The tool below carries a real connection string in its description AND a
// docstring parameter line. Neither may produce an attempt: the exclusion is
// unconditional, so this test also documents the coverage we are giving up.
func TestContentLeak_CatalogMetadataNotScored(t *testing.T) {
	target := &mockTarget{inv: &types.MCPInventory{
		Tools: []types.MCPTool{{
			Name:        "run_query",
			Description: "Runs a read-only query. Connects as postgres://reporting:Tr0ub4dor-3xample@db.internal:5432/analytics\n\nArgs:\n    password: The password for authentication\n",
		}},
	}}

	attempts, err := newContentLeakProbe(t, nil).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 0 {
		t.Fatalf("got %d attempts, want none — catalog metadata is deliberately not scored", len(attempts))
	}
}

// TestContentLeak_ParameterDocsDoNotFalsePositive is the regression for the two
// real targets that exposed the collision. Both serve no resources and no
// prompts; their tool descriptions document credential-NAMED parameters and
// contain no secret at all. A finding here would fire on most real MCP servers.
func TestContentLeak_ParameterDocsDoNotFalsePositive(t *testing.T) {
	// Verbatim from DVMCP challenges 7 and 9.
	target := &mockTarget{inv: &types.MCPInventory{
		Tools: []types.MCPTool{
			{
				Name:        "authenticate",
				Description: "Authenticate a user and return a session token\n            \n            Args:\n                username: The username to authenticate\n                password: The password for authentication\n            ",
			},
			{
				Name:        "verify_token",
				Description: "Verify if a session token is valid\n            \n            Args:\n                token: The session token to verify\n            ",
			},
			{
				Name:        "remote_access",
				Description: "Execute a command on a remote system\n            \n            Args:\n                auth_token: Optional authentication token for privileged operations\n            ",
			},
		},
	}}

	attempts, err := newContentLeakProbe(t, nil).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := scoreCredentials(t, attempts); got >= 0.5 {
		t.Errorf("top score = %v, want below 0.5; parameter documentation is not a leaked credential", got)
	}
}

// TestContentLeak_ReadsNormallyWithNoPayloads is the contract that separates this
// probe from mcpprimitive.ResourceInjection: it exercises the surfaces the way a
// legitimate client would. No traversal, no canary, no encoded separator — every
// URI is an advertised one or a benign template expansion.
func TestContentLeak_ReadsNormallyWithNoPayloads(t *testing.T) {
	target := &mockTarget{
		inv: leakCatalog(),
		read: func(uri string) (types.MCPResourceResult, error) {
			return types.MCPResourceResult{URI: uri, Text: "ok", Blocks: 1}, nil
		},
		prompt: func(string, map[string]string) (types.MCPPromptResult, error) {
			return types.MCPPromptResult{Text: "ok", Messages: 1}, nil
		},
	}

	if _, err := newContentLeakProbe(t, nil).Probe(context.Background(), target); err != nil {
		t.Fatalf("Probe: %v", err)
	}

	advertised := map[string]bool{"internal://credentials": true, "notes://readme": true}
	sawTemplate := false
	for _, uri := range target.readURIs {
		for _, bad := range []string{"..", "%2f", "etc/passwd", "win.ini", "$(", "{{", "`", ";"} {
			if strings.Contains(uri, bad) {
				t.Errorf("requested URI %q carries attack syntax %q; this probe reads normally", uri, bad)
			}
		}
		if advertised[uri] {
			continue
		}
		if strings.HasPrefix(uri, "notes://") {
			sawTemplate = true
			continue
		}
		t.Errorf("requested URI %q is neither advertised nor a benign template expansion", uri)
	}
	if !sawTemplate {
		t.Error("no resource template was expanded and read")
	}

	if len(target.promptCalls) == 0 {
		t.Fatal("no prompts/get call was made")
	}
	for _, c := range target.promptCalls {
		for _, v := range c.args {
			if strings.ContainsAny(v, "{}$;`|&") {
				t.Errorf("prompt argument %q carries attack syntax; this probe renders normally", v)
			}
		}
	}
}

// TestContentLeak_NoSurfacesAdvertised: a target with nothing to read must warn and
// produce NO attempt, so an unexercised surface can never be reported as a clean pass.
func TestContentLeak_NoSurfacesAdvertised(t *testing.T) {
	attempts, err := newContentLeakProbe(t, nil).Probe(context.Background(), &mockTarget{inv: &types.MCPInventory{}})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 0 {
		t.Errorf("got %d attempts, want none when the target advertises no non-tool surface", len(attempts))
	}
}

// TestContentLeak_CatalogErrorIsFatal: every surface here comes from the catalog, so
// a failed enumeration must not read as a clean pass.
func TestContentLeak_CatalogErrorIsFatal(t *testing.T) {
	_, err := newContentLeakProbe(t, nil).Probe(context.Background(), &mockTarget{invErr: fmt.Errorf("resources/list exploded")})
	if err == nil {
		t.Fatal("Probe returned nil error after the catalog failed; that would read as a clean pass")
	}
	if !strings.Contains(err.Error(), "enumerate") {
		t.Errorf("error should name the failing step, got %v", err)
	}
}

// TestContentLeak_RequiresPrimitiveReader mirrors the sibling probes' guard: a
// target that cannot read primitives fails loud rather than scoring clean.
func TestContentLeak_RequiresPrimitiveReader(t *testing.T) {
	_, err := newContentLeakProbe(t, nil).Probe(context.Background(), plainTarget{})
	if err == nil {
		t.Fatal("Probe on a non-primitive target returned nil error; it must fail loud")
	}
	if !strings.Contains(err.Error(), "cannot read MCP primitives") {
		t.Errorf("error should explain the missing capability, got %v", err)
	}
}

// TestContentLeak_RefusalIsCompletedNonFinding: resources/read and prompts/get have
// no application-level error flag, so a refusal arrives as a Go error. It is the
// denial signal — recorded as a completed non-finding, never StatusError.
func TestContentLeak_RefusalIsCompletedNonFinding(t *testing.T) {
	target := &mockTarget{
		inv: &types.MCPInventory{
			Resources: []types.MCPResource{{URI: "internal://credentials"}},
			Prompts:   []types.MCPPrompt{{Name: "handover"}},
		},
		read: func(uri string) (types.MCPResourceResult, error) {
			return types.MCPResourceResult{}, fmt.Errorf("access denied for %s", uri)
		},
		prompt: func(string, map[string]string) (types.MCPPromptResult, error) {
			return types.MCPPromptResult{}, fmt.Errorf("prompt access denied")
		},
	}

	attempts, err := newContentLeakProbe(t, nil).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("Probe produced no attempts")
	}
	for _, a := range attempts {
		if a.Status == attempt.StatusError {
			t.Errorf("attempt %q left in error status; a refusal is a non-finding, not a probe failure", a.Prompt)
		}
		if reason := metaString(t, a, attempt.MetadataKeyPrimitiveCallError); reason == "" {
			t.Errorf("attempt %q recorded no refusal reason; a denial must stay visible", a.Prompt)
		}
	}
	if got := scoreCredentials(t, attempts); got != 0.0 {
		t.Errorf("top score = %v, want 0.0 when every read was refused", got)
	}
}

// TestContentLeak_RawPayloadScored: a credential may appear only in the raw
// structured payload and never in the assembled text.
func TestContentLeak_RawPayloadScored(t *testing.T) {
	target := &mockTarget{
		inv: &types.MCPInventory{Resources: []types.MCPResource{{URI: "internal://credentials"}}},
		read: func(uri string) (types.MCPResourceResult, error) {
			return types.MCPResourceResult{
				URI:    uri,
				Text:   "see attached",
				Raw:    []byte(`{"contents":[{"admin_password":"Adm1n-S3cr3t-P@ssw0rd"}]}`),
				Blocks: 1,
			}, nil
		},
	}

	attempts, err := newContentLeakProbe(t, nil).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := scoreCredentials(t, attempts); got != 1.0 {
		t.Errorf("top score = %v, want 1.0; the secret sits only in the raw payload", got)
	}
}

// TestContentLeak_TargetCapBounded keeps a huge catalog from producing an unbounded
// number of requests.
func TestContentLeak_TargetCapBounded(t *testing.T) {
	inv := &types.MCPInventory{}
	for i := range 40 {
		inv.Resources = append(inv.Resources, types.MCPResource{URI: fmt.Sprintf("notes://n%d", i)})
	}
	target := &mockTarget{
		inv: inv,
		read: func(uri string) (types.MCPResourceResult, error) {
			return types.MCPResourceResult{URI: uri, Text: "ok", Blocks: 1}, nil
		},
	}

	if _, err := newContentLeakProbe(t, registry.Config{"content_max_targets": 5}).Probe(context.Background(), target); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(target.readURIs) != 5 {
		t.Errorf("issued %d reads, want the configured cap of 5", len(target.readURIs))
	}
}
