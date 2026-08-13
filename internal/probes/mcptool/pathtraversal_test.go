package mcptool

import (
	"context"
	"regexp"
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

// TestPathTraversal_DetectsRead: a read-only-annotated tool that resolves
// the payload as a filesystem path and returns file contents is flagged
// by the read-payload path (targeting /etc/passwd).
func TestPathTraversal_DetectsRead(t *testing.T) {
	p := newPathTraversalProbe(t)

	tool := stringTool("read", "filepath")
	tool["annotations"] = types.MCPToolAnnotations{ReadOnly: true}
	target := &mockTarget{
		tools: []map[string]any{tool},
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

	// Annotate ReadOnly so the read /etc/passwd payload set is used —
	// otherwise the tool would receive write-canary payloads and the
	// "signature match on /etc/passwd" check would never fire.
	descTool := stringToolWithDescription(
		"read", "filename",
		"Read a file. Only files in /tmp/safe/ are accessible.",
	)
	descTool["annotations"] = types.MCPToolAnnotations{ReadOnly: true}
	target := &mockTarget{
		tools: []map[string]any{descTool},
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

// TestPathTraversal_WritePayloadsOnNonReadOnlyTool: an operator who has
// opted into destructive-tool testing (allow_destructive=true) still MUST
// NOT see /etc/passwd payloads sent to a write-capable tool — the payload
// would OVERWRITE /etc/passwd. Instead, write-capable tools receive canary
// payloads targeting /tmp/proof-augwrite-<hex> (novel path, no clobber).
// Regression guard for the Mauro S1 rework.
func TestPathTraversal_WritePayloadsOnNonReadOnlyTool(t *testing.T) {
	pr, err := NewPathTraversal(registry.Config{"allow_destructive": true})
	if err != nil {
		t.Fatalf("NewPathTraversal: %v", err)
	}
	p := pr.(*PathTraversal)

	// A destructive-annotated tool with a path-like param. Without the
	// rework, /etc/passwd payloads would flow here.
	destructiveTrue := true
	target := &mockTarget{
		tools: []map[string]any{
			annotatedTool("save_report", "filepath", types.MCPToolAnnotations{Destructive: &destructiveTrue}),
		},
		call: func(_ string, _ map[string]any) types.ToolResult {
			return types.ToolResult{Text: "ok"}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("expected write-canary attempts against the destructive tool")
	}
	for _, a := range attempts {
		// NO payload should target /etc/passwd or windows/win.ini —
		// those are the exact strings that would overwrite sensitive
		// files on a write sink.
		if strings.Contains(a.Prompt, "/etc/passwd") {
			t.Errorf("write-capable tool received /etc/passwd payload %q — would overwrite the real file!", a.Prompt)
		}
		if strings.Contains(strings.ToLower(a.Prompt), "windows\\win.ini") ||
			strings.Contains(strings.ToLower(a.Prompt), "windows/win.ini") {
			t.Errorf("write-capable tool received win.ini payload %q — would overwrite the real file!", a.Prompt)
		}
		lower := strings.ToLower(a.Prompt)
		if !strings.Contains(lower, "tmp") || !strings.Contains(lower, "proof-augwrite-") {
			t.Errorf("write-canary payload %q should target /tmp/proof-augwrite-<canary> (also accepts URL-encoded /tmp/)", a.Prompt)
		}
	}
}

// TestPathTraversal_ReadPayloadsOnReadOnlyTool: the read-only-annotated
// path continues to receive /etc/passwd-class payloads because ReadOnly
// is the only signal the tool CANNOT overwrite the target file.
func TestPathTraversal_ReadPayloadsOnReadOnlyTool(t *testing.T) {
	p := newPathTraversalProbe(t)

	target := &mockTarget{
		tools: []map[string]any{
			annotatedTool("read_file", "filepath", types.MCPToolAnnotations{ReadOnly: true}),
		},
		call: func(_ string, args map[string]any) types.ToolResult {
			path, _ := args["filepath"].(string)
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
	sawEtcPasswdPayload := false
	for _, a := range attempts {
		if strings.Contains(a.Prompt, "/etc/passwd") {
			sawEtcPasswdPayload = true
			break
		}
	}
	if !sawEtcPasswdPayload {
		t.Errorf("read-only-annotated tool should receive /etc/passwd payloads for read detection")
	}
}

// TestPathTraversal_WriteCanaryScoresInconclusive: a write-capable tool
// that echoes the canary path with a success verb produces the
// InconclusiveScore (0.5) rather than a confirmed 1.0 vulnerability.
// Response-only evidence of a write is intrinsically weak — a reader
// that includes "wrote" in its response text would produce the same
// signal without ever touching the filesystem. See detector doc.
func TestPathTraversal_WriteCanaryScoresInconclusive(t *testing.T) {
	pr, err := NewPathTraversal(registry.Config{"allow_destructive": true})
	if err != nil {
		t.Fatalf("NewPathTraversal: %v", err)
	}
	p := pr.(*PathTraversal)

	destTrue := true
	target := &mockTarget{
		tools: []map[string]any{
			annotatedTool("save_report", "filepath", types.MCPToolAnnotations{Destructive: &destTrue}),
		},
		call: func(_ string, args map[string]any) types.ToolResult {
			path, _ := args["filepath"].(string)
			return types.ToolResult{Text: "Successfully wrote to " + path, IsError: false}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	det := &pathTraversalDetectorStub{}
	sawInconclusive := false
	for _, a := range attempts {
		for _, s := range det.detect(a) {
			if s == 1.0 {
				t.Errorf("write finding must not score 1.0 (response-only evidence is too weak); got 1.0 on attempt %q", a.Prompt)
			}
			if s == 0.5 {
				sawInconclusive = true
			}
		}
	}
	if !sawInconclusive {
		t.Errorf("expected at least one write-canary attempt to score InconclusiveScore (0.5)")
	}
}

// TestPathTraversal_WriteCanary_ReaderEchoingSuccessVerb: a READER tool
// that happens to include "wrote" in its response text (bad log line
// or debug output) must NOT produce even an inconclusive score — the
// InconclusiveScore is for cases where the SUCCESS-VERB signal is
// unverified, but this test isolates a case where there's no write
// happening at all. Since the tool is annotated ReadOnly, the probe
// should send READ payloads instead of WRITE payloads, and none of
// those would carry the write canary in the response. Regression
// guard against future refactors that might over-broaden the write
// classification.
func TestPathTraversal_WriteCanary_ReaderEchoingSuccessVerb(t *testing.T) {
	p := newPathTraversalProbe(t)

	target := &mockTarget{
		tools: []map[string]any{
			annotatedTool("view_file", "filepath", types.MCPToolAnnotations{ReadOnly: true}),
		},
		call: func(_ string, args map[string]any) types.ToolResult {
			path, _ := args["filepath"].(string)
			// Reader that phrases its response with "success" language.
			return types.ToolResult{Text: "Successfully read " + path + ": (content redacted)"}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	det := &pathTraversalDetectorStub{}
	for _, a := range attempts {
		isWrite, _ := a.GetMetadata(attempt.MetadataKeyPathTraversalIsWrite)
		if b, _ := isWrite.(bool); b {
			t.Errorf("ReadOnly-annotated tool should not receive WRITE payloads; got isWrite on attempt %q", a.Prompt)
		}
		for _, s := range det.detect(a) {
			if s == 0.5 {
				t.Errorf("reader tool that echoes success verb should not score 0.5; got InconclusiveScore on attempt %q", a.Prompt)
			}
		}
	}
}

// TestPathTraversal_WriteCanarySuppressedOnRefusal: a write-capable tool
// that REFUSES the write (returns IsError=true with the payload echoed in
// the error message) must NOT be flagged — the echo alone isn't evidence.
func TestPathTraversal_WriteCanarySuppressedOnRefusal(t *testing.T) {
	pr, err := NewPathTraversal(registry.Config{"allow_destructive": true})
	if err != nil {
		t.Fatalf("NewPathTraversal: %v", err)
	}
	p := pr.(*PathTraversal)

	destTrue := true
	target := &mockTarget{
		tools: []map[string]any{
			annotatedTool("save_report", "filepath", types.MCPToolAnnotations{Destructive: &destTrue}),
		},
		call: func(_ string, args map[string]any) types.ToolResult {
			path, _ := args["filepath"].(string)
			// Hardened: refuses with the path echoed in the error.
			return types.ToolResult{Text: "Access to " + path + " denied", IsError: true}
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
				t.Errorf("write refusal (IsError=true) with echoed payload must be SAFE, got %v", s)
			}
		}
	}
}

// TestMatchesPathParam covers the camelCase normalisation added for
// CodeRabbit finding #5. Real-world MCP tool schemas use both snake_case
// and camelCase parameter names; the matcher must handle both.
func TestMatchesPathParam(t *testing.T) {
	positive := []string{
		// snake_case / hyphen / space separators
		"filename", "file_path", "output-file", "log file",
		// camelCase (the fix)
		"filePath", "outputPath", "targetFile", "logFile",
		"resourceURI", "sourcePath", "destPath",
	}
	for _, n := range positive {
		if !matchesPathParam(n) {
			t.Errorf("matchesPathParam(%q) = false, want true", n)
		}
	}
	negative := []string{
		"", "message", "count", "isValid", "userId",
	}
	for _, n := range negative {
		if matchesPathParam(n) {
			t.Errorf("matchesPathParam(%q) = true, want false", n)
		}
	}
}

// TestExtractHintedPrefixes covers the description-parsing helper directly.
// Broadened to cover the FS-prefix acceptance changes: any absolute FS-
// shaped path is a candidate; URL-route shapes are rejected by
// looksLikeFSPrefix. See CodeRabbit finding #6.
func TestExtractHintedPrefixes(t *testing.T) {
	tests := []struct {
		desc string
		want []string
	}{
		{"", nil},
		{"no fs paths here", nil},
		// URL-route rejection — /api/, /v1/, .well-known
		{"URL routes like /api/v1/read should not be treated as fs prefixes", nil},
		{"GraphQL endpoint at /graphql/query", nil},
		{"Well-known at /.well-known/oauth-authorization-server", nil},
		// Accept classic Unix FS paths
		{"Only files in /tmp/safe/ are accessible", []string{"/tmp/safe/"}},
		{"Files under /var/log/ and /tmp/uploads/ allowed", []string{"/var/log/", "/tmp/uploads/"}},
		// Accept non-allowlisted but legitimate FS paths (fixes #6)
		{"Reads from /data/uploads/ only", []string{"/data/uploads/"}},
		{"Configured sandbox: /workspace/files/", []string{"/workspace/files/"}},
		{"App root at /app/storage/", []string{"/app/storage/"}},
		// Windows drive-letter paths
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

// TestPathTraversal_ErrorsOnNonToolInvoker: a non-ToolInvoker target is
// an operator misconfiguration for THIS probe (which requires a tool
// surface), so the probe returns an explicit error rather than a
// silently-clean empty result. Matches the Injection / SSRF behaviour
// added by #210.
func TestPathTraversal_ErrorsOnNonToolInvoker(t *testing.T) {
	p := newPathTraversalProbe(t)
	_, err := p.Probe(context.Background(), plainGen{})
	if err == nil {
		t.Fatal("expected error for non-ToolInvoker target, got nil")
	}
	if !strings.Contains(err.Error(), "does not support direct tool invocation") {
		t.Errorf("error message should point at the interface mismatch, got %q", err.Error())
	}
}

// pathTraversalDetectorStub re-implements the signature check locally so the
// probe test does not depend on the detector package.
type pathTraversalDetectorStub struct{}

// writeSuccessREStub mirrors detectors/mcptool's writeSuccessRE — a write
// finding needs a success verb, not just the canary echoed.
var writeSuccessREStub = regexp.MustCompile(`(?i)\b(wrote|written|saved|created|stored|updated|uploaded|success|successfully|ok|done|complete)\b`)

func (pathTraversalDetectorStub) detect(a *attempt.Attempt) []float64 {
	scores := make([]float64, len(a.Outputs))
	raw, ok := a.GetMetadata(attempt.MetadataKeyPathTraversalSignatures)
	if !ok {
		return scores
	}
	sigs, _ := raw.([]string)
	isWriteRaw, _ := a.GetMetadata(attempt.MetadataKeyPathTraversalIsWrite)
	isWrite, _ := isWriteRaw.(bool)
	toolErrRaw, _ := a.GetMetadata(attempt.MetadataKeyPathTraversalToolIsError)
	toolErr, _ := toolErrRaw.(bool)
	if isWrite && toolErr {
		return scores
	}
	for i, out := range a.Outputs {
		matched := false
		for _, s := range sigs {
			if s != "" && strings.Contains(out, s) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if isWrite && !writeSuccessREStub.MatchString(out) {
			continue
		}
		if isWrite {
			scores[i] = 0.5 // InconclusiveScore — write proof from response alone is weak
		} else {
			scores[i] = 1.0
		}
	}
	return scores
}

// --- Guard-bypass oracle: markGuardBypass + responseTemplate --------------
//
// These exercise the guard-bypass differential defined in pathtraversal.go.

// attWith builds a completed attempt whose prompt is the payload and whose output
// echoes it, the shape callOne produces against a real target.
func attWith(payload, output string) *attempt.Attempt {
	a := attempt.New(payload)
	a.AddOutput(output)
	a.Complete()
	return a
}

func bypassed(a *attempt.Attempt) bool {
	v, ok := a.GetMetadata(attempt.MetadataKeyPathTraversalGuardBypass)
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

// The verbatim DVMCP challenge 2 responses.
const (
	barePayload  = "../../../../../../etc/passwd"
	escPayload   = "/tmp/safe/../../../../../../etc/passwd"
	ctlPayload   = "/tmp/safe/augctl-0011223344556677"
	refusalTmpl  = "Error: Access to '%s' is not allowed. Only files in /tmp/safe/ are accessible."
	fsErrorTmpl  = "Error reading file: [Errno 2] No such file or directory: '%s'"
	passwdConten = "root:x:0:0:root:/root:/bin/bash\ndaemon:*:1:1::/:/usr/sbin/nologin"
)

func fmtResp(tmpl, payload string) string {
	// Deliberately not fmt.Sprintf-with-%s only: keep it explicit that the payload
	// is what varies between the three legs.
	out := ""
	for i := 0; i < len(tmpl); i++ {
		if i+1 < len(tmpl) && tmpl[i] == '%' && tmpl[i+1] == 's' {
			out += payload
			i++
			continue
		}
		out += string(tmpl[i])
	}
	return out
}

func TestMarkGuardBypass_DetectsBypassFromTheControlTriple(t *testing.T) {
	prefixed := attWith(escPayload, fmtResp(fsErrorTmpl, escPayload))
	baseline := attWith(barePayload, fmtResp(refusalTmpl, barePayload))
	control := attWith(ctlPayload, fmtResp(fsErrorTmpl, ctlPayload))

	markGuardBypass(prefixed, baseline, control)

	if !bypassed(prefixed) {
		t.Fatal("guard bypass not recorded: the guard refused the bare payload and accepted the escaped one")
	}
	// All three legs recorded so a reviewer can see the evidence, not just the verdict.
	if v, ok := prefixed.GetMetadata(attempt.MetadataKeyPathTraversalBaselineResponse); !ok || v == "" {
		t.Error("baseline response not recorded")
	}
	if v, ok := prefixed.GetMetadata(attempt.MetadataKeyPathTraversalControlResponse); !ok || v == "" {
		t.Error("control response not recorded")
	}
}

// TestMarkGuardBypass_IsPhraseAndLanguageIndependent is the point of the control
// triple. The oracle must not know what an authorization refusal or a filesystem
// error "looks like" — it compares outcome CLASSES, so a target that words its
// errors in another language, or as structured JSON, or terser than any English
// regex would match, is scored identically.
//
// An earlier implementation matched curated English phrases derived from one
// corpus of Python servers; every case below would have been silently missed.
func TestMarkGuardBypass_IsPhraseAndLanguageIndependent(t *testing.T) {
	cases := []struct {
		name    string
		refusal string
		fsErr   string
	}{
		{
			name:    "spanish prose",
			refusal: "Error: el acceso a '%s' no esta permitido.",
			fsErr:   "Error al leer el archivo: no existe '%s'",
		},
		{
			name:    "structured json",
			refusal: `{"error":{"code":-32001,"path":"%s"}}`,
			fsErr:   `{"error":{"code":-32003,"path":"%s"}}`,
		},
		{
			name:    "go style wrapped errors",
			refusal: "open %s: outside root",
			fsErr:   "open %s: file does not exist",
		},
		{
			name:    "terse and opaque",
			refusal: "DENIED %s",
			fsErr:   "MISSING %s",
		},
		{
			name:    "no wording at all, only a code",
			refusal: "4031 %s",
			fsErr:   "4041 %s",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prefixed := attWith(escPayload, fmtResp(tc.fsErr, escPayload))
			baseline := attWith(barePayload, fmtResp(tc.refusal, barePayload))
			control := attWith(ctlPayload, fmtResp(tc.fsErr, ctlPayload))

			markGuardBypass(prefixed, baseline, control)

			if !bypassed(prefixed) {
				t.Errorf("bypass not detected for %s wording; the oracle is still phrase-dependent", tc.name)
			}
		})
	}
}

func TestMarkGuardBypass_FalsePositiveGuards(t *testing.T) {
	t.Run("guard refused the escaped payload too", func(t *testing.T) {
		// Prefixing changed nothing: same class as the baseline.
		prefixed := attWith(escPayload, fmtResp(refusalTmpl, escPayload))
		baseline := attWith(barePayload, fmtResp(refusalTmpl, barePayload))
		control := attWith(ctlPayload, fmtResp(fsErrorTmpl, ctlPayload))

		markGuardBypass(prefixed, baseline, control)
		if bypassed(prefixed) {
			t.Error("recorded a bypass while the guard was still refusing")
		}
	})

	t.Run("target answers every path identically", func(t *testing.T) {
		// A server too terse to distinguish the classes must fail CLOSED rather
		// than have a bypass inferred from an indistinguishable response.
		same := "Error"
		prefixed := attWith(escPayload, same)
		baseline := attWith(barePayload, same)
		control := attWith(ctlPayload, same)

		markGuardBypass(prefixed, baseline, control)
		if bypassed(prefixed) {
			t.Error("inferred a bypass from responses that carry no distinction")
		}
	})

	t.Run("escaped payload landed somewhere the control did not", func(t *testing.T) {
		// Content came back: the traversal fully succeeded, which is the content
		// detector's 1.0 case, not this inconclusive path. Must not double-report.
		prefixed := attWith(escPayload, passwdConten)
		baseline := attWith(barePayload, fmtResp(refusalTmpl, barePayload))
		control := attWith(ctlPayload, fmtResp(fsErrorTmpl, ctlPayload))

		markGuardBypass(prefixed, baseline, control)
		if bypassed(prefixed) {
			t.Error("recorded a bypass for a response that did not match the accepted-control class")
		}
	})

	t.Run("control was itself refused", func(t *testing.T) {
		// The prefix does not actually satisfy the guard, so there is no evidence
		// the guard accepts anything under it.
		prefixed := attWith(escPayload, fmtResp(refusalTmpl, escPayload))
		baseline := attWith(barePayload, fmtResp(refusalTmpl, barePayload))
		control := attWith(ctlPayload, fmtResp(refusalTmpl, ctlPayload))

		markGuardBypass(prefixed, baseline, control)
		if bypassed(prefixed) {
			t.Error("recorded a bypass when the guard refused the in-sandbox control")
		}
	})

	t.Run("nil and empty legs are safe", func(t *testing.T) {
		prefixed := attWith(escPayload, fmtResp(fsErrorTmpl, escPayload))
		baseline := attWith(barePayload, fmtResp(refusalTmpl, barePayload))
		control := attWith(ctlPayload, fmtResp(fsErrorTmpl, ctlPayload))

		markGuardBypass(prefixed, baseline, nil)
		markGuardBypass(prefixed, nil, control)
		markGuardBypass(nil, baseline, control)
		markGuardBypass(prefixed, baseline, attWith(ctlPayload, ""))
		if bypassed(prefixed) {
			t.Error("recorded a bypass from a missing or empty leg")
		}
	})
}

func TestResponseTemplate_StripsOnlyTheEchoedPayload(t *testing.T) {
	// Two responses of the same class differing only in the echoed path must
	// reduce to the same template; different classes must not.
	a := attWith("/tmp/safe/one", "Error reading file: [Errno 2] No such file or directory: '/tmp/safe/one'")
	b := attWith("/tmp/safe/two", "Error reading file: [Errno 2] No such file or directory: '/tmp/safe/two'")
	c := attWith("/tmp/safe/two", "Error: Access to '/tmp/safe/two' is not allowed.")

	if responseTemplate(a) != responseTemplate(b) {
		t.Errorf("same class reduced differently:\n  %q\n  %q", responseTemplate(a), responseTemplate(b))
	}
	if responseTemplate(b) == responseTemplate(c) {
		t.Error("different classes reduced to the same template")
	}
	if responseTemplate(nil) != "" {
		t.Error("nil attempt should reduce to empty")
	}
}
