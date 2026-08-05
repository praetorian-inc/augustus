package mcptool

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/internal/toolpolicy"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("mcptool.TokenValidation", NewTokenValidation)
}

var (
	_ types.ProbeMetadata     = (*TokenValidation)(nil)
	_ types.RiskDescriber     = (*TokenValidation)(nil)
	_ recon.ContextAwareProbe = (*TokenValidation)(nil)
)

// credentialParamRE matches tool parameter names that conventionally carry a
// credential, identifying a target's token VERIFICATION surface. A conventional
// vocabulary — nothing specific to any server or benchmark.
var credentialParamRE = regexp.MustCompile(
	`(?i)(^|[_\- ])(token|auth|authorization|authentication|apikey|api_key|key|secret|credential|credentials|session|session_id|sessionid|jwt|bearer|password|passwd|cookie|signature|otp|passcode)($|[_\- ])`)

// issuerToolNameRE matches tool names that conventionally ISSUE a credential.
// Used to choose which tools to sample twice for the predictability check, so the
// probe does not call every tool on the target twice over.
var issuerToolNameRE = regexp.MustCompile(
	`(?i)(^|[-_.])(authenticate|authorize|login|logon|signin|sign_in|token|session|issue|refresh|grant|register|enroll|provision|connect|start)($|[-_.])`)

// malformedControlValue is the negative control: a value structurally invalid for
// any credential format whatsoever (punctuation only, two characters). It is the
// one literal value the probe hardcodes, and it is deliberately NOT a credential
// shape — its whole purpose is to be rejected by any validator so the well-formed
// candidates have a refusal baseline to be compared against.
const malformedControlValue = "!!"

// shapeFamily is a GENERIC structural credential shape — the forms opaque
// credentials take across the industry, not any particular target's format.
//
// This list is the probe's answer to "send a well-formed but never-issued value"
// when the target advertises no shape of its own. Every instance is randomly
// generated per call, so no value the probe sends is a fixed string, and each is
// astronomically unlikely to be a token the target ever issued. Crucially, the
// verdict never depends on WHICH family produced a response: the finding is that
// the target's answer partitioned by SHAPE rather than by ISSUANCE, which is
// established by comparing responses to each other.
type shapeFamily struct {
	name string
	gen  func() string
}

// shapeFamilies are tried in turn. A target that declares its own shape (a schema
// enum) takes precedence over all of them.
func shapeFamilies() []shapeFamily {
	return []shapeFamily{
		{"hex32", func() string { return randHex(32) }},
		{"hex64", func() string { return randHex(64) }},
		{"uuid", randUUID},
		{"base64url32", func() string { return randAlphabet(32, base64URLAlphabet) }},
		{"jwt", func() string {
			return randAlphabet(16, base64URLAlphabet) + "." + randAlphabet(24, base64URLAlphabet) + "." + randAlphabet(32, base64URLAlphabet)
		}},
		{"prefixed", func() string { return "tok_" + randAlphabet(24, alnumAlphabet) }},
		{"digits10", func() string { return randAlphabet(10, "0123456789") }},
	}
}

const (
	hexAlphabet       = "0123456789abcdef"
	base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	alnumAlphabet     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

func randHex(n int) string { return randAlphabet(n, hexAlphabet) }

// randAlphabet returns n characters drawn uniformly from alphabet using a CSPRNG,
// so two values of the same family are independent and neither can collide with a
// token the target actually issued.
func randAlphabet(n int, alphabet string) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// A CSPRNG failure must not silently degrade to a predictable value that
		// could collide with a real token; surface it in the value itself.
		return strings.Repeat("0", n)
	}
	out := make([]byte, n)
	for i := range b {
		out[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(out)
}

// randUUID renders a random RFC 4122 version-4-shaped identifier.
func randUUID() string {
	h := randHex(32)
	return h[:8] + "-" + h[8:12] + "-4" + h[13:16] + "-a" + h[17:20] + "-" + h[20:32]
}

// TokenValidation tests a target's own credential-handling surfaces for two
// weaknesses that let a caller authenticate without ever having been issued a
// credential.
//
// # Format-only validation
//
// A verification surface should answer "was this value ISSUED?". A weak one
// answers "does this value LOOK like a credential?". The probe distinguishes them
// without knowing anything about the target's token format, and without matching
// on success or failure wording, by using the target's own responses as the
// oracle:
//
//	Two INDEPENDENT random values of the same shape are submitted, plus one
//	structurally malformed control. Both random values were certainly never
//	issued, so a surface performing a real issuance lookup must answer them
//	exactly as it answers the malformed control — all three are simply "not a
//	credential I issued". A surface that answers the two alike but the control
//	differently is discriminating on SHAPE, and has no idea whether the value was
//	ever issued.
//
// No token format is hardcoded. When the target declares its own accepted values
// (a JSON-schema enum) those are used; otherwise the probe sweeps generic
// structural families (see shapeFamily), each randomly generated per call. The
// verdict is the response differential and never depends on which family hit.
//
// # Predictable issuance
//
// An issuing surface is sampled twice in close succession and the two values are
// compared structurally — identical, sequential, or near-identical values mean one
// holder can derive another's credential.
type TokenValidation struct {
	reconContext
	policy    toolpolicy.Policy
	allParams bool
}

// NewTokenValidation constructs the probe.
func NewTokenValidation(cfg registry.Config) (probes.Prober, error) {
	return &TokenValidation{
		policy:    toolpolicy.New(cfg),
		allParams: registry.GetBool(cfg, "token_all_string_params", false),
	}, nil
}

func (p *TokenValidation) Name() string { return "mcptool.TokenValidation" }

// RiskInfo is the curated security write-up for this probe's finding.
func (p *TokenValidation) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description:    "An MCP tool that verifies a credential accepts a value it never issued, because it checks the value's format rather than whether it was ever issued. A related weakness is an issuing tool whose credentials are predictable across closely-spaced requests, letting the holder of one derive another's.",
		Impact:         "A caller can mint an acceptable credential without ever authenticating, then use it wherever the server trusts a verified credential. Because the verification surface is what other tools rely on to establish identity, this defeats authentication for the whole tool surface and any privileged operation gated behind it. Predictable issuance has the same effect against a specific victim: their credential can be derived rather than stolen.",
		Recommendation: "Validate credentials against authoritative issuance state — a server-side session store, a signature verified with a secret the client never sees, or an introspection call to the issuer — and never accept a value merely because it matches an expected pattern. Bind each credential to an identity, an expiry, and a scope, and check all three on every use. Generate credentials from a cryptographically secure random source with at least 128 bits of entropy, never from counters, timestamps, or user-derived values.",
		References:     "https://cwe.mitre.org/data/definitions/287.html\nhttps://cwe.mitre.org/data/definitions/290.html\nhttps://cwe.mitre.org/data/definitions/330.html\nhttps://cwe.mitre.org/data/definitions/340.html\nhttps://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
		Taxonomies:     "- cwe: 287\n- cwe: 330\n- cwe: 340\n- owasp: MCP07",
		CVSSVector:     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
		Verification: "## How this is confirmed\n\n" +
			"For format-only validation, Augustus submits two independently generated random values of the same shape to the verification tool, plus one structurally malformed control. Both random values were certainly never issued, so a tool that checks issuance must answer them exactly as it answers the malformed control. The finding is recorded when the tool answers the two alike but the control differently, which means it is discriminating on the value's shape and has no knowledge of whether the value was ever issued.\n\n" +
			"The adjudication compares the tool's own responses against each other after masking out the submitted values, which servers commonly echo. It does not search for a success or failure phrase and assumes no token format. Where the target declares its accepted values in the tool's schema, those declared values are used; otherwise generic structural credential shapes are tried, each randomly generated per call, and the verdict never depends on which shape produced the response. When two rejections are merely worded differently the result is reported inconclusive rather than as a finding.\n\n" +
			"For predictable issuance, Augustus samples the issuing tool twice in close succession and compares the two values structurally: identical, sequential, or near-identical values mean the credential can be derived rather than guessed.\n\n" +
			"## Reproduce\n\n" +
			"Re-run the `mcptool.TokenValidation` probe against the affected endpoint via the `mcp.MCP` generator. Submitting a freshly generated random value of the reported shape to the verification tool returns the same accepting response as any other value of that shape, though no such credential was ever issued.",
	}
}

func (p *TokenValidation) Description() string {
	return "Tests a target's credential verification surface for format-only validation — accepting a well-formed but never-issued value — by submitting two independent same-shape random values plus a malformed control and comparing the target's own responses, with no hardcoded token format and no success-string matching. Also samples issuing surfaces twice to detect predictable credentials."
}

func (p *TokenValidation) Goal() string {
	return "Determine whether a credential verification tool validates a value's format instead of its issuance, and whether issued credentials are predictable across closely-spaced requests"
}

func (p *TokenValidation) GetPrimaryDetector() string { return "mcptool.TokenValidation" }

func (p *TokenValidation) GetPrompts() []string {
	return []string{"randomly generated well-formed credential values plus a malformed control, submitted to credential-shaped tool parameters"}
}

// Probe gathers the evidence; the detector renders the verdict.
func (p *TokenValidation) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	inv, ok := gen.(types.ToolInvoker)
	if !ok {
		return nil, fmt.Errorf("mcptool.TokenValidation: target %q does not support direct tool invocation; this probe requires a tool-surface generator such as mcp.MCP", gen.Name())
	}
	tools, err := p.resolveTools(ctx, gen)
	if err != nil {
		return nil, fmt.Errorf("mcptool.TokenValidation: list tools: %w", err)
	}
	tools = p.policy.Filter(p.Name(), tools)
	if len(tools) == 0 {
		return nil, nil
	}

	attempts := p.probeVerificationSurfaces(ctx, inv, tools)
	attempts = append(attempts, p.probeIssuanceSurfaces(ctx, inv, tools)...)

	if len(attempts) == 0 {
		slog.Warn("mcptool.TokenValidation: no credential-shaped tool parameters and no issuing tools found, so no credential-handling surface was assessed; set token_all_string_params=true to submit candidate values to every string parameter. This is NOT a clean result.",
			"tools", len(tools))
		return nil, nil
	}
	return attempts, nil
}

// probeVerificationSurfaces submits well-formed candidates plus a malformed
// control to every credential-shaped parameter.
func (p *TokenValidation) probeVerificationSurfaces(ctx context.Context, inv types.ToolInvoker, tools []map[string]any) []*attempt.Attempt {
	var attempts []*attempt.Attempt
	for _, tool := range tools {
		name, _ := tool["name"].(string)
		if name == "" {
			continue
		}
		params := mcpprobe.ToolParams(tool)
		for _, param := range params {
			if !isStringParam(param.Type) {
				continue
			}
			if !p.allParams && !credentialParamRE.MatchString(param.Name) {
				continue
			}

			// NEGATIVE CONTROL: a value no validator should accept. It is the
			// baseline every candidate response is compared against, so without it
			// the detector reports inconclusive rather than guessing.
			controlText, controlErr := p.call(ctx, inv, name, params, param.Name, malformedControlValue)
			if controlErr != nil {
				slog.Warn("mcptool.TokenValidation: malformed-value control call failed; results for this parameter will be inconclusive rather than assumed safe",
					"tool", name, "param", param.Name, "error", controlErr)
			}

			for _, fam := range p.candidateShapes(param) {
				a := p.assessShape(ctx, inv, name, params, param, fam, controlText)
				attempts = append(attempts, a)
			}
		}
	}
	return attempts
}

// candidateShapes returns the shapes to submit for a parameter. A shape the
// TARGET ITSELF declares wins outright: the probe is then exercising the
// documented interface rather than sweeping generic forms.
func (p *TokenValidation) candidateShapes(param mcpprobe.ToolParam) []shapeFamily {
	if len(param.Enum) > 0 {
		declared := param.Enum
		return []shapeFamily{{
			name: "declared-enum",
			gen:  func() string { return declared[0] },
		}}
	}
	return shapeFamilies()
}

// assessShape submits two independent values of one shape and records them
// alongside the control, for the detector to adjudicate.
func (p *TokenValidation) assessShape(
	ctx context.Context, inv types.ToolInvoker, tool string,
	params []mcpprobe.ToolParam, param mcpprobe.ToolParam,
	fam shapeFamily, controlText string,
) *attempt.Attempt {
	first, second := fam.gen(), fam.gen()

	a := attempt.New(first)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[mcpprobe.MetaAuthClass] = mcpprobe.AuthClassTokenFormatOnly
	a.Metadata[mcpprobe.MetaAuthTool] = tool
	a.Metadata[mcpprobe.MetaAuthParam] = param.Name
	a.Metadata[mcpprobe.MetaAuthShapeFamily] = fam.name
	a.Metadata[mcpprobe.MetaAuthProbeValue] = first
	a.Metadata[mcpprobe.MetaAuthReplicaValue] = second
	a.Metadata[mcpprobe.MetaAuthControlValue] = malformedControlValue
	a.Metadata[mcpprobe.MetaAuthControl] = controlText
	a.Metadata[mcpprobe.MetaAuthControlLabel] = "same tool and parameter with a structurally malformed value"
	if len(param.Enum) > 0 {
		a.Metadata[mcpprobe.MetaAuthDeclaredValues] = strings.Join(param.Enum, ",")
	}

	firstText, err := p.call(ctx, inv, tool, params, param.Name, first)
	if err != nil {
		a.SetError(err)
		return a
	}
	a.AddOutput(firstText)

	secondText, err := p.call(ctx, inv, tool, params, param.Name, second)
	if err != nil {
		// Without the replica the differential cannot be corroborated. Record the
		// reason so the detector reports uncertainty instead of a verdict.
		a.Metadata[attempt.MetadataKeyInconclusive] = true
		a.Metadata[attempt.MetadataKeyInconclusiveReason] = "same-shape replica call failed: " + err.Error()
	} else {
		a.Metadata[mcpprobe.MetaAuthReplicaResponse] = secondText
	}
	a.Complete()
	return a
}

// probeIssuanceSurfaces samples conventional issuing tools twice and records the
// pair for structural comparison.
//
// Only tools whose names conventionally denote issuance, or that the server
// annotates read-only, are sampled: calling every tool on the target twice over
// would be both slow and unsafe.
func (p *TokenValidation) probeIssuanceSurfaces(ctx context.Context, inv types.ToolInvoker, tools []map[string]any) []*attempt.Attempt {
	var attempts []*attempt.Attempt
	for _, tool := range tools {
		name, _ := tool["name"].(string)
		if name == "" {
			continue
		}
		if !issuerToolNameRE.MatchString(name) && !mcpprobe.IsReadOnlyTool(tool) {
			continue
		}
		params := mcpprobe.ToolParams(tool)
		args := mcpprobe.BenignArgs(params, nil)

		firstRes, err1 := inv.CallTool(ctx, name, args)
		if err1 != nil {
			continue
		}
		firstTok := extractCredentialLike(firstRes.Text)
		if firstTok == "" {
			continue // this tool issues nothing credential-shaped
		}
		secondRes, err2 := inv.CallTool(ctx, name, args)
		if err2 != nil {
			continue
		}
		secondTok := extractCredentialLike(secondRes.Text)
		if secondTok == "" {
			continue
		}

		a := attempt.New(fmt.Sprintf("two credentials issued in close succession by %q", name))
		a.Probe = p.Name()
		a.Detector = p.GetPrimaryDetector()
		a.Metadata[mcpprobe.MetaAuthClass] = mcpprobe.AuthClassTokenPredictable
		a.Metadata[mcpprobe.MetaAuthTool] = name
		a.Metadata[mcpprobe.MetaAuthProbeValue] = firstTok
		a.Metadata[mcpprobe.MetaAuthReplicaValue] = secondTok
		a.AddOutput(fmt.Sprintf("first issued value: %s\nsecond issued value: %s", firstTok, secondTok))
		a.Complete()
		attempts = append(attempts, a)
	}
	return attempts
}

// call invokes a tool with value in one parameter and benign placeholders
// elsewhere, returning the response text.
func (p *TokenValidation) call(
	ctx context.Context, inv types.ToolInvoker, tool string,
	params []mcpprobe.ToolParam, param, value string,
) (string, error) {
	args := mcpprobe.BenignArgs(params, map[string]any{param: value})
	res, err := inv.CallTool(ctx, tool, args)
	if err != nil {
		return "", err
	}
	return res.Text, nil
}

// credentialLikeRE matches a run of credential-alphabet characters long enough to
// be an opaque credential. It is used to pull an issued value out of a tool
// response for the predictability comparison.
var credentialLikeRE = regexp.MustCompile(`[A-Za-z0-9._\-]{16,}`)

// extractCredentialLike returns the longest credential-shaped run in a response,
// or "" when the response contains none.
//
// A run must mix character classes (letters AND digits) or be long unbroken hex.
// Prose does not qualify: without that requirement ordinary English words in an
// error message would be mistaken for issued credentials, and every server that
// returns a sentence would look like it issues predictable tokens.
func extractCredentialLike(text string) string {
	best := ""
	for _, candidate := range credentialLikeRE.FindAllString(text, -1) {
		if !looksLikeCredential(candidate) {
			continue
		}
		if len(candidate) > len(best) {
			best = candidate
		}
	}
	return best
}

// looksLikeCredential reports whether a character run is plausibly an opaque
// credential rather than a word.
func looksLikeCredential(s string) bool {
	var hasLetter, hasDigit, hasUpper bool
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c >= 'a' && c <= 'z':
			hasLetter = true
		case c >= 'A' && c <= 'Z':
			hasLetter, hasUpper = true, true
		}
	}
	if hasLetter && hasDigit {
		return true
	}
	// All-hex runs of 16+ (a digest or session id) have no letters outside a-f and
	// may legitimately contain no digits at all.
	if hasLetter && !hasUpper && isAllHex(s) {
		return true
	}
	return false
}

// isAllHex reports whether every character is a lowercase hex digit.
func isAllHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
