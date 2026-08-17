package mcptool

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/internal/toolpolicy"
	"github.com/praetorian-inc/augustus/internal/toolsig"
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

// readVerbToolNameRE matches a tool name that reads as a RETRIEVAL rather than an
// issuance. Used to disqualify getters from the predictability sampling: an issuer
// noun in a name ("token", "session") says what the tool deals in, not whether it
// mints anything.
var readVerbToolNameRE = regexp.MustCompile(
	`(?i)(^|[-_.])(get|list|read|show|view|fetch|retrieve|describe|inspect|lookup|find|search|query|current|info|status|check|validate|verify|introspect)($|[-_.])`)

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
	gen  func() (string, error)
}

// shapeFamilies are tried in turn. A target that declares its own shape (a schema
// enum) takes precedence over all of them.
func shapeFamilies() []shapeFamily {
	return []shapeFamily{
		{"hex32", func() (string, error) { return randHex(32) }},
		{"hex64", func() (string, error) { return randHex(64) }},
		{"uuid", randUUID},
		{"base64url32", func() (string, error) { return randAlphabet(32, base64URLAlphabet) }},
		{"jwt", func() (string, error) {
			parts := make([]string, 3)
			for i, n := range []int{16, 24, 32} {
				p, err := randAlphabet(n, base64URLAlphabet)
				if err != nil {
					return "", err
				}
				parts[i] = p
			}
			return strings.Join(parts, "."), nil
		}},
		{"prefixed", func() (string, error) {
			v, err := randAlphabet(24, alnumAlphabet)
			return "tok_" + v, err
		}},
		{"digits10", func() (string, error) { return randAlphabet(10, "0123456789") }},
	}
}

const (
	hexAlphabet       = "0123456789abcdef"
	base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	alnumAlphabet     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

func randHex(n int) (string, error) { return randAlphabet(n, hexAlphabet) }

// randAlphabet returns n characters drawn uniformly from alphabet using a CSPRNG,
// so two values of the same family are independent and neither can collide with a
// token the target actually issued.
func randAlphabet(n int, alphabet string) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Propagated, never degraded. Returning a fixed fallback would submit a
		// PREDICTABLE value while the check's entire premise is that the two values
		// are independent and never-issued — so the verdict would be meaningless
		// rather than merely unlucky. The caller reports the parameter as
		// inconclusive instead.
		return "", fmt.Errorf("mcptool.TokenValidation: CSPRNG unavailable, cannot generate an independent never-issued value: %w", err)
	}
	out := make([]byte, n)
	for i := range b {
		out[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(out), nil
}

// randUUID renders a random RFC 4122 version-4-shaped identifier.
func randUUID() (string, error) {
	h, err := randHex(32)
	if err != nil {
		return "", err
	}
	return h[:8] + "-" + h[8:12] + "-4" + h[13:16] + "-a" + h[17:20] + "-" + h[20:32], nil
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
	// allowDestructive opts in to sampling irreversible-sounding unannotated
	// issuer tools, which this probe calls TWICE.
	allowDestructive bool
}

// NewTokenValidation constructs the probe.
func NewTokenValidation(cfg registry.Config) (probes.Prober, error) {
	policy := toolpolicy.New(cfg)
	return &TokenValidation{
		policy:    policy,
		allParams: registry.GetBool(cfg, "token_all_string_params", false),
		// The shared allow_destructive is the master opt-in; token_allow_destructive
		// is a probe-specific override. EITHER unlocks the name-heuristic gate, so an
		// operator who enabled destructive testing globally is not silently still
		// blocked on unannotated destructive-named tools.
		allowDestructive: policy.AllowsDestructive() || registry.GetBool(cfg, "token_allow_destructive", false),
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
	inv, ok := p.invoker(gen)
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
		// Verification submits values to the REAL tool, so an irreversible-sounding
		// unannotated tool (delete_account(api_key, id)) would have random tokens sent
		// to it — and if it trusts a token's presence, the call performs the operation.
		// toolpolicy.Filter removes only server-annotated destructive tools, so gate
		// here as the issuance path does. Opt in with token_allow_destructive.
		if !p.allowDestructive && mcpprobe.InvokesDestructiveOperation(tool) {
			slog.Warn("mcptool.TokenValidation: skipping token verification against an irreversible-sounding unannotated tool; submitting values to it could perform the operation. Set token_allow_destructive=true to include it. This is NOT a clean result for that tool.",
				"tool", name)
			continue
		}
		// One sweep per CALL SIGNATURE. A credential argument that exists only
		// under one branch of a conditional schema was invisible to the flat
		// reader, so the verification surface it guards was never submitted to.
		for _, sig := range mcpprobe.ToolSignatures(tool) {
			for _, param := range sig.Params {
				if !isStringParam(param.Type) {
					continue
				}
				if !p.allParams && !credentialParamRE.MatchString(mcpprobe.SplitCamelCase(param.Path.Leaf())) {
					continue
				}

				// NEGATIVE CONTROL: a value no validator should accept. It is the
				// baseline every candidate response is compared against, so without it
				// the detector reports inconclusive rather than guessing.
				controlText, controlErr := p.call(ctx, inv, name, sig, param.Path, malformedControlValue)
				if controlErr != nil {
					slog.Warn("mcptool.TokenValidation: malformed-value control call failed; results for this parameter will be inconclusive rather than assumed safe",
						"tool", name, "param", string(param.Path), "error", controlErr)
				}

				for _, fam := range p.candidateShapes(param) {
					a := p.assessShape(ctx, inv, name, sig, param, fam, controlText)
					attempts = append(attempts, a)
				}
			}
		}
	}
	return attempts
}

// unsampledAttempt records an issuing surface whose samples could not be obtained,
// even after a retry.
//
// Logging and moving on was not enough: with no attempt appended, an issuer we
// could NOT assess is indistinguishable in the results from one we assessed and
// found clean. That is the false-clean shape this branch has been removing
// elsewhere, and the retry fix introduced a fresh instance of it.
//
// The failed sample's value is deliberately absent. Where one leg succeeded, that
// value is a live credential the target issued, and an attempt recording an
// unfinished comparison has no use for it.
func (p *TokenValidation) unsampledAttempt(tool, which string, err error) *attempt.Attempt {
	a := attempt.New(fmt.Sprintf("predictability sampling of %q could not be completed", tool))
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[mcpprobe.MetaAuthClass] = mcpprobe.AuthClassTokenPredictable
	a.Metadata[mcpprobe.MetaAuthTool] = tool
	a.Metadata[attempt.MetadataKeyInconclusive] = true
	a.Metadata[attempt.MetadataKeyInconclusiveReason] = fmt.Sprintf(
		"the %s credential sample could not be obtained after a retry, so the two issued values were never compared: %v", which, err)
	slog.Warn("mcptool.TokenValidation: could not complete the predictability sampling, so this issuing surface was NOT assessed; this is not a clean result",
		"tool", tool, "sample", which, "error", err)
	a.SetError(err)
	return a
}

// callToolOnce invokes a tool, retrying once on error.
//
// A differential is destroyed by a single failed leg, so a transient error costs a
// finding rather than producing a wrong verdict. One retry is the same remedy
// mcptool.FunctionAuthorization's callLeg applies.
func callToolOnce(ctx context.Context, inv types.ToolInvoker, name string, args map[string]any) (types.ToolResult, error) {
	res, err := inv.CallTool(ctx, name, args)
	if err == nil {
		return res, nil
	}
	return inv.CallTool(ctx, name, args)
}

// candidateShapes returns the shapes to submit for a parameter.
//
// A parameter that declares an ENUM is deliberately skipped rather than swept.
//
// The check needs two INDEPENDENT values that were certainly never issued, so that
// a surface performing a real issuance lookup must refuse them exactly as it
// refuses the malformed control. A declared enum is the opposite of never-issued:
// it is the closed set of values the target itself says are acceptable. An earlier
// version submitted the first declared value TWICE, so a correctly-implemented
// enum validator accepted both and rejected the malformed control — and that
// differential was reported as accepting forged credentials. Correct behaviour
// scored 1.0.
//
// Deduplicating and using two DISTINCT enum members does not fix it: submitting
// declared-valid values and treating their acceptance as a weakness is the error,
// not the reuse. (A credential literal sitting in a schema enum is a real finding,
// but it is credential EXPOSURE — mcpsecrets.Credential's surface — not weak
// validation.)
func (p *TokenValidation) candidateShapes(param toolsig.Param) []shapeFamily {
	if len(param.Enum) > 0 {
		slog.Info("mcptool.TokenValidation: parameter declares an enum, so every acceptable value is target-declared and none is never-issued; skipping the shape differential for it",
			"param", string(param.Path))
		return nil
	}
	return shapeFamilies()
}

// assessShape submits two independent values of one shape and records them
// alongside the control, for the detector to adjudicate.
func (p *TokenValidation) assessShape(
	ctx context.Context, inv types.ToolInvoker, tool string,
	sig toolsig.Signature, param toolsig.Param,
	fam shapeFamily, controlText string,
) *attempt.Attempt {
	first, err1 := fam.gen()
	second, err2 := fam.gen()

	a := attempt.New(first)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[mcpprobe.MetaAuthClass] = mcpprobe.AuthClassTokenFormatOnly
	a.Metadata[mcpprobe.MetaAuthTool] = tool
	a.Metadata[mcpprobe.MetaAuthParam] = string(param.Path)
	a.Metadata[mcpprobe.MetaAuthShapeFamily] = fam.name
	a.Metadata[mcpprobe.MetaAuthProbeValue] = first
	a.Metadata[mcpprobe.MetaAuthReplicaValue] = second
	a.Metadata[mcpprobe.MetaAuthControlValue] = malformedControlValue
	a.Metadata[mcpprobe.MetaAuthControl] = controlText
	if err1 != nil || err2 != nil {
		// Without two independent never-issued values there is no differential to
		// draw, so this is reported as unassessed rather than as a clean parameter.
		err := err1
		if err == nil {
			err = err2
		}
		a.Metadata[attempt.MetadataKeyInconclusive] = true
		a.Metadata[attempt.MetadataKeyInconclusiveReason] = "could not generate independent never-issued values: " + err.Error()
		slog.Warn("mcptool.TokenValidation: could not generate the probe values, so this parameter was NOT assessed; this is not a clean result",
			"tool", tool, "param", string(param.Path), "shape", fam.name, "error", err)
		a.SetError(err)
		return a
	}
	a.Metadata[mcpprobe.MetaAuthControlLabel] = "same tool and parameter with a structurally malformed value"
	if len(param.Enum) > 0 {
		a.Metadata[mcpprobe.MetaAuthDeclaredValues] = strings.Join(param.Enum, ",")
	}

	firstText, err := p.call(ctx, inv, tool, sig, param.Path, first)
	if err != nil {
		// A failed leg is not a clean parameter: without the first response there is
		// no differential to draw. Marked inconclusive and loud, exactly as the
		// value-generation failure above and the replica failure below do, so a
		// transient error cannot read as 0.0/safe.
		a.Metadata[attempt.MetadataKeyInconclusive] = true
		a.Metadata[attempt.MetadataKeyInconclusiveReason] = "probe verification call failed: " + err.Error()
		markCallOutcome(a, err)
		slog.Warn("mcptool.TokenValidation: the probe verification call failed, so this parameter was NOT assessed; this is not a clean result",
			"tool", tool, "param", string(param.Path), "shape", fam.name, "error", err)
		a.SetError(err)
		return a
	}
	a.AddOutput(firstText)

	secondText, err := p.call(ctx, inv, tool, sig, param.Path, second)
	if err != nil {
		// Without the replica the differential cannot be corroborated. Record the
		// reason so the detector reports uncertainty instead of a verdict.
		a.Metadata[attempt.MetadataKeyInconclusive] = true
		a.Metadata[attempt.MetadataKeyInconclusiveReason] = "same-shape replica call failed: " + err.Error()
		markCallOutcome(a, err)
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
		// The name must suggest the tool ISSUES a credential. The previous condition
		// also accepted any read-only tool, which inverted the intent: read-only says
		// it is SAFE to call a tool twice, never that it hands out credentials.
		//
		// Measured: a `get_config` configuration reader was sampled twice, returned
		// the same configuration value both times (correct, deterministic behaviour),
		// and was reported as predictable credential issuance at 1.0. Generalised,
		// the read-only path fires on every idempotent tool whose response happens to
		// look credential-shaped -- config getters, version endpoints, status and
		// health checks -- all of which are supposed to return the same value twice.
		if !issuerToolNameRE.MatchString(mcpprobe.SplitCamelCase(name)) {
			continue
		}
		// An issuer NOUN is not enough: the name must not also read as a READ.
		//
		// issuerToolNameRE matches `token` and `session` as segments, so
		// `get_session_token` and `get_current_token` qualified as issuing surfaces.
		// A getter that correctly returns the caller's stable current credential
		// returns the SAME value to two reads, which is exactly the signal the
		// predictability check treats as derivable issuance — so correct behaviour
		// scored 1.0. This is the same false positive shape already measured on a
		// configuration reader, arriving through the name vocabulary instead of the
		// read-only gate.
		if readVerbToolNameRE.MatchString(mcpprobe.SplitCamelCase(name)) {
			slog.Info("mcptool.TokenValidation: tool name reads as a getter rather than an issuer; skipping the predictability sampling (returning the same current credential to two reads is correct behaviour, not derivable issuance)",
				"tool", name)
			continue
		}
		// Sampling means invoking the tool TWICE, so an irreversible-sounding
		// unannotated issuer would be performed twice for evidence: two accounts,
		// two grants, two sessions. p.policy.Filter removes only tools the SERVER
		// annotated destructive, and most servers ship no annotations at all.
		if !p.allowDestructive && mcpprobe.InvokesDestructiveOperation(tool) {
			slog.Warn("mcptool.TokenValidation: skipping predictability sampling for an irreversible-sounding unannotated tool, which this check would invoke twice. Set token_allow_destructive=true to include it. This is NOT a clean result for that tool.",
				"tool", name)
			continue
		}
		attempts = append(attempts, p.sampleIssuer(ctx, inv, name, tool)...)
	}
	return attempts
}

// maxIssuerSignatures bounds how many distinct call signatures of one issuing
// tool are sampled. Sampling means invoking the tool TWICE, so a tool with many
// conditional branches would otherwise turn one check into a burst of live
// credential issuances against a customer's server.
const maxIssuerSignatures = 4

// sampleIssuer draws two credentials from each distinct call signature of an
// issuing tool and records the pair for structural comparison.
//
// Sampling per SIGNATURE rather than once per tool is the point of the
// migration: a discriminated tool is several operations behind one name, and
// only one branch may mint anything. Argument objects are deduplicated first, so
// branches that differ only in optional parameters collapse to a single sample
// instead of issuing the same credential repeatedly.
func (p *TokenValidation) sampleIssuer(ctx context.Context, inv types.ToolInvoker, name string, tool map[string]any) []*attempt.Attempt {
	sigs := mcpprobe.ToolSignatures(tool)
	if len(sigs) == 0 {
		slog.Warn("mcptool.TokenValidation: could not read this tool's parameter schema, so its issuance surface was NOT sampled; this is not a clean result for that tool",
			"tool", name)
		return nil
	}

	var (
		attempts []*attempt.Attempt
		seen     = map[string]bool{}
		sampled  int
	)
	for _, sig := range sigs {
		args := mcpprobe.BenignArgs(sig, nil)
		key, err := json.Marshal(args)
		if err == nil {
			if seen[string(key)] {
				continue
			}
			seen[string(key)] = true
		}
		if sampled >= maxIssuerSignatures {
			slog.Warn("mcptool.TokenValidation: more distinct call signatures than the sampling cap; the remaining branches of this issuing tool were NOT sampled. This is NOT a clean result for those branches.",
				"tool", name, "signatures", len(sigs), "cap", maxIssuerSignatures)
			break
		}
		sampled++

		if a := p.samplePair(ctx, inv, name, args); a != nil {
			attempts = append(attempts, a)
		}
	}
	return attempts
}

// samplePair invokes one concrete call twice and records how the two issued
// credentials relate. It returns nil when the tool issues nothing
// credential-shaped, which is not a finding and not a failure.
func (p *TokenValidation) samplePair(ctx context.Context, inv types.ToolInvoker, name string, args map[string]any) *attempt.Attempt {
	// Each leg is retried once, for the same reason callLeg is: a transient
	// failure under load destroys the comparison rather than producing a wrong
	// answer, so a dropped request silently costs a finding. Measured on the
	// benchmark corpus, contention alone accounted for lost findings.
	firstRes, err1 := callToolOnce(ctx, inv, name, args)
	if err1 != nil {
		return p.unsampledAttempt(name, "first", err1)
	}
	firstTok := extractCredentialLike(firstRes.Text)
	if firstTok == "" {
		return nil // this call issues nothing credential-shaped
	}
	secondRes, err2 := callToolOnce(ctx, inv, name, args)
	if err2 != nil {
		return p.unsampledAttempt(name, "second", err2)
	}
	secondTok := extractCredentialLike(secondRes.Text)
	if secondTok == "" {
		return nil
	}

	// Compared HERE, in memory, and only the verdict is recorded. Both values
	// are live credentials the target just issued; storing them so the detector
	// could compare them later would put working credentials in the attempt
	// metadata, the JSONL report and every downstream consumer.
	relation := mcpprobe.IssuedRelation(firstTok, secondTok)
	evidence := fmt.Sprintf("first %s; second %s",
		mcpprobe.RedactCredential(firstTok), mcpprobe.RedactCredential(secondTok))

	a := attempt.New(fmt.Sprintf("two credentials issued in close succession by %q", name))
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[mcpprobe.MetaAuthClass] = mcpprobe.AuthClassTokenPredictable
	a.Metadata[mcpprobe.MetaAuthTool] = name
	a.Metadata[mcpprobe.MetaAuthIssuedRelation] = relation
	a.Metadata[mcpprobe.MetaAuthIssuedEvidence] = evidence
	a.AddOutput(fmt.Sprintf("two credentials issued in close succession relate as %q (%s)", relation, evidence))
	a.Complete()
	return a
}

// call invokes a tool with value in one parameter and benign placeholders
// elsewhere, returning the response text.
func (p *TokenValidation) call(
	ctx context.Context, inv types.ToolInvoker, tool string,
	sig toolsig.Signature, param toolsig.Path, value string,
) (string, error) {
	args := mcpprobe.BenignArgs(sig, map[toolsig.Path]any{param: value})
	// Retried once (via callToolOnce), like FunctionAuthorization's callLeg: a
	// single transient failure of a leg destroys the differential, so without the
	// retry it would cost a finding rather than produce a wrong verdict.
	res, err := callToolOnce(ctx, inv, tool, args)
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
