package mcptool

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
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
	probes.Register("mcptool.FunctionAuthorization", NewFunctionAuthorization)
}

var (
	_ types.ProbeMetadata     = (*FunctionAuthorization)(nil)
	_ types.RiskDescriber     = (*FunctionAuthorization)(nil)
	_ recon.ContextAwareProbe = (*FunctionAuthorization)(nil)
)

// privilegedToolNameRE matches tool names that conventionally denote a privileged
// operation — administration, access control, credential handling, or command
// execution. A conventional vocabulary, nothing target-specific.
var privilegedToolNameRE = regexp.MustCompile(
	`(?i)(^|[-_.])(admin|administrate|manage|management|grant|revoke|permission|permissions|privilege|privileges|role|roles|sudo|root|exec|execute|command|shell|remote|access|config|configure|configuration|setting|settings|secret|secrets|credential|credentials|token|user|users|account|accounts|delete|disable|enable|reset|override|impersonate|escalate|promote|assign|provision|deploy|restart|shutdown)($|[-_.])`)

// Note on parameter selection: an earlier version also qualified a parameter by a
// conventional NAME pattern (role, user, level, mode, system, ...). That was
// removed because a name cannot supply a baseline — see the comment in
// probeDiscriminator. Qualification is now solely "the target declares values for
// this parameter", which is what makes the sweep a differential rather than a
// comparison against a string the server has never seen.

// contentParamRE matches parameters that carry a PAYLOAD rather than select an
// authority: the thing to execute, render, query or process. They are excluded
// from the privileged-value sweep because on such a parameter any novel value
// produces novel behaviour, so a response differential proves nothing about
// authorization.
//
// Measured on an independent lab: `execute_system_command(command)` scored 1.0
// because the conventional name "sa" happened to be a runnable command while the
// controls were not. That is real remote code execution -- and mcptool.Injection
// reports it correctly, nine times -- but filing it as an authorization bypass is
// the wrong finding under the wrong risk slug.
var contentParamRE = regexp.MustCompile(
	`(?i)(^|[_\- ])(command|cmd|script|code|exec|expression|expr|query|sql|statement|template|payload|body|content|text|data|input|prompt|message|message_body)($|[_\- ])`)

// maxDeclaredValues bounds how many target-declared values are exercised per
// parameter, so a schema enumerating hundreds of values cannot turn one probe into
// a many-thousand-call scan.
const maxDeclaredValues = 5

// FunctionAuthorization tests whether privileged MCP tool operations are actually
// gated on the caller's authority.
//
// This is FUNCTION-level authorization — can a caller reach a privileged
// OPERATION at all — and is deliberately kept separate from mcptool.BOLA, which
// covers OBJECT-level authorization (can identity A read identity B's objects).
// The verdicts answer different questions and are reported as different findings.
//
// # Two checks, both differentials
//
// CREDENTIAL PRESENCE vs VALIDITY. Where a tool takes an OPTIONAL
// credential-shaped argument, the probe compares the call with that argument
// OMITTED against the same call carrying a random, certainly-invalid value. A
// server that behaves differently is treating the argument's PRESENCE as proof of
// authority — it never checked the value.
//
// PRIVILEGE DISCRIMINATOR. Where a parameter selects an authority level, the probe
// exercises the values the TARGET ITSELF declares (schema enum, or values
// documented in its description) to establish what ordinary authority looks like,
// then tries a small conventional set of privileged names. The finding is the
// DIFFERENTIAL — a call that reached behaviour a declared value did not — never the
// presence of any particular string.
//
// # On not overfitting
//
// The probe carries no target-specific value. Declared values come from the
// target; the privileged names are the conventional set a practitioner tries on
// every engagement (see mcpprobe.ConventionalPrivilegedNames), capped by a test to
// stop it drifting into a corpus-specific wordlist. A target whose privileged
// value is not conventional and is not declared anywhere is reported as NOT
// vulnerable, which is the honest result: the probe found no authorization
// differential it could demonstrate. Reporting otherwise would require hardcoding
// a value that finds nothing in the field.
//
// # Safety
//
// The probe invokes privileged-LOOKING operations, which is inherent to the check
// — an authorization boundary can only be tested by trying to cross it. It honours
// internal/toolpolicy throughout (allow-list, deny-list, and the
// server-annotated-destructive gate).
//
// It additionally REFUSES, by default, to invoke a tool whose name denotes an
// irreversible operation when the server supplies no annotation to the contrary.
// toolpolicy deliberately keeps unannotated tools — "a scanner's worst outcome is a
// silent false negative" — which is right for probes sending an inert payload and
// wrong for one whose method IS performing the privileged operation. Most real
// servers ship no annotations, so that is the common case, and the privileged-name
// vocabulary above includes delete, shutdown, restart and revoke. Skipped tools are
// reported loudly as unassessed. Set authz_allow_destructive=true to include them.
//
// Against production infrastructure, scope with tool_allowlist regardless.
type FunctionAuthorization struct {
	reconContext
	policy toolpolicy.Policy
	// allTools widens the sweep from conventionally-privileged tool names to every
	// tool the policy permits.
	allTools bool
	// allowDestructive opts in to invoking irreversible-sounding unannotated
	// tools. Off by default: see privilegedTools.
	allowDestructive bool
}

// NewFunctionAuthorization constructs the probe.
func NewFunctionAuthorization(cfg registry.Config) (probes.Prober, error) {
	policy := toolpolicy.New(cfg)
	return &FunctionAuthorization{
		policy:   policy,
		allTools: registry.GetBool(cfg, "authz_all_tools", false),
		// The shared allow_destructive is the master opt-in; authz_allow_destructive
		// is a probe-specific override. EITHER unlocks the name-heuristic gate, so an
		// operator who enabled destructive testing globally is not silently still
		// blocked on unannotated destructive-named tools.
		allowDestructive: policy.AllowsDestructive() || registry.GetBool(cfg, "authz_allow_destructive", false),
	}, nil
}

func (p *FunctionAuthorization) Name() string { return "mcptool.FunctionAuthorization" }

// RiskInfo is the curated security write-up for this probe's finding.
func (p *FunctionAuthorization) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description:    "A privileged MCP tool operation is reachable without valid authorization. Either the tool treats the mere presence of a credential argument as proof of authority without validating its value, or an argument that selects an authority level reaches behaviour the values the tool documents do not — so a caller can choose the authority the operation runs with.",
		Impact:         "A caller with no privileged authority can invoke operations the deployment intends to restrict — administrative actions, access-control changes, credential retrieval, or command execution on the systems the tool fronts. Because the tool surface is the trust boundary in front of those backends, a caller who can select their own authority level effectively holds whatever authority the server does, and can escalate by asking rather than by exploiting anything.",
		Recommendation: "Derive the caller's authority from the authenticated session on the server side and never from an argument the caller supplies. Validate any credential argument against authoritative issuance state rather than checking that it is present, and reject an absent or invalid one. Enforce the check inside each privileged operation, not only at the transport, so a tool cannot be reached by a caller the transport happened to admit. Constrain authority-selecting arguments to a server-side allow-list bound to the caller's identity, and log every privileged invocation with the identity it ran as.",
		References:     "https://cwe.mitre.org/data/definitions/862.html\nhttps://cwe.mitre.org/data/definitions/863.html\nhttps://cwe.mitre.org/data/definitions/269.html\nhttps://cwe.mitre.org/data/definitions/1220.html\nhttps://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
		Taxonomies:     "- cwe: 862\n- cwe: 863\n- cwe: 269\n- owasp: MCP07",
		CVSSVector:     "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
		Verification: "## How this is confirmed\n\n" +
			"Both checks are differentials, established from the target's own responses rather than from any expected phrase or value format.\n\n" +
			"For credential presence, Augustus calls a privileged tool twice: once with its optional credential argument omitted, and once with that argument carrying a freshly generated random value that was certainly never issued. A server that answers the two differently is reacting to the argument being THERE rather than to what it contains, so it never validated the credential at all.\n\n" +
			"For the authority discriminator, Augustus first exercises the values the tool itself declares — in its parameter schema, or documented in its description — to establish what ordinary authority looks like on this target. It then tries a small conventional set of privileged names. A finding is recorded only when one of those calls reaches behaviour a declared value did not; the finding is that differential in authorization behaviour, never the presence of a particular string.\n\n" +
			"Submitted values are masked out of both responses before they are compared, because servers commonly echo them. Where the two responses are merely differently worded refusals, the result is reported inconclusive rather than as a finding.\n\n" +
			"This is function-level authorization — whether a privileged operation can be reached at all — and is reported separately from object-level authorization, which the BOLA probe covers.\n\n" +
			"## Reproduce\n\n" +
			"Re-run the `mcptool.FunctionAuthorization` probe against the affected endpoint via the `mcp.MCP` generator. Invoking the reported tool with the reported argument reproduces the response that the equivalent unauthorized call does not receive.",
	}
}

func (p *FunctionAuthorization) Description() string {
	return "Tests whether privileged MCP tool operations enforce function-level authorization: whether the mere presence of a credential argument is mistaken for its validity, and whether an authority-selecting argument reaches behaviour the target's own declared values do not. Reports the differential in authorization behaviour, never the presence of a particular value."
}

func (p *FunctionAuthorization) Goal() string {
	return "Determine whether a privileged tool operation can be reached without valid authorization, by comparing an unauthorized call against an equivalent call the target itself documents"
}

func (p *FunctionAuthorization) GetPrimaryDetector() string {
	return "mcptool.FunctionAuthorization"
}

func (p *FunctionAuthorization) GetPrompts() []string {
	return []string{"privileged tool invocations with an absent versus an invalid credential argument, and with target-declared versus conventional privileged discriminator values"}
}

// Probe gathers the evidence; the detector renders the verdict.
func (p *FunctionAuthorization) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	inv, ok := gen.(types.ToolInvoker)
	if !ok {
		return nil, fmt.Errorf("mcptool.FunctionAuthorization: target %q does not support direct tool invocation; this probe requires a tool-surface generator such as mcp.MCP", gen.Name())
	}
	tools, err := p.resolveTools(ctx, gen)
	if err != nil {
		return nil, fmt.Errorf("mcptool.FunctionAuthorization: list tools: %w", err)
	}
	tools = p.policy.Filter(p.Name(), tools)
	if len(tools) == 0 {
		return nil, nil
	}

	targets := p.privilegedTools(tools)
	if len(targets) == 0 {
		slog.Warn("mcptool.FunctionAuthorization: no conventionally-privileged tool names found, so no function-level authorization boundary was assessed; set authz_all_tools=true to test every permitted tool. This is NOT a clean result.",
			"tools", len(tools))
		return nil, nil
	}
	slog.Info("mcptool.FunctionAuthorization: probing privileged operations; this invokes them. Scope with tool_allowlist against production infrastructure.",
		"privileged_tools", len(targets))

	var attempts []*attempt.Attempt
	for _, tool := range targets {
		// Order matters. The discriminator sweep runs FIRST because it discovers
		// which argument combinations the target refuses, and a refusal is exactly
		// the context worth retrying with a credential attached.
		//
		// Without this, the credential check would only ever run with benign
		// placeholder arguments and would never reach a privileged code path — so a
		// tool that gates its privileged branch on the mere presence of a token
		// would be reported clean, because the benign context never got as far as
		// the gate.
		discAttempts, refused := p.probeDiscriminator(ctx, inv, tool)
		attempts = append(attempts, discAttempts...)
		attempts = append(attempts, p.probeCredentialPresence(ctx, inv, tool, refused)...)
	}
	if len(attempts) == 0 {
		slog.Warn("mcptool.FunctionAuthorization: privileged tools were found but none exposed an optional credential argument or an authority-selecting parameter, so nothing could be compared. This is NOT a clean result.",
			"privileged_tools", len(targets))
		return nil, nil
	}
	return attempts, nil
}

// privilegedTools selects the tools whose names conventionally denote a privileged
// operation (or every permitted tool when authz_all_tools is set).
func (p *FunctionAuthorization) privilegedTools(tools []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(tools))
	skipped := 0
	for _, tm := range tools {
		name, _ := tm["name"].(string)
		if name == "" {
			continue
		}
		// allTools widens the sweep from conventionally-privileged names to every
		// permitted tool, but it bypasses ONLY the name filter — never the
		// destructive safety gate below. Returning every tool here (the previous
		// behaviour) handed an unannotated delete_user / reset_password to the probe
		// with authz_allow_destructive still false, so proving the boundary would
		// perform the irreversible operation.
		if !p.allTools && !privilegedToolNameRE.MatchString(mcpprobe.SplitCamelCase(name)) {
			continue
		}
		// This probe PROVES a missing authorization boundary by performing the
		// privileged operation, so for an irreversible-sounding operation the
		// evidence-gathering is itself the damage. internal/toolpolicy keeps
		// unannotated tools on purpose ("a scanner's worst outcome is a silent
		// false negative"), which is the right trade for a probe sending an inert
		// payload and the wrong one here — and the privileged-name vocabulary
		// above deliberately includes delete, shutdown, restart and revoke.
		//
		// Measured: most real MCP servers ship no annotations at all, so this is
		// the common case, not an edge case.
		if !p.allowDestructive && mcpprobe.InvokesDestructiveOperation(tm) {
			skipped++
			slog.Warn("mcptool.FunctionAuthorization: skipping a privileged tool whose name denotes an irreversible operation and which carries no read-only annotation; proving the boundary here would mean performing that operation. Set authz_allow_destructive=true to include it.",
				"tool", name)
			continue
		}
		out = append(out, tm)
	}
	if skipped > 0 {
		slog.Warn("mcptool.FunctionAuthorization: some privileged tools were NOT assessed because invoking them is destructive and they carry no annotation. This is NOT a clean result for those tools.",
			"skipped", skipped)
	}
	return out
}

// maxPresenceContexts bounds how many refused argument contexts are retried with a
// credential, so a tool with a large value space cannot expand this check without
// limit.
const maxPresenceContexts = 6

// probeCredentialPresence compares an OMITTED optional credential argument against
// the same call carrying a random, certainly-invalid value.
//
// Only OPTIONAL credential parameters qualify: a required one cannot be omitted,
// so there would be no control to compare against.
//
// The check runs in several argument CONTEXTS: the plain benign one, plus each
// context the discriminator sweep found refused. The extra contexts are essential
// rather than thorough — a tool's privileged branch is usually only reachable with
// a particular value in some OTHER argument, and with benign placeholders alone the
// call never arrives at the credential gate, so a tool that trusts the mere
// presence of a token would be reported clean.
func (p *FunctionAuthorization) probeCredentialPresence(
	ctx context.Context, inv types.ToolInvoker, tool map[string]any, refused []argContext,
) []*attempt.Attempt {
	name, _ := tool["name"].(string)

	contexts := append([]argContext{nil}, refused...)
	if len(contexts) > maxPresenceContexts {
		slog.Warn("mcptool.FunctionAuthorization: more refused argument contexts than the cap; retrying the credential in only the first maxPresenceContexts, so a gate reachable only in a dropped context is not assessed. This is NOT a clean result for those contexts.",
			"tool", name, "contexts", len(contexts), "cap", maxPresenceContexts)
		contexts = contexts[:maxPresenceContexts]
	}

	var attempts []*attempt.Attempt
	// One sweep per CALL SIGNATURE. A tool whose parameters depend on a
	// discriminator exposes a different credential surface under each branch —
	// an optional token that exists only under action=admin was invisible to the
	// flat reader, and the branch it gates was never reached.
	for _, sig := range mcpprobe.ToolSignatures(tool) {
		for _, param := range sig.Params {
			if param.Required || !isStringParam(param.Type) {
				continue
			}
			if !credentialParamRE.MatchString(mcpprobe.SplitCamelCase(param.Path.Leaf())) {
				continue
			}
			for _, base := range contexts {
				if a := p.assessPresence(ctx, inv, name, sig, param.Path, base); a != nil {
					attempts = append(attempts, a)
				}
			}
		}
	}
	return attempts
}

func callLeg(ctx context.Context, inv types.ToolInvoker, tool string, args map[string]any) (types.ToolResult, error) {
	res, err := inv.CallTool(ctx, tool, args)
	if err == nil || ctx.Err() != nil {
		return res, err
	}
	return inv.CallTool(ctx, tool, args)
}

// assessPresence runs one omitted-versus-forged comparison in a given argument
// context.
// callLeg issues one leg of a differential, retrying once on error.
//
// Every verdict this probe reaches is a COMPARISON, so both legs must succeed for
// the comparison to exist. A single transient failure therefore does not merely
// lose one data point — it discards the whole finding.
//
// Measured: under a full ten-probe sweep against one server, six of this probe's
// calls errored where the same probe run alone had none (a concurrently-running
// injection probe was issuing 144 calls to the same target). One of the lost calls
// was the confirmed privileged context, so a genuine finding read as 0.0. Retrying
// once recovers it without weakening any judgement: a leg that fails twice still
// yields no comparison, and the attempt still surfaces as an error rather than as a
// clean result.
//
// Context cancellation is never retried — that is the operator stopping the scan,
// not the target faltering.
func (p *FunctionAuthorization) assessPresence(
	ctx context.Context, inv types.ToolInvoker, tool string,
	sig toolsig.Signature, param toolsig.Path, base argContext,
) *attempt.Attempt {
	// CONTROL: the credential argument absent entirely — an openly unauthenticated
	// caller in this same context.
	control := mcpprobe.BenignCall(sig)
	base.applyTo(control)
	control.Unset(param)
	controlRes, controlErr := callLeg(ctx, inv, tool, control.Args())
	controlText := ""
	if controlErr != nil {
		slog.Warn("mcptool.FunctionAuthorization: credential-absent control call failed; this context will be inconclusive rather than assumed safe",
			"tool", tool, "param", param, "error", controlErr)
	} else {
		controlText = controlRes.Text
	}

	forged, forgeErr := randHex(32)
	label := fmt.Sprintf("%s with a forged %s", tool, param)
	if len(base) > 0 {
		label += " (" + base.describe() + ")"
	}

	a := attempt.New(label)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[mcpprobe.MetaAuthClass] = mcpprobe.AuthClassCredentialPresence
	a.Metadata[mcpprobe.MetaAuthTool] = tool
	a.Metadata[mcpprobe.MetaAuthParam] = string(param)
	a.Metadata[mcpprobe.MetaAuthProbeValue] = forged
	a.Metadata[mcpprobe.MetaAuthControlValue] = ""
	a.Metadata[mcpprobe.MetaAuthControl] = controlText
	a.Metadata[mcpprobe.MetaAuthControlLabel] = "same call, same other arguments, with the credential argument omitted entirely"

	if forgeErr != nil {
		// The whole comparison is "omitted versus a value that was certainly never
		// issued". A degraded, predictable value could collide with a real
		// credential, which would make acceptance meaningless rather than damning.
		a.Metadata[attempt.MetadataKeyInconclusive] = true
		a.Metadata[attempt.MetadataKeyInconclusiveReason] = "could not generate a never-issued credential value: " + forgeErr.Error()
		slog.Warn("mcptool.FunctionAuthorization: could not generate the forged credential, so this parameter was NOT assessed; this is not a clean result",
			"tool", tool, "param", param, "error", forgeErr)
		a.SetError(forgeErr)
		return a
	}

	probe := mcpprobe.BenignCall(sig)
	probe.Set(param, forged)
	// The refused context is applied AFTER the forged credential, so a context
	// that pins the very parameter under test still wins — that was the flat
	// override map's ordering and it is what makes the context meaningful.
	base.applyTo(probe)
	res, err := callLeg(ctx, inv, tool, probe.Args())
	if err != nil {
		// The forged-credential leg is the finding's evidence; without it there is
		// nothing to compare against the omitted-credential control. Marked
		// inconclusive and loud, like the control-absent failure above, so a
		// transient error cannot read as 0.0/safe.
		a.Metadata[attempt.MetadataKeyInconclusive] = true
		a.Metadata[attempt.MetadataKeyInconclusiveReason] = "forged-credential call failed: " + err.Error()
		slog.Warn("mcptool.FunctionAuthorization: the forged-credential call failed, so this context was NOT assessed; this is not a clean result",
			"tool", tool, "param", param, "error", err)
		a.SetError(err)
		return a
	}
	a.AddOutput(res.Text)
	a.Complete()
	return a
}

// argContext is a set of argument values to impose on a call, addressed by PATH.
//
// The paths matter. These contexts travel: the discriminator sweep discovers a
// combination the target refused, and the credential check replays it on a
// different call. Carrying bare parameter NAMES meant a value belonging to a
// nested object was replayed beside that object instead of inside it, so the
// replayed call was not the refused one and the retry proved nothing.
type argContext map[toolsig.Path]any

// applyTo imposes the context on a call under construction.
func (c argContext) applyTo(call *toolsig.Call) {
	for path, v := range c {
		call.Set(path, v)
	}
}

// describe renders a context compactly and deterministically for an attempt
// label.
func (c argContext) describe() string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, c[toolsig.Path(k)]))
	}
	return strings.Join(parts, " ")
}

// probeDiscriminator exercises the target's DECLARED values for an
// authority-selecting parameter to establish an ordinary-authority baseline, then
// tries the conventional privileged names against it.
// It returns the attempts plus the argument contexts the target REFUSED, which the
// credential-presence check retries with a credential attached.
func (p *FunctionAuthorization) probeDiscriminator(ctx context.Context, inv types.ToolInvoker, tool map[string]any) ([]*attempt.Attempt, []argContext) {
	name, _ := tool["name"].(string)
	desc, _ := tool["description"].(string)

	var (
		attempts []*attempt.Attempt
		refused  []argContext
	)
	// One representative per DISTINCT refusal. A tool that answers every
	// unrecognised value with the same "not found" message yields one context, not
	// dozens of identical ones — which matters because an interesting refusal (an
	// authentication demand, say) would otherwise be crowded out of the finite
	// retry budget by a crowd of duplicates.
	//
	// The set is shared across signatures on purpose: two branches that refuse
	// identically are one refusal to retry, not one per branch.
	seenRefusal := map[string]bool{}

	// One sweep per CALL SIGNATURE. An authority-selecting parameter that exists
	// only under a particular branch was invisible to the flat reader, and a
	// discriminator is exactly the construct that produces such branches — so this
	// is where reading only top-level properties was blindest.
	for _, sig := range mcpprobe.ToolSignatures(tool) {
		for _, param := range sig.Params {
			if !isStringParam(param.Type) {
				continue
			}
			as, refusals := p.sweepParam(ctx, inv, name, desc, sig, param, seenRefusal)
			attempts = append(attempts, as...)
			refused = append(refused, refusals...)
		}
	}
	return attempts, refused
}

// sweepParam runs the privileged-value sweep for ONE parameter of ONE call
// signature, returning its attempts and the argument contexts the target refused.
//
// It is split out from probeDiscriminator because the sweep is now nested two
// deep — signature, then parameter — and the body is long enough that the
// indentation, not the logic, would become the thing a reader has to track.
func (p *FunctionAuthorization) sweepParam(
	ctx context.Context, inv types.ToolInvoker, name, desc string,
	sig toolsig.Signature, param toolsig.Param, seenRefusal map[string]bool,
) ([]*attempt.Attempt, []argContext) {
	var (
		attempts []*attempt.Attempt
		refused  []argContext
	)
	leaf := param.Path.Leaf()
	declared := mcpprobe.DeclaredValuesFor(param, desc)

	// The target MUST declare values for the parameter. Without them there is no
	// such thing as "ordinary authority" on this target, and the differential
	// degrades into something else entirely: the baseline becomes a synthesized
	// string the server has never heard of, so every real value differs from it
	// and the probe measures known-versus-unknown identifier rather than
	// unprivileged-versus-privileged authority.
	//
	// Measured: on a tool `get_user_info(username)` — no declared values, but a
	// name matching the old conventional-name pattern — `username=admin` returned that
	// account's profile while both controls returned nothing, and the check
	// scored 1.0. There IS something worth reporting there (an unauthenticated
	// caller enumerating privileged accounts), but it is information disclosure,
	// not function-level authorization: the tool is a lookup, not a privileged
	// operation. Generalised, the name-only path fires on any tool that takes an
	// identifier and returns information about it.
	//
	// A conventional-looking name is therefore necessary but not sufficient: it
	// selects WHICH parameter to sweep, never whether a sweep is meaningful.
	if len(declared) == 0 {
		slog.Info("mcptool.FunctionAuthorization: parameter declares no values, so the target defines no ordinary authority to compare against; skipping the privileged-value sweep rather than measuring known-vs-unknown identifiers",
			"tool", name, "param", string(param.Path))
		return nil, nil
	}
	// A payload parameter is not an authority selector. Sweeping it measures
	// "is this a valid command" rather than "may this caller do this".
	if contentParamRE.MatchString(mcpprobe.SplitCamelCase(leaf)) {
		slog.Info("mcptool.FunctionAuthorization: parameter carries a payload rather than selecting authority; skipping the privileged-value sweep (an execution sink is mcptool.Injection's finding, not an authorization bypass)",
			"tool", name, "param", string(param.Path))
		return nil, nil
	}
	if len(declared) > maxDeclaredValues {
		slog.Warn("mcptool.FunctionAuthorization: more declared authority values than the cap; the baseline uses only the first maxDeclaredValues, so this sweep is a lower bound. This is NOT a clean result for the dropped values.",
			"tool", name, "param", string(param.Path), "declared", len(declared), "cap", maxDeclaredValues)
		declared = declared[:maxDeclaredValues]
	}

	// BASELINE: what ordinary authority looks like on THIS target, taken from a
	// value the target itself documents. Without one there is nothing to call a
	// differential against, so the parameter is skipped rather than guessed at.
	baselineValue, baselineText, ok := p.baseline(ctx, inv, name, sig, param.Path, declared)
	if !ok {
		slog.Info("mcptool.FunctionAuthorization: no usable baseline for an authority parameter; skipping it rather than reporting against a guess",
			"tool", name, "param", string(param.Path), "declared_values", len(declared))
		return nil, nil
	}

	// SECOND unprivileged control: an arbitrary value that is, by
	// construction, not a privileged name. Without it a single differing
	// response is ambiguous — it could be the privilege, or the target's
	// answers could simply vary with whatever string it is given. Two
	// unprivileged controls that agree, with the probe differing from both,
	// isolates the privilege as the cause.
	randomControl, randErr := randHex(12)
	if randErr != nil {
		slog.Warn("mcptool.FunctionAuthorization: could not generate the second unprivileged control, so privilege cannot be isolated from response variation; skipping this parameter rather than reporting it",
			"tool", name, "param", string(param.Path), "error", randErr)
		return nil, nil
	}
	control2Value, control2Text, _ := p.baseline(ctx, inv, name, sig, param.Path, []string{"aug" + randomControl})

	// Candidates: the conventional privileged names, plus any value the TARGET
	// disclosed in its own responses. Servers routinely refuse an unrecognised
	// value with a message enumerating the accepted ones, and that list is
	// target-derived data — the most productive source there is, and the reason
	// this check can reach a privileged value that appears nowhere in the
	// advertised catalogue without the probe carrying any knowledge of it.
	// Target-disclosed values come FIRST: they are evidence from this target,
	// whereas the conventional names are informed guesses. Ordering matters
	// because the refused-context budget downstream is finite.
	var candidates []string
	disclosed := p.disclosedValues(baselineText, control2Text, baselineValue, control2Value, declared)
	if len(disclosed) > 0 {
		slog.Info("mcptool.FunctionAuthorization: target disclosed additional accepted values in its own response; adding them as candidates",
			"tool", name, "param", string(param.Path), "disclosed", strings.Join(disclosed, ","))
		candidates = append(candidates, disclosed...)
	}
	candidates = append(candidates, mcpprobe.ConventionalPrivilegedNames()...)

	for _, candidate := range candidates {
		// A conventional name the target already declares is ordinary
		// authority here, not an escalation.
		if containsFold(declared, candidate) {
			continue
		}
		a := attempt.New(fmt.Sprintf("%s with %s=%s", name, param.Path, candidate))
		a.Probe = p.Name()
		a.Detector = p.GetPrimaryDetector()
		a.Metadata[mcpprobe.MetaAuthClass] = mcpprobe.AuthClassPrivilegeDiscriminator
		a.Metadata[mcpprobe.MetaAuthTool] = name
		a.Metadata[mcpprobe.MetaAuthParam] = string(param.Path)
		a.Metadata[mcpprobe.MetaAuthProbeValue] = candidate
		a.Metadata[mcpprobe.MetaAuthControlValue] = baselineValue
		a.Metadata[mcpprobe.MetaAuthControl] = baselineText
		a.Metadata[mcpprobe.MetaAuthControlLabel] = fmt.Sprintf("same call with the target-declared value %q", baselineValue)
		if control2Text != "" {
			a.Metadata[mcpprobe.MetaAuthControl2Value] = control2Value
			a.Metadata[mcpprobe.MetaAuthControl2Response] = control2Text
		}
		if len(declared) > 0 {
			a.Metadata[mcpprobe.MetaAuthDeclaredValues] = strings.Join(declared, ",")
		}

		args := mcpprobe.BenignArgs(sig, argContext{param.Path: candidate})
		res, err := callLeg(ctx, inv, name, args)
		if err != nil {
			// A candidate that would have revealed an escalation but errored must
			// not read as 0.0/safe: mark it inconclusive and loud, like the other
			// failed legs, so a transient error surfaces for a reviewer.
			a.Metadata[attempt.MetadataKeyInconclusive] = true
			a.Metadata[attempt.MetadataKeyInconclusiveReason] = "privilege-discriminator call failed: " + err.Error()
			slog.Warn("mcptool.FunctionAuthorization: a privilege-discriminator candidate call failed, so that candidate was NOT assessed; this is not a clean result",
				"tool", name, "param", string(param.Path), "candidate", candidate, "error", err)
			a.SetError(err)
		} else {
			a.AddOutput(res.Text)
			a.Complete()
			// A refused value is the most informative context to retry with a
			// credential: the refusal may BE the authorization gate, and whether
			// it actually validates anything is precisely the next question.
			if mcpprobe.ReadsAsRefusal(res.Text) {
				class := mcpprobe.ResponseClass(res.Text, candidate)
				if !seenRefusal[class] {
					seenRefusal[class] = true
					refused = append(refused, argContext{param.Path: candidate})
				}
			}
		}
		attempts = append(attempts, a)
	}
	return attempts, refused
}

// disclosedValues harvests candidate values the target volunteered in its own
// control responses, dropping the values already declared or already submitted.
//
// Values the target DECLARES are excluded because they are the ordinary-authority
// baseline, not an escalation: re-testing them would compare a declared value
// against another declared value and report nothing useful.
func (p *FunctionAuthorization) disclosedValues(baselineText, control2Text, baselineValue, control2Value string, declared []string) []string {
	submitted := append([]string{baselineValue, control2Value}, declared...)
	var out []string
	seen := map[string]bool{}
	for _, text := range []string{baselineText, control2Text} {
		for _, v := range mcpprobe.ValuesFromResponse(text, submitted) {
			key := strings.ToLower(v)
			if seen[key] || containsFold(declared, v) {
				continue
			}
			seen[key] = true
			out = append(out, v)
		}
	}
	return out
}

// baseline calls the tool with each supplied unprivileged value in turn and returns
// the first that produced a non-empty response, together with that response.
//
// Callers supply either the values the TARGET declares or a single random value; a
// random string is unprivileged by construction, which is what makes it usable as
// the second control. There is deliberately no fallback for an empty list:
// probeDiscriminator skips a parameter that declares no values, because a
// synthesized string the server has never seen cannot establish what ordinary
// authority looks like — that was a measured false positive, and a fallback here
// would quietly reintroduce it.
func (p *FunctionAuthorization) baseline(
	ctx context.Context, inv types.ToolInvoker, tool string,
	sig toolsig.Signature, param toolsig.Path, declared []string,
) (string, string, bool) {
	for _, value := range declared {
		args := mcpprobe.BenignArgs(sig, argContext{param: value})
		res, err := callLeg(ctx, inv, tool, args)
		if err != nil {
			continue
		}
		if strings.TrimSpace(res.Text) == "" {
			continue
		}
		return value, res.Text, true
	}
	return "", "", false
}

// containsFold reports case-insensitive membership.
func containsFold(values []string, want string) bool {
	for _, v := range values {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}
