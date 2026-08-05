package mcptool

import (
	"context"
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

// discriminatorParamRE matches parameter names that conventionally SELECT an
// authority level, identity, or target — the argument a server is most likely to
// branch on when deciding what a caller may do.
var discriminatorParamRE = regexp.MustCompile(
	`(?i)(^|[_\- ])(role|roles|user|username|account|identity|actor|as_user|level|permission|permissions|privilege|scope|scopes|group|groups|mode|profile|system|target|env|environment|tenant|realm|domain|namespace|type|kind|category|action|operation|command)($|[_\- ])`)

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
// server-annotated-destructive gate). Against production infrastructure, scope it
// with tool_allowlist.
type FunctionAuthorization struct {
	reconContext
	policy toolpolicy.Policy
	// allTools widens the sweep from conventionally-privileged tool names to every
	// tool the policy permits.
	allTools bool
}

// NewFunctionAuthorization constructs the probe.
func NewFunctionAuthorization(cfg registry.Config) (probes.Prober, error) {
	return &FunctionAuthorization{
		policy:   toolpolicy.New(cfg),
		allTools: registry.GetBool(cfg, "authz_all_tools", false),
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
		attempts = append(attempts, p.probeCredentialPresence(ctx, inv, tool)...)
		attempts = append(attempts, p.probeDiscriminator(ctx, inv, tool)...)
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
	if p.allTools {
		return tools
	}
	out := make([]map[string]any, 0, len(tools))
	for _, tm := range tools {
		if name, _ := tm["name"].(string); name != "" && privilegedToolNameRE.MatchString(name) {
			out = append(out, tm)
		}
	}
	return out
}

// probeCredentialPresence compares an OMITTED optional credential argument against
// the same call carrying a random, certainly-invalid value.
//
// Only OPTIONAL credential parameters qualify: a required one cannot be omitted,
// so there would be no control to compare against.
func (p *FunctionAuthorization) probeCredentialPresence(ctx context.Context, inv types.ToolInvoker, tool map[string]any) []*attempt.Attempt {
	name, _ := tool["name"].(string)
	params := mcpprobe.ToolParams(tool)

	var attempts []*attempt.Attempt
	for _, param := range params {
		if param.Required || !isStringParam(param.Type) {
			continue
		}
		if !credentialParamRE.MatchString(param.Name) {
			continue
		}

		// CONTROL: the credential argument absent entirely — an openly
		// unauthenticated caller.
		controlArgs := mcpprobe.BenignArgs(params, nil)
		delete(controlArgs, param.Name)
		controlRes, controlErr := inv.CallTool(ctx, name, controlArgs)
		controlText := ""
		if controlErr != nil {
			slog.Warn("mcptool.FunctionAuthorization: credential-absent control call failed; this parameter will be inconclusive rather than assumed safe",
				"tool", name, "param", param.Name, "error", controlErr)
		} else {
			controlText = controlRes.Text
		}

		forged := randHex(32)
		a := attempt.New(fmt.Sprintf("%s with a forged %s", name, param.Name))
		a.Probe = p.Name()
		a.Detector = p.GetPrimaryDetector()
		a.Metadata[mcpprobe.MetaAuthClass] = mcpprobe.AuthClassCredentialPresence
		a.Metadata[mcpprobe.MetaAuthTool] = name
		a.Metadata[mcpprobe.MetaAuthParam] = param.Name
		a.Metadata[mcpprobe.MetaAuthProbeValue] = forged
		a.Metadata[mcpprobe.MetaAuthControlValue] = ""
		a.Metadata[mcpprobe.MetaAuthControl] = controlText
		a.Metadata[mcpprobe.MetaAuthControlLabel] = "same call with the credential argument omitted entirely"

		probeArgs := mcpprobe.BenignArgs(params, map[string]any{param.Name: forged})
		res, err := inv.CallTool(ctx, name, probeArgs)
		if err != nil {
			a.SetError(err)
		} else {
			a.AddOutput(res.Text)
			a.Complete()
		}
		attempts = append(attempts, a)
	}
	return attempts
}

// probeDiscriminator exercises the target's DECLARED values for an
// authority-selecting parameter to establish an ordinary-authority baseline, then
// tries the conventional privileged names against it.
func (p *FunctionAuthorization) probeDiscriminator(ctx context.Context, inv types.ToolInvoker, tool map[string]any) []*attempt.Attempt {
	name, _ := tool["name"].(string)
	params := mcpprobe.ToolParams(tool)

	var attempts []*attempt.Attempt
	for _, param := range params {
		if !isStringParam(param.Type) {
			continue
		}
		declared := mcpprobe.DeclaredValues(tool, param.Name)
		// A parameter qualifies when the target declares values for it (so a
		// baseline exists) or its name conventionally selects authority.
		if len(declared) == 0 && !discriminatorParamRE.MatchString(param.Name) {
			continue
		}
		if len(declared) > maxDeclaredValues {
			declared = declared[:maxDeclaredValues]
		}

		// BASELINE: what ordinary authority looks like on THIS target, taken from a
		// value the target itself documents. Without one there is nothing to call a
		// differential against, so the parameter is skipped rather than guessed at.
		baselineValue, baselineText, ok := p.baseline(ctx, inv, name, params, param.Name, declared)
		if !ok {
			slog.Info("mcptool.FunctionAuthorization: no usable baseline for an authority parameter; skipping it rather than reporting against a guess",
				"tool", name, "param", param.Name, "declared_values", len(declared))
			continue
		}

		// SECOND unprivileged control: an arbitrary value that is, by
		// construction, not a privileged name. Without it a single differing
		// response is ambiguous — it could be the privilege, or the target's
		// answers could simply vary with whatever string it is given. Two
		// unprivileged controls that agree, with the probe differing from both,
		// isolates the privilege as the cause.
		control2Value, control2Text, _ := p.baseline(ctx, inv, name, params, param.Name, []string{"aug" + randHex(12)})

		for _, candidate := range mcpprobe.ConventionalPrivilegedNames() {
			// A conventional name the target already declares is ordinary
			// authority here, not an escalation.
			if containsFold(declared, candidate) {
				continue
			}
			a := attempt.New(fmt.Sprintf("%s with %s=%s", name, param.Name, candidate))
			a.Probe = p.Name()
			a.Detector = p.GetPrimaryDetector()
			a.Metadata[mcpprobe.MetaAuthClass] = mcpprobe.AuthClassPrivilegeDiscriminator
			a.Metadata[mcpprobe.MetaAuthTool] = name
			a.Metadata[mcpprobe.MetaAuthParam] = param.Name
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

			args := mcpprobe.BenignArgs(params, map[string]any{param.Name: candidate})
			res, err := inv.CallTool(ctx, name, args)
			if err != nil {
				a.SetError(err)
			} else {
				a.AddOutput(res.Text)
				a.Complete()
			}
			attempts = append(attempts, a)
		}
	}
	return attempts
}

// baseline calls the tool with a target-declared value (or, when the target
// declares none, a random value that is certainly not a privileged name) and
// returns that value with its response.
//
// The random fallback is what lets the check work on a parameter the target
// documents nothing for: an arbitrary string is by construction unprivileged, so
// it establishes the "ordinary caller" response just as a declared value would.
func (p *FunctionAuthorization) baseline(
	ctx context.Context, inv types.ToolInvoker, tool string,
	params []mcpprobe.ToolParam, param string, declared []string,
) (string, string, bool) {
	candidates := declared
	if len(candidates) == 0 {
		candidates = []string{"aug" + randHex(12)}
	}
	for _, value := range candidates {
		args := mcpprobe.BenignArgs(params, map[string]any{param: value})
		res, err := inv.CallTool(ctx, tool, args)
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
