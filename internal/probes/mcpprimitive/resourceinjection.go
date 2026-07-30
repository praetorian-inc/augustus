package mcpprimitive

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("mcpprimitive.ResourceInjection", NewResourceInjection)
}

var (
	_ types.ProbeMetadata           = (*ResourceInjection)(nil)
	_ types.ProbeSecondaryDetectors = (*ResourceInjection)(nil)
	_ types.RiskDescriber           = (*ResourceInjection)(nil)
	_ recon.ContextAwareProbe       = (*ResourceInjection)(nil)
)

// resourcePayload is one resources/read request to issue. token is non-empty for
// out-of-band payloads, tying the attempt to a collector callback.
type resourcePayload struct {
	uriPayload
	token string
}

// ResourceInjection attacks the URI parameter of resources/read. The URI is fully
// caller-controlled, which makes it two sinks at once:
//
//   - A filesystem sink. Servers commonly map a resource URI onto a path under a
//     base directory. Traversal payloads escape it; success is proven by a
//     well-known file-content signature in the returned body, which a server that
//     merely echoes the URI cannot forge.
//   - A network sink. A server that resolves arbitrary URI schemes turns
//     resources/read into server-side request forgery. Success is proven by an
//     out-of-band callback (blind) or by the collector's body marker coming back
//     in the resource content (non-blind).
//
// Payloads come from three sources: a baseline set sent to every target, traversal
// variants derived from each advertised resource URI (defeating a server that
// validates a directory prefix but then joins the remainder), and expansions of
// each advertised resource TEMPLATE, whose parameter is interpolated straight into
// the sink.
//
// Each advertised resource is additionally read AS-IS — the server's intended use,
// not an attack — so the secondary content detector can score the bodies the server
// genuinely serves for smuggled model-directed instructions. Every other payload
// requests a URI of the probe's own choosing, so without this pass a poisoned
// advertised resource would never be looked at.
//
// The baseline set is sent even when the catalog is empty, deliberately: recon
// gates enumeration on the server's declared capabilities and treats a failed list
// call as an empty one, so "no resources advertised" is not evidence that
// resources/read is unreachable.
type ResourceInjection struct {
	reconContext
	listen       string        // OOB collector bind address
	baseOverride string        // URL the target should use to reach the collector
	wait         time.Duration // grace period for callbacks after sending
	marker       string        // collector body marker (reflection signal)
	maxTargets   int           // cap on advertised resources/templates derived from
}

// NewResourceInjection constructs the probe. Every setting defaults so a
// localhost target works with zero config.
func NewResourceInjection(cfg registry.Config) (probes.Prober, error) {
	return &ResourceInjection{
		listen:       registry.GetString(cfg, "oob_listen", "127.0.0.1:0"),
		baseOverride: registry.GetString(cfg, "oob_base_url", ""),
		wait:         time.Duration(registry.GetInt(cfg, "oob_wait_seconds", 3)) * time.Second,
		marker:       "AUGOOB" + mcpprobe.RandToken(),
		maxTargets:   registry.GetInt(cfg, "resource_max_targets", 25),
	}, nil
}

func (p *ResourceInjection) Name() string { return "mcpprimitive.ResourceInjection" }

func (p *ResourceInjection) Description() string {
	return "Attacks the resources/read URI parameter with filesystem-traversal payloads (detected by file-content signatures) and out-of-band canary URLs (detected by callback or reflection), deriving variants from advertised resource URIs and templates"
}

func (p *ResourceInjection) Goal() string {
	return "Determine whether an MCP server's resources/read call exposes an unrestricted filesystem read sink (arbitrary file read via URI traversal) or an unrestricted network sink (server-side request forgery via URI scheme abuse)"
}

func (p *ResourceInjection) GetPrimaryDetector() string { return "mcpprimitive.Injection" }

// GetSecondaryDetectors scores the CONTENT the server returned for smuggled
// model-directed instructions, so a poisoned resource body is reported alongside
// the sink verdict (OWASP MCP10).
func (p *ResourceInjection) GetSecondaryDetectors() []types.SecondaryDetector {
	return []types.SecondaryDetector{{Name: "mcpprimitive.ContentInjection"}}
}

// GetPrompts returns the stable baseline URIs. Per-run canary URLs and
// catalog-derived variants are omitted: they carry run-specific values.
func (p *ResourceInjection) GetPrompts() []string {
	base := baselineURIPayloads()
	out := make([]string, len(base))
	for i, b := range base {
		out[i] = b.uri
	}
	return out
}

// RiskInfo is the curated security write-up for this probe's finding.
func (p *ResourceInjection) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description:    "An MCP server resolves the caller-supplied URI of a resources/read request without confining it, so the request reaches an unintended destination — a file outside the server's intended directory, or an arbitrary network host.",
		Impact:         "A caller who can read resources obtains files the server process can access beyond the intended scope, which commonly includes configuration and credential material. Where the URI is resolved as a network location, the caller also directs outbound requests from the server, reaching internal services and cloud metadata endpoints that are otherwise unreachable.",
		Recommendation: "Resolve resource URIs against a fixed allowlist rather than interpreting caller input: match the URI to a known catalog entry, or canonicalize the derived path (absolute, symlinks resolved) and reject anything outside an allowlisted base directory. Restrict permitted URI schemes to those the server genuinely serves, refuse file and network schemes it does not, and apply the same validation to resource-template parameters, which are interpolated into the same sink. Run the server with least privilege.",
		References:     "https://cwe.mitre.org/data/definitions/22.html\nhttps://cwe.mitre.org/data/definitions/918.html\nhttps://cwe.mitre.org/data/definitions/73.html\nhttps://modelcontextprotocol.io/specification/2025-06-18/server/resources",
		Taxonomies:     "- cwe: 22\n- cwe: 23\n- cwe: 73\n- cwe: 918",
		CVSSVector:     "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
		Verification: "## How this is confirmed\n\n" +
			"Augustus requests resources the server never advertised, using URIs built to escape the intended scope. Two independent oracles confirm the sink, and neither can be satisfied by a server that simply echoes the requested URI back:\n\n" +
			"- Filesystem: the returned content carries the content signature of a well-known system file. Only a real read of that file produces the signature, so a match proves the URI resolved outside the intended directory.\n" +
			"- Network: a canary URI triggers a callback to the augustus out-of-band host, proving the server issued the request. The callback covers the blind case, where the server fetches the URI but returns nothing; the non-blind case additionally reflects the canary body in the resource content.\n\n" +
			"Payloads are also derived from the advertised catalog: traversal appended to a real resource URI defeats a server that validates only the leading directory, and a resource template's parameter is interpolated directly into the sink. A server that refuses the request returns a protocol error, which is recorded as the denial signal rather than treated as a finding.\n\n" +
			"## Reproduce\n\n" +
			"Re-run the `mcpprimitive.ResourceInjection` probe against the affected endpoint via the `mcp.MCP` generator. A filesystem finding is confirmed by the out-of-scope file content in the response; a blind network finding is confirmed by the recorded out-of-band callback rather than by the response body, so confirm against the recorded proof and not the response text alone. Blind detection requires out-of-band infrastructure the target can reach.",
	}
}

// Probe issues every derived resources/read request and records one attempt each.
// A target that cannot read primitives is a hard error rather than a clean empty
// result, so an unsupported target never reads as "no injection sinks".
func (p *ResourceInjection) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	reader, ok := gen.(types.MCPPrimitiveReader)
	if !ok {
		return nil, fmt.Errorf("mcpprimitive.ResourceInjection: target %q cannot read MCP primitives; this probe requires a primitive-reading generator such as mcp.MCP", gen.Name())
	}

	// The catalog only ENRICHES the payload set; its absence is not fatal.
	invs, err := p.resolveInventories(ctx, gen)
	if err != nil {
		slog.Warn("mcpprimitive.ResourceInjection: catalog unavailable, sending baseline payloads only",
			"probe", p.Name(), "error", err)
	}

	col, err := mcpprobe.StartCollector(p.listen, p.baseOverride, p.marker)
	if err != nil {
		return nil, fmt.Errorf("mcpprimitive.ResourceInjection: start OOB collector: %w", err)
	}
	defer col.Close()

	payloads := p.buildPayloads(invs, col)

	var (
		attempts []*attempt.Attempt
		pend     []*attempt.Attempt
	)
	tokenOf := make(map[*attempt.Attempt]string, len(payloads))

	for _, rp := range payloads {
		// Stop issuing new reads the moment the context is done; attempts already
		// sent are still recorded and their callbacks reconciled below.
		if ctx.Err() != nil {
			break
		}
		a := p.readOne(ctx, reader, rp)
		attempts = append(attempts, a)
		if rp.token != "" {
			pend = append(pend, a)
			tokenOf[a] = rp.token
		}
	}

	if len(pend) > 0 {
		mcpprobe.WaitForCallbacks(ctx, p.wait)
		for _, a := range pend {
			a.Metadata[attempt.MetadataKeyPrimitiveOOBCallback] = col.WasHit(tokenOf[a])
		}
	}
	return attempts, nil
}

// buildPayloads assembles the request set: the always-sent baseline, traversal
// variants derived from advertised resource URIs, out-of-band canary URIs, and
// expansions of advertised resource templates (traversal and canary alike, since
// a template parameter may land in either sink). Results are deduplicated by URI
// so an overlapping catalog doesn't multiply identical requests.
func (p *ResourceInjection) buildPayloads(invs []*types.MCPInventory, col *mcpprobe.Collector) []resourcePayload {
	var out []resourcePayload
	seen := make(map[string]bool)

	add := func(rp resourcePayload) {
		if rp.uri == "" || seen[rp.uri] {
			return
		}
		seen[rp.uri] = true
		out = append(out, rp)
	}

	for _, b := range baselineURIPayloads() {
		add(resourcePayload{uriPayload: b})
	}

	// Bare out-of-band canary URIs: does the server fetch what it is handed?
	for _, scheme := range []string{"http", "https"} {
		token := mcpprobe.RandToken()
		canary := col.URL(token)
		if scheme == "https" {
			canary = strings.Replace(canary, "http://", "https://", 1)
		}
		add(resourcePayload{
			uriPayload: uriPayload{uri: canary, class: classSSRF},
			token:      token,
		})
	}

	targets := 0
	for _, inv := range invs {
		if inv == nil {
			continue
		}
		for _, res := range inv.Resources {
			if targets >= p.maxTargets {
				break
			}
			if res.URI == "" {
				continue
			}
			targets++
			// Read the advertised resource AS-IS. This is not an attack — it is the
			// server's intended use — but it is the only way the secondary content
			// detector ever sees what the server actually serves. Without it a server
			// whose advertised resource bodies carry hidden model-directed
			// instructions would go unreported, since every other payload here
			// requests a URI of our own choosing. Carries no signatures, so the
			// primary sink detector cannot fire on it.
			add(resourcePayload{uriPayload: uriPayload{uri: res.URI, class: classResourceContent}})
			for _, tp := range traversalFrom(res.URI) {
				add(resourcePayload{uriPayload: tp})
			}
		}
		for _, tpl := range inv.ResourceTemplates {
			if targets >= p.maxTargets {
				break
			}
			if tpl.URITemplate == "" {
				continue
			}
			targets++
			// Traversal through the template parameter.
			if uri := expandTemplate(tpl.URITemplate, "../../../../../../etc/passwd"); uri != "" {
				add(resourcePayload{uriPayload: uriPayload{
					uri: uri, signatures: passwdSignatures, class: classTemplateArg,
				}})
			}
			// Canary URL through the template parameter.
			token := mcpprobe.RandToken()
			if uri := expandTemplate(tpl.URITemplate, col.URL(token)); uri != "" {
				add(resourcePayload{
					uriPayload: uriPayload{uri: uri, class: classTemplateArg},
					token:      token,
				})
			}
		}
	}
	if targets >= p.maxTargets {
		slog.Warn("mcpprimitive.ResourceInjection: advertised-resource cap reached; later catalog entries were not derived from",
			"probe", p.Name(), "cap", p.maxTargets)
	}
	return out
}

// readOne issues one resources/read and records the attempt. A protocol error is
// the server's denial signal, not a probe failure: it is preserved in metadata and
// the attempt is completed so a refusal stays visible in the report instead of
// being classified as an error and dropped from the verdict.
func (p *ResourceInjection) readOne(ctx context.Context, reader types.MCPPrimitiveReader, rp resourcePayload) *attempt.Attempt {
	a := attempt.New(rp.uri)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeyPrimitiveTarget] = rp.uri
	a.Metadata[attempt.MetadataKeyPrimitiveClass] = rp.class
	if len(rp.signatures) > 0 {
		a.Metadata[attempt.MetadataKeyPrimitiveSignatures] = rp.signatures
	}
	if rp.token != "" {
		a.Metadata[attempt.MetadataKeyPrimitiveOOBURL] = rp.uri
	}

	res, err := reader.ReadResource(ctx, rp.uri)
	if err != nil {
		// Refused (unknown URI, denied path, unsupported scheme) — the expected,
		// healthy outcome. Recorded as a completed non-finding with the reason.
		a.Metadata[attempt.MetadataKeyPrimitiveCallError] = err.Error()
		a.AddOutput("")
		a.Complete()
		return a
	}
	a.Metadata[attempt.MetadataKeyPrimitiveReflected] = p.marker != "" && strings.Contains(res.Text, p.marker)
	if res.MIMEType != "" {
		a.Metadata["mcpprimitive.mime_type"] = res.MIMEType
	}
	a.AddOutput(res.Text)
	a.Complete()
	return a
}
