package mcpprimitive

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("mcpprimitive.ContentLeak", NewContentLeak)
}

var (
	_ types.ProbeMetadata     = (*ContentLeak)(nil)
	_ types.RiskDescriber     = (*ContentLeak)(nil)
	_ recon.ContextAwareProbe = (*ContentLeak)(nil)
)

// ContentLeak tests every content-bearing NON-TOOL MCP surface for credential
// exposure (OWASP MCP01). It is the mcptool.ResponseLeak of the primitive
// surfaces: same shape, same mcpsecrets.Credential primary detector, one surface
// over. Where ResponseLeak invokes tools and scores their responses, this probe
// reads the surfaces a client reaches WITHOUT calling a tool:
//
//  1. Advertised resources — resources/read on each catalogued URI.
//  2. Resource templates — a benign value substituted into the template, then read.
//  3. Prompt templates — prompts/get with benign arguments.
//  4. Server instructions — the initialize response's instructions field, which
//     reconnaissance already captures and nothing scored.
//  5. (excluded) Catalog descriptions and titles. See declaredAttempts for why:
//     a docstring "name: description" line is indistinguishable from a leaked
//     "key: value" pair to the credential detector.
//
// Nothing here is an attack. Every request is the server's own advertised URI,
// name or template with an innocuous value; no traversal, no canary, no payload.
// That is the point: a server that hands production credentials to any client
// that politely asks is exposed without an exploit, and the remediation
// (authenticate and remove the secret) is unrelated to the URI-handling flaws
// mcpprimitive.ResourceInjection reports. The two probes therefore stay separate
// findings over one surface, exactly as mcptool.Injection and
// mcptool.ResponseLeak do over the tool surface.
//
// Any credential appearing on these surfaces is reported, by design — as with
// ResponseLeak, a resource whose legitimate purpose is to vend a secret is still
// a secret readable by whoever can reach the server, which is the exposure this
// probe exists to surface.
//
// SIDE EFFECTS: this probe issues REAL resources/read and prompts/get calls.
// Both are read-oriented by design, and the arguments carry no payloads, so it is
// the least invasive probe in this package. A server whose "read" handler has
// side effects will still execute them.
type ContentLeak struct {
	reconContext
	// maxTargets caps how many entries each surface group contributes: resource
	// reads (concrete plus template expansions), prompt renders, and catalog
	// metadata entries are budgeted separately so a large tool catalog cannot
	// starve the resource reads.
	maxTargets int
}

// NewContentLeak constructs the probe. Every setting defaults, so the probe works
// against any MCP target with no configuration.
func NewContentLeak(cfg registry.Config) (probes.Prober, error) {
	return &ContentLeak{maxTargets: registry.GetInt(cfg, "content_max_targets", 25)}, nil
}

func (p *ContentLeak) Name() string { return "mcpprimitive.ContentLeak" }

func (p *ContentLeak) Description() string {
	return "Reads every content-bearing non-tool MCP surface the way a legitimate client would — advertised resources, resource templates, prompt templates and the server instructions — and scores what comes back for exposed credentials"
}

func (p *ContentLeak) Goal() string {
	return "Determine whether an MCP server exposes credentials or secrets on any non-tool surface a client can read without an exploit (OWASP MCP01)"
}

func (p *ContentLeak) GetPrimaryDetector() string { return "mcpsecrets.Credential" }

// GetPrompts returns nil: this probe sends no fixed payloads. Every request is
// derived from the target's own catalog.
func (p *ContentLeak) GetPrompts() []string { return nil }

// RiskInfo is the curated security write-up for this probe's finding.
func (p *ContentLeak) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description:    "An MCP server exposes credentials on a surface any connected client can read without an exploit: the content of an advertised resource or resource template, a rendered prompt template, or the instructions returned during initialization.",
		Impact:         "Any client that can reach the server collects the exposed API keys, passwords, tokens or connection strings and reuses them directly against the systems those credentials protect, reaching data and services well beyond the MCP server itself. No protocol abuse is required, so the exposure leaves none of the traces an attack would, and every client and host model that has read the surface has already received the secret.",
		Recommendation: "Remove secrets from everything the server serves or declares: do not publish credential material as a resource, and redact credential-shaped values from resource content, rendered prompts and server instructions. Where a client genuinely needs a secret, require authentication and authorization on the read and return a scoped, short-lived credential rather than a durable one. Treat any credential that was reachable this way as compromised and rotate it.",
		References:     "https://cwe.mitre.org/data/definitions/200.html\nhttps://cwe.mitre.org/data/definitions/522.html\nhttps://cwe.mitre.org/data/definitions/312.html\nhttps://modelcontextprotocol.io/specification/2025-06-18/server/resources\nhttps://owasp.org/www-project-top-10-for-large-language-model-applications/",
		Taxonomies:     "- cwe: 200\n- cwe: 522\n- cwe: 312\n- cwe: 532",
		CVSSVector:     "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N",
		Verification: "## How this is confirmed\n\n" +
			"Augustus reads each non-tool surface exactly as a legitimate client would and scores the returned content for credential patterns. Every request uses the server's own advertised URI, prompt name or template with an innocuous substituted value: there is no traversal, no canary and no injected payload, so a finding here shows the secret was served on request rather than extracted by abuse. The surfaces covered are advertised resources, resource templates, prompt templates rendered with benign arguments, and the instructions returned during initialization. Catalog descriptions and titles are deliberately excluded: a docstring parameter line such as `password: The password for authentication` is shaped identically to a leaked `key: value` pair, so scoring them would false-positive on most real servers.\n\n" +
			"Credential patterns are matched by the same detector used for MCP configuration files and tool responses, which rejects placeholders, endpoint URLs and pointer values such as a path to a key file, so a documentation example is not reported as a secret. A server that refuses a read returns a protocol error, recorded as the denial signal rather than as a finding.\n\n" +
			"## Reproduce\n\n" +
			"Re-run the `mcpprimitive.ContentLeak` probe against the affected endpoint via the `mcp.MCP` generator, with the `recon.MCP` reconnaissance module supplying the catalog. The flagged attempt records which surface was read, and its stored response contains the exposed credential. Treat the credential as compromised and rotate it before remediating.",
	}
}

// Probe reads every advertised non-tool surface and records one attempt each.
//
// The catalog is the ONLY source of these surfaces — unlike a resource URI, a
// prompt name or a server's instructions cannot be guessed — so a failed
// enumeration is fatal rather than a quietly narrowed scan. A target that
// genuinely advertises nothing produces an explicit warning and NO attempts, so an
// unexercised surface can never be reported as a clean pass.
func (p *ContentLeak) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	reader, ok := gen.(types.MCPPrimitiveReader)
	if !ok {
		return nil, fmt.Errorf("mcpprimitive.ContentLeak: target %q cannot read MCP primitives; this probe requires a primitive-reading generator such as mcp.MCP", gen.Name())
	}

	invs, err := p.resolveInventories(ctx, gen)
	if err != nil {
		return nil, fmt.Errorf("mcpprimitive.ContentLeak: enumerate non-tool catalog: %w", err)
	}
	p.warnIncomplete(invs)

	var attempts []*attempt.Attempt
	attempts = append(attempts, p.declaredAttempts(invs)...)
	attempts = append(attempts, p.readResources(ctx, reader, invs)...)
	attempts = append(attempts, p.renderPrompts(ctx, reader, invs)...)

	if len(attempts) == 0 {
		slog.Warn("mcpprimitive.ContentLeak: target advertises no resources, resource templates or prompt templates and returned no instructions; nothing to read",
			"probe", p.Name())
		return nil, nil
	}
	return attempts, nil
}

// warnIncomplete reports a catalog whose enumeration stopped early. Such an
// inventory is a LOWER BOUND on the target's surface, so the surfaces this probe
// scored are a prefix of what exists — a hostile server can halt enumeration after
// a secret-free prefix. Recorded loudly rather than acted on: the alternative
// (refusing to score anything) would discard the surfaces that WERE enumerated,
// and this probe reports secrets it finds rather than certifying their absence.
func (p *ContentLeak) warnIncomplete(invs []*types.MCPInventory) {
	for _, inv := range invs {
		if inv != nil && !inv.IsComplete() {
			slog.Warn("mcpprimitive.ContentLeak: catalog enumeration was incomplete; the surfaces read are a lower bound on the target's",
				"probe", p.Name(), "incomplete_catalogs", inv.Incomplete)
		}
	}
}

// benignTemplateValue is substituted into a resource template so the expansion is
// a request a legitimate client could make. It is deliberately inert: this probe
// scores what a server serves normally, so a payload here would both change the
// finding's meaning and risk being rejected before the read happens.
const benignTemplateValue = "readme"

// readResources reads each advertised resource URI as-is and each resource
// template expanded with a benign value, deduplicating URIs across inventories.
func (p *ContentLeak) readResources(ctx context.Context, reader types.MCPPrimitiveReader, invs []*types.MCPInventory) []*attempt.Attempt {
	var attempts []*attempt.Attempt
	seen := make(map[string]bool)
	truncated := false

	read := func(uri, class string) bool {
		if uri == "" || seen[uri] {
			return true
		}
		if len(seen) >= p.maxTargets {
			truncated = true
			return false
		}
		seen[uri] = true
		attempts = append(attempts, p.readOne(ctx, reader, uri, class))
		return true
	}

	for _, inv := range invs {
		if inv == nil {
			continue
		}
		for _, res := range inv.Resources {
			if ctx.Err() != nil {
				return attempts
			}
			if !read(res.URI, classResourceContent) {
				break
			}
		}
		for _, tpl := range inv.ResourceTemplates {
			if ctx.Err() != nil {
				return attempts
			}
			if !read(expandTemplate(tpl.URITemplate, benignTemplateValue), classTemplateContent) {
				break
			}
		}
	}
	if truncated {
		slog.Warn("mcpprimitive.ContentLeak: resource cap reached; later catalog entries were not read",
			"probe", p.Name(), "cap", p.maxTargets)
	}
	return attempts
}

// readOne issues one resources/read and records the attempt. A protocol error is
// the server's denial signal, not a probe failure (resources/read has no
// application-level error flag), so it is preserved in metadata and the attempt
// completed — a refusal stays a visible non-finding instead of an error verdict.
func (p *ContentLeak) readOne(ctx context.Context, reader types.MCPPrimitiveReader, uri, class string) *attempt.Attempt {
	a := p.newAttempt("read resource "+uri, uri, class)

	res, err := reader.ReadResource(ctx, uri)
	if err != nil {
		a.Metadata[attempt.MetadataKeyPrimitiveCallError] = err.Error()
		a.AddOutput("")
		a.Complete()
		return a
	}
	if res.MIMEType != "" {
		a.Metadata[attempt.MetadataKeyPrimitiveMIMEType] = res.MIMEType
	}
	p.addBounded(a, res.Text, res.Raw)
	a.Complete()
	return a
}

// renderPrompts fetches each advertised prompt template with benign arguments.
func (p *ContentLeak) renderPrompts(ctx context.Context, reader types.MCPPrimitiveReader, invs []*types.MCPInventory) []*attempt.Attempt {
	var attempts []*attempt.Attempt
	seen := make(map[string]bool)
	truncated := false

	for _, inv := range invs {
		if inv == nil {
			continue
		}
		for _, pr := range inv.Prompts {
			if ctx.Err() != nil {
				return attempts
			}
			if pr.Name == "" || seen[pr.Name] {
				continue
			}
			if len(seen) >= p.maxTargets {
				truncated = true
				break
			}
			seen[pr.Name] = true
			attempts = append(attempts, p.renderOne(ctx, reader, pr))
		}
	}
	if truncated {
		slog.Warn("mcpprimitive.ContentLeak: prompt-template cap reached; later catalog entries were not rendered",
			"probe", p.Name(), "cap", p.maxTargets)
	}
	return attempts
}

// renderOne issues one prompts/get with benign arguments. As with a resource
// read, a refusal arrives as a Go error and is recorded as a completed
// non-finding.
func (p *ContentLeak) renderOne(ctx context.Context, reader types.MCPPrimitiveReader, pr types.MCPPrompt) *attempt.Attempt {
	a := p.newAttempt("render prompt template "+pr.Name, pr.Name, classPromptContent)

	res, err := reader.GetPrompt(ctx, pr.Name, benignPromptArgs(pr.Arguments))
	if err != nil {
		a.Metadata[attempt.MetadataKeyPrimitiveCallError] = err.Error()
		a.AddOutput("")
		a.Complete()
		return a
	}
	p.addBounded(a, res.Text, res.Raw)
	a.Complete()
	return a
}

// declaredAttempts scores the one surface the server DECLARES rather than serves
// on request: its initialization instructions. Those reach a client and its host
// model without any call being made, so a secret pasted there is exposed to
// everyone who merely connects.
//
// Catalog descriptions and titles are deliberately NOT scored, despite reaching a
// client the same way. `mcpsecrets.Credential` identifies a credential by a
// credential-shaped KEY followed by a colon and a value, which is exactly right
// for a config file (`"password": "hunter2"`) and exactly wrong for a docstring:
// the `Args:` block of a tool description is also `name: description`. Measured
// against DVMCP challenges 7 and 9, that collision scored 1.0 on nothing more
// than parameter documentation ("password: The password for authentication",
// "token: The session token to verify"). The shape is near-universal in MCP
// descriptions, so the false-positive rate on real targets would exceed the
// value of the surface.
//
// Restoring it needs a value-shaped guard in the detector — suppress when the
// text after the key is prose rather than a secret-shaped token — which belongs
// in mcpsecrets.Credential, where the config and tool-response surfaces would
// benefit too.
func (p *ContentLeak) declaredAttempts(invs []*types.MCPInventory) []*attempt.Attempt {
	var attempts []*attempt.Attempt

	for _, inv := range invs {
		if inv == nil {
			continue
		}
		if strings.TrimSpace(inv.Instructions) != "" {
			a := p.newAttempt("server instructions", inv.ServerName, classInstructions)
			p.addBounded(a, inv.Instructions, nil)
			a.Complete()
			attempts = append(attempts, a)
		}
	}
	return attempts
}

// newAttempt builds the attempt shell every surface shares.
func (p *ContentLeak) newAttempt(prompt, target, class string) *attempt.Attempt {
	a := attempt.New(prompt)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeyPrimitiveClass] = class
	if target != "" {
		a.Metadata[attempt.MetadataKeyPrimitiveTarget] = target
	}
	return a
}

// addBounded stores the returned content, and the raw structured payload when it
// differs, capped at mcpprobe.MaxResponseBytes.
//
// The bound is a deliberate trade. Unlike an injection oracle — whose proof (a
// file signature, a computed canary) appears at the START of the content by
// construction — a credential can sit anywhere in a body, so a cap can hide one
// past the boundary and produce a false clean. 10 MiB is chosen to make that
// remote (it is orders of magnitude beyond any config blob, DSN or key material a
// server plausibly serves) while still bounding report memory against a resource
// pointing at an arbitrarily large or hostile file. What is given up is a secret
// buried beyond 10 MiB of preceding content; what is bought is that a single
// hostile resource cannot exhaust memory and abort the scan.
//
// The raw payload is scored too because a credential may appear only there and
// never in the assembled text — for example in a content block the text assembly
// dropped. It is capped BEFORE the byte-to-string conversion so a huge payload
// cannot force an unbounded allocation, and deduped against the text form.
func (p *ContentLeak) addBounded(a *attempt.Attempt, text string, raw []byte) {
	bounded := mcpprobe.TruncateResponse(text)
	a.AddOutput(bounded)
	if len(raw) > 0 {
		if rawStr := mcpprobe.TruncateResponseBytes(raw); rawStr != bounded {
			a.AddOutput(rawStr)
		}
	}
}
