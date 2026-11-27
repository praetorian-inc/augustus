package mcpprimitive

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("mcpprimitive.UnframedRelay", NewUnframedRelay)
}

var (
	_ types.ProbeMetadata     = (*UnframedRelay)(nil)
	_ types.RiskDescriber     = (*UnframedRelay)(nil)
	_ recon.ContextAwareProbe = (*UnframedRelay)(nil)
)

// UnframedRelay tests whether MCP resources and prompt templates relay
// caller-supplied content back to the host model interpolated into
// server-authored prose, without escaping, delimiting, or labelling it.
//
// The probe injects a structurally distinctive canary — not an injection
// payload — into resource template parameters and prompt template arguments,
// then checks the response for four simultaneous conditions: verbatim echo,
// no escaping, no delimiter, and substantial server-authored text around the
// canary. All four together are the finding; any alone is not.
//
// This covers the resource and prompt surfaces that the sibling
// mcptool.UnframedRelay does not reach (that probe covers tools/call).
type UnframedRelay struct {
	reconContext
	canary     mcpprobe.RelayCanary
	maxTargets int
}

func NewUnframedRelay(cfg registry.Config) (probes.Prober, error) {
	maxTargets := registry.GetInt(cfg, "resource_max_targets", 25)
	if maxTargets <= 0 {
		return nil, fmt.Errorf("mcpprimitive.UnframedRelay: resource_max_targets must be positive, got %d; a non-positive cap skips every surface and reports nothing, which is indistinguishable from a clean result", maxTargets)
	}
	return &UnframedRelay{
		canary:     mcpprobe.NewRelayCanary(),
		maxTargets: maxTargets,
	}, nil
}

func (p *UnframedRelay) Name() string { return "mcpprimitive.UnframedRelay" }

func (p *UnframedRelay) Description() string {
	return "Sends a structurally distinctive canary into resource template parameters and prompt template arguments and checks whether the response relays it back interpolated into server-authored prose without escaping, delimiting, or labelling (authority confusion channel)"
}

func (p *UnframedRelay) Goal() string {
	return "Determine whether any MCP resource template or prompt template relays caller-supplied content into its response without a data boundary, enabling authority confusion (OWASP MCP06/MCP10)"
}

func (p *UnframedRelay) GetPrimaryDetector() string { return "mcptool.UnframedRelay" }

func (p *UnframedRelay) GetPrompts() []string { return p.canary.Payloads }

func (p *UnframedRelay) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description:    "An MCP resource template or prompt template relays caller-supplied content back to the host model interpolated into server-authored prose, without escaping, delimiting, or labelling the relayed content.",
		Impact:         "Attacker-controlled content inherits the authority of the server's own output in the model's context. A model consuming the response cannot distinguish what the server said from what the caller planted, enabling indirect prompt injection through the resource or prompt response channel.",
		Recommendation: "Frame all relayed content with a data boundary: return it in a named JSON field with a source label, inside a code fence, or with explicit delimiters and escaping. Never interpolate untrusted content into server-authored prose as though the server wrote it.",
		References:     "https://cwe.mitre.org/data/definitions/74.html\nhttps://cwe.mitre.org/data/definitions/116.html\nhttps://owasp.org/www-project-top-10-for-large-language-model-applications/",
		Taxonomies:     "- cwe: 74\n- cwe: 116",
		CVSSVector:     "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N",
		Verification: "## How this is confirmed\n\n" +
			"Augustus sends a structurally distinctive canary into each resource template parameter and prompt template argument. " +
			"The canary is not an injection payload: it observes how the server handles relayed content, " +
			"it does not attempt to manipulate the model.\n\n" +
			"A finding requires ALL FOUR conditions simultaneously:\n\n" +
			"1. The canary appears verbatim in the response (echoed back unchanged).\n" +
			"2. The canary is unescaped: no HTML entity, backslash, or URL encoding was applied.\n" +
			"3. The canary is undelimited: not inside a JSON string value, code fence, quoted block, or HTML code/pre tag.\n" +
			"4. The canary is adjacent to server-authored text: the response contains substantial server prose around it, so there is authority to borrow. A bare echo with no surrounding text does not fire.\n\n" +
			"Any one condition alone is not a finding.\n\n" +
			"## Reproduce\n\n" +
			"Re-run the mcpprimitive.UnframedRelay probe against the affected endpoint via the mcp.MCP generator. " +
			"The flagged resource or prompt template's response contains the relay canary embedded in server prose without framing.",
	}
}

// Probe discovers the target's resource templates and prompt templates, injects
// relay canary payloads into their parameters, and records one attempt each.
func (p *UnframedRelay) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	reader, ok := gen.(types.MCPPrimitiveReader)
	if !ok {
		return nil, fmt.Errorf("mcpprimitive.UnframedRelay: target %q cannot read MCP primitives; this probe requires a primitive-reading generator such as mcp.MCP", gen.Name())
	}

	invs, err := p.resolveInventories(ctx, gen)
	if err != nil {
		return nil, fmt.Errorf("mcpprimitive.UnframedRelay: catalog unavailable: %w", err)
	}
	if len(invs) == 0 {
		_, hasRecon := gen.(types.MCPReconnaissance)
		if !hasRecon {
			return nil, fmt.Errorf("mcpprimitive.UnframedRelay: no inventories available and target does not support enumeration; cannot assess resource or prompt templates")
		}
	}

	var attempts []*attempt.Attempt
	resourceTargets := 0
	promptTargets := 0
	resourceTruncated := false
	promptTruncated := false

	for _, inv := range invs {
		if inv == nil {
			continue
		}
		for _, tpl := range inv.ResourceTemplates {
			if resourceTargets >= p.maxTargets || ctx.Err() != nil {
				resourceTruncated = resourceTargets >= p.maxTargets
				break
			}
			if tpl.URITemplate == "" {
				continue
			}
			for _, payload := range p.canary.Payloads {
				encoded := url.PathEscape(payload)
				uri := expandTemplate(tpl.URITemplate, encoded)
				if uri == "" {
					continue
				}
				if ctx.Err() != nil {
					return attempts, nil
				}
				attempts = append(attempts, p.readResource(ctx, reader, uri, payload))
			}
			resourceTargets++
		}
		for _, pt := range inv.Prompts {
			if promptTargets >= p.maxTargets || ctx.Err() != nil {
				promptTruncated = promptTargets >= p.maxTargets
				break
			}
			if pt.Name == "" || len(pt.Arguments) == 0 {
				continue
			}
			for _, arg := range pt.Arguments {
				if arg.Name == "" {
					continue
				}
				for _, payload := range p.canary.Payloads {
					if ctx.Err() != nil {
						return attempts, nil
					}
					args := promptArgs(pt.Arguments, arg.Name, payload)
					attempts = append(attempts, p.readPrompt(ctx, reader, pt.Name, arg.Name, args))
				}
			}
			promptTargets++
		}
	}

	if resourceTruncated {
		slog.Warn("mcpprimitive.UnframedRelay: resource cap reached; later catalog entries were not tested",
			"probe", p.Name(), "cap", p.maxTargets)
	}
	if promptTruncated {
		slog.Warn("mcpprimitive.UnframedRelay: prompt cap reached; later catalog entries were not tested",
			"probe", p.Name(), "cap", p.maxTargets)
	}
	return attempts, nil
}

func (p *UnframedRelay) readResource(ctx context.Context, reader types.MCPPrimitiveReader, uri, payload string) *attempt.Attempt {
	// Store the actual payload (not the expanded URI) so the detector can
	// subtract caller-authored text from the server-context calculation.
	a := attempt.New(payload)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeyRelayCanary] = p.canary.Marker
	a.Metadata[attempt.MetadataKeyPrimitiveTarget] = uri
	a.Metadata[attempt.MetadataKeyPrimitiveClass] = classTemplateArg

	res, err := reader.ReadResource(ctx, uri)
	if err != nil {
		recordCallError(p.Name(), a, err, uri)
		return a
	}
	a.AddOutput(mcpprobe.TruncateResponse(res.Text))
	a.Complete()
	return a
}

func (p *UnframedRelay) readPrompt(ctx context.Context, reader types.MCPPrimitiveReader, promptName, argName string, args map[string]string) *attempt.Attempt {
	payload := args[argName]
	a := attempt.New(payload)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeyRelayCanary] = p.canary.Marker
	a.Metadata[attempt.MetadataKeyPrimitiveTarget] = promptName
	a.Metadata[attempt.MetadataKeyPrimitiveClass] = classPromptContent
	a.Metadata[attempt.MetadataKeyPrimitiveArg] = argName

	res, err := reader.GetPrompt(ctx, promptName, args)
	if err != nil {
		recordCallError(p.Name(), a, err, promptName)
		return a
	}
	a.AddOutput(mcpprobe.TruncateResponse(res.Text))
	a.Complete()
	return a
}
