// Package mcpconfig provides a context-aware probe over MCP (Model Context
// Protocol) server configuration.
//
// CredentialExposure is a scorer, not a collector: it does no file I/O itself.
// Config collection lives in the recon.MCPConfig module (internal/recon/mcpconfig),
// which reads inline content, a file, or a directory and emits one mcp.config
// observation per source into the shared recon Store. This probe opts into that
// store via recon.ContextAwareProbe and, for each collected config source, emits
// an attempt whose output is the config content so the mcpsecrets.Credential
// detector can flag exposed credentials. This is the "scan once, reuse
// everywhere" model: recon populates the workspace, the probe scores it.
//
// Run it after recon. recon.MCPConfig is configured from the recon.settings block
// of a YAML config file (recon modules are not configured by --config, which
// carries generator config only):
//
//	# mcpconfig.yaml
//	recon:
//	  settings:
//	    recon.MCPConfig:
//	      path: "/path/to/mcp/config"
//
//	augustus scan <target> --recon recon.MCPConfig --probe mcpconfig.CredentialExposure \
//	  --config-file mcpconfig.yaml
//
// When the recon store holds no config (recon.MCPConfig was not run, or found
// nothing), the probe emits a single informational, non-vulnerable attempt
// explaining that recon.MCPConfig must supply config content. It covers the
// static half of LAB-4463 (Credential Exposure), mapping to OWASP MCP01 (Token
// Mismanagement) / MCP04 (Supply Chain).
//
// Caveat: attempt outputs embed the scanned content verbatim, including any real
// credential found, so the resulting JSONL report artifacts are secret-bearing
// and should be treated as sensitive.
package mcpconfig

import (
	"context"

	mcpconfigrecon "github.com/praetorian-inc/augustus/internal/recon/mcpconfig"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

const (
	probeName       = "mcpconfig.CredentialExposure"
	primaryDetector = "mcpsecrets.Credential"
)

func init() {
	probes.Register(probeName, NewCredentialExposure)
}

// Compile-time assertions: CredentialExposure exposes probe metadata and
// consumes prior reconnaissance.
var (
	_ types.ProbeMetadata     = (*CredentialExposure)(nil)
	_ recon.ContextAwareProbe = (*CredentialExposure)(nil)
)

// CredentialExposure scores MCP configuration gathered by the recon.MCPConfig
// module for exposed credentials. It reads the shared recon store delivered via
// SetContext and does no file I/O of its own.
type CredentialExposure struct {
	store *recon.Store
}

// NewCredentialExposure constructs the probe. It takes no config: config
// collection (path/content) moved to the recon.MCPConfig module.
func NewCredentialExposure(_ registry.Config) (probes.Prober, error) {
	return &CredentialExposure{}, nil
}

// SetContext implements recon.ContextAwareProbe. The scan runner calls it once,
// before Probe(), with the shared observation store.
func (p *CredentialExposure) SetContext(pc recon.ProbeContext) { p.store = pc.Recon }

// Probe emits one attempt per config source held in the recon store, each
// carrying that source's content as output for the mcpsecrets.Credential
// detector to score. When the store holds no config, it returns a single
// informational, non-vulnerable attempt. The generator is intentionally unused.
func (p *CredentialExposure) Probe(ctx context.Context, _ probes.Generator) ([]*attempt.Attempt, error) {
	configs := mcpconfigrecon.ConfigsFrom(p.store)
	if len(configs) == 0 {
		return []*attempt.Attempt{p.informational()}, nil
	}

	attempts := make([]*attempt.Attempt, 0, len(configs))
	for _, cfg := range configs {
		if err := ctx.Err(); err != nil {
			return attempts, err
		}
		a := attempt.New(cfg.Source)
		a.Probe = probeName
		a.Detector = primaryDetector
		a.WithMetadata("source", cfg.Source)
		a.AddOutput(cfg.Content)
		a.Complete()
		attempts = append(attempts, a)
	}
	return attempts, nil
}

// informational records a benign, non-vulnerable attempt noting that no config
// was available to score, so an operator can tell "recon not run" apart from a
// genuinely clean pass. Its output carries no credential, so the detector scores
// it 0.0.
func (p *CredentialExposure) informational() *attempt.Attempt {
	a := attempt.New("no MCP config in recon store")
	a.Probe = probeName
	a.Detector = primaryDetector
	a.AddOutput("no MCP configuration was available to scan; run the recon.MCPConfig module (with a 'path' or 'content' config) before this probe to supply config content")
	a.Complete()
	return a
}

// Name returns the fully qualified probe name.
func (p *CredentialExposure) Name() string { return probeName }

var _ types.RiskDescriber = (*CredentialExposure)(nil)

// RiskInfo is the curated security write-up for this probe's finding.
func (p *CredentialExposure) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description:    "An MCP server's configuration, .env files, or connection strings contain hard-coded credentials — provider API keys, secret-named values, or URI userinfo.",
		Impact:         "Anyone able to read the configuration (a source repo, an image layer, a shared config directory) obtains working credentials for the services the server integrates with.",
		Recommendation: "Keep credentials out of committed configuration: load them from a secrets manager or injected environment at runtime, reference them indirectly rather than inlining values, and rotate any secret that has already been committed. Scope each credential to least privilege.",
		References:     "https://cwe.mitre.org/data/definitions/798.html\nhttps://cwe.mitre.org/data/definitions/312.html\nhttps://owasp.org/www-project-top-10-for-large-language-model-applications/",
		Taxonomies:     "- cwe: 798\n- cwe: 312\n- cwe: 200",
		CVSSVector:     "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
	}
}

// Description returns a human-readable description.
func (p *CredentialExposure) Description() string {
	return "Scores MCP server configuration gathered by the recon.MCPConfig module for exposed credentials"
}

// Goal returns the probe's goal.
func (p *CredentialExposure) Goal() string {
	return "detect credentials exposed in MCP configuration content collected by recon.MCPConfig (inline text, a file, or config files found by walking a directory)"
}

// GetPrimaryDetector returns the recommended detector for this probe.
func (p *CredentialExposure) GetPrimaryDetector() string { return primaryDetector }

// GetPrompts returns the probe's prompts. CredentialExposure sends none: it
// scores prior reconnaissance rather than issuing prompts.
func (p *CredentialExposure) GetPrompts() []string { return nil }
