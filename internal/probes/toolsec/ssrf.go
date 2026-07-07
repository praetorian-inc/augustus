package toolsec

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("toolsec.SSRF", NewSSRF)
}

var _ types.ProbeMetadata = (*SSRF)(nil)

// urlParamRE matches parameter names likely to accept a URL/host, so the probe
// targets plausible SSRF sinks precisely. Set ssrf_all_string_params to widen to
// every string parameter.
var urlParamRE = regexp.MustCompile(`(?i)(^|[_\- ])(url|uri|endpoint|host|hostname|target|webhook|callback|link|href|src|source|dest|destination|proxy|fetch|address|domain|site|server|request)($|[_\- ])`)

// SSRF tests a directly-invokable tool surface for server-side request forgery.
// It stands up a built-in out-of-band collector, injects a unique canary URL
// into each URL-like tool parameter, then waits for the target to call back —
// catching blind SSRF (callback with no returned content) as well as non-blind
// SSRF (the tool returns the fetched body, matched by reflection).
type SSRF struct {
	listen       string        // OOB collector bind address
	baseOverride string        // URL the target should use to reach the collector (optional)
	wait         time.Duration // grace period for callbacks after sending
	allParams    bool          // inject into every string param, not just URL-like ones
	marker       string        // collector body marker (reflection signal)
}

// NewSSRF constructs the probe. All OOB settings default so a localhost target
// works with zero config (ephemeral collector, base derived from its address).
func NewSSRF(cfg registry.Config) (probes.Prober, error) {
	return &SSRF{
		listen:       registry.GetString(cfg, "oob_listen", "127.0.0.1:0"),
		baseOverride: registry.GetString(cfg, "oob_base_url", ""),
		wait:         time.Duration(registry.GetInt(cfg, "oob_wait_seconds", 3)) * time.Second,
		allParams:    registry.GetBool(cfg, "ssrf_all_string_params", false),
		marker:       "AUGOOB" + randToken(),
	}, nil
}

func (p *SSRF) Name() string { return "toolsec.SSRF" }

func (p *SSRF) Description() string {
	return "Injects out-of-band canary URLs into URL-like tool arguments and detects server-side request forgery via callback (blind) or reflected content (non-blind)"
}

func (p *SSRF) Goal() string {
	return "Determine whether any directly-invokable tool fetches attacker-controlled URLs (SSRF)"
}

func (p *SSRF) GetPrimaryDetector() string { return "toolsec.SSRF" }

func (p *SSRF) GetPrompts() []string {
	return []string{"out-of-band SSRF canary URL injected into URL-like parameters"}
}

// Probe discovers tools, injects canary URLs into URL-like string params, waits
// for out-of-band callbacks, and records the callback/reflection signals per
// attempt. Returns no attempts (no error) for non-ToolInvoker targets.
func (p *SSRF) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	inv, ok := gen.(types.ToolInvoker)
	if !ok {
		return nil, nil
	}

	tools, err := inv.ListTools(ctx)
	if err != nil {
		return nil, fmt.Errorf("toolsec.SSRF: list tools: %w", err)
	}

	col, err := startCollector(p.listen, p.baseOverride, p.marker)
	if err != nil {
		return nil, err
	}
	defer col.close()

	type pending struct {
		a     *attempt.Attempt
		token string
	}

	var (
		attempts []*attempt.Attempt
		pend     []pending
	)

	for _, tool := range tools {
		name, _ := tool["name"].(string)
		if name == "" {
			continue
		}
		params := toolParams(tool)
		for _, param := range params {
			if !isStringParam(param.typ) {
				continue
			}
			if !p.allParams && !urlParamRE.MatchString(param.name) {
				continue
			}
			token := randToken()
			canaryURL := col.url(token)

			a := attempt.New(canaryURL)
			a.Probe = p.Name()
			a.Detector = p.GetPrimaryDetector()
			a.Metadata["toolsec.tool"] = name
			a.Metadata["toolsec.param"] = param.name
			a.Metadata[attempt.MetadataKeySSRFOOBURL] = canaryURL

			reflected := false
			res, callErr := inv.CallTool(ctx, name, benignArgs(params, param.name, canaryURL))
			if callErr != nil {
				a.SetError(callErr)
			} else {
				a.AddOutput(res.Text)
				reflected = strings.Contains(res.Text, p.marker)
				a.Complete()
			}
			a.Metadata[attempt.MetadataKeySSRFReflected] = reflected

			pend = append(pend, pending{a: a, token: token})
			attempts = append(attempts, a)
		}
	}

	if len(attempts) == 0 {
		slog.Warn("toolsec.SSRF: no URL-like tool parameters found; set ssrf_all_string_params=true to test every string parameter", "tools", len(tools))
		return nil, nil
	}

	// Give the target time to make out-of-band callbacks, then record results.
	p.waitForCallbacks(ctx)
	for _, item := range pend {
		item.a.Metadata[attempt.MetadataKeySSRFCallback] = col.wasHit(item.token)
	}
	return attempts, nil
}

// waitForCallbacks sleeps for the grace period, honoring context cancellation.
func (p *SSRF) waitForCallbacks(ctx context.Context) {
	if p.wait <= 0 {
		return
	}
	t := time.NewTimer(p.wait)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}
