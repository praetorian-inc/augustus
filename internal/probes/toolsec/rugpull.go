package toolsec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	driftdet "github.com/praetorian-inc/augustus/internal/detectors/toolsec"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("toolsec.RugPull", NewRugPull)
}

// Compile-time assertion: RugPull exposes probe metadata.
var _ types.ProbeMetadata = (*RugPull)(nil)

// cfgBaselinePath names the config key holding a trusted tool snapshot to diff
// the live tool set against.
const cfgBaselinePath = "baseline_path"

// RugPull detects post-approval tool-definition drift (OWASP MCP04 "rug pull"):
// an MCP server that advertises benign tools at approval time and later mutates
// their definitions. It diffs a baseline snapshot against the current tool set.
//
// The baseline is a trusted on-disk snapshot supplied via the baseline_path
// config key. Without one there is nothing to diff against, so the probe emits a
// single informational attempt explaining that a baseline snapshot is required
// rather than mutating the shared session to re-enumerate.
//
// The target must implement types.ToolInvoker; other targets fail loud rather
// than return a clean-looking empty result.
type RugPull struct {
	baselinePath string
}

// NewRugPull constructs the probe, reading the optional baseline_path.
func NewRugPull(cfg registry.Config) (probes.Prober, error) {
	return &RugPull{baselinePath: registry.GetString(cfg, cfgBaselinePath, "")}, nil
}

func (p *RugPull) Name() string { return "toolsec.RugPull" }

func (p *RugPull) Description() string {
	return "Diffs a baseline tool snapshot against the current tool set to detect post-approval tool-definition drift (added/removed tools, changed description/parameters)"
}

func (p *RugPull) Goal() string {
	return "Determine whether a tool-surface target mutates its tool definitions after approval (OWASP MCP04 rug-pull / tool poisoning)"
}

func (p *RugPull) GetPrimaryDetector() string { return "toolsec.ToolDrift" }

func (p *RugPull) GetPrompts() []string { return nil }

// Probe compares the baseline and current tool snapshots and emits one attempt
// per detected change (marker-prefixed, scored by toolsec.ToolDrift). When there
// is no drift it emits a single benign attempt so the scan still records a clean
// SAFE result rather than an empty one.
func (p *RugPull) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	inv, ok := gen.(types.ToolInvoker)
	if !ok {
		return nil, fmt.Errorf("toolsec.RugPull: target %q does not support direct tool invocation; this probe requires a tool-surface generator such as mcp.MCP", gen.Name())
	}

	// Drift detection requires a trusted baseline to diff the live tool set
	// against. Without one there is nothing to compare, so emit a single
	// informational attempt rather than mutating the shared session to re-list.
	if p.baselinePath == "" {
		return []*attempt.Attempt{p.noBaselineAttempt()}, nil
	}

	baseline, current, err := p.snapshots(ctx, inv)
	if err != nil {
		return nil, err
	}

	changes := DiffTools(baseline, current)
	if len(changes) == 0 {
		a := attempt.New("tool definitions stable across snapshots")
		a.Probe = p.Name()
		a.Detector = p.GetPrimaryDetector()
		a.AddOutput("no tool-definition drift detected")
		a.Complete()
		return []*attempt.Attempt{a}, nil
	}

	attempts := make([]*attempt.Attempt, 0, len(changes))
	for _, ch := range changes {
		a := attempt.New("tool-definition drift: " + ch.Name)
		a.Probe = p.Name()
		a.Detector = p.GetPrimaryDetector()
		a.Metadata["toolsec.tool"] = ch.Name
		a.AddOutput(driftdet.DriftMarker + " " + ch.Name + ": " + ch.Kind + " " + ch.Detail)
		a.Complete()
		attempts = append(attempts, a)
	}
	return attempts, nil
}

// noBaselineAttempt records a benign, non-vulnerable attempt explaining that
// drift detection needs a trusted baseline snapshot. It carries no DriftMarker,
// so toolsec.ToolDrift scores it 0.0 (SAFE).
func (p *RugPull) noBaselineAttempt() *attempt.Attempt {
	a := attempt.New("rug-pull drift detection requires a baseline snapshot")
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.AddOutput("no baseline snapshot configured; set the baseline_path config key to a trusted tool snapshot to enable post-approval drift detection")
	a.Complete()
	return a
}

// snapshots returns the baseline and current tool sets. It reads the trusted
// on-disk snapshot named by baseline_path as the baseline and one live ListTools
// as current. It is only called when baseline_path is set.
func (p *RugPull) snapshots(ctx context.Context, inv types.ToolInvoker) (baseline, current []map[string]any, err error) {
	baseline, err = loadToolSnapshot(p.baselinePath)
	if err != nil {
		return nil, nil, fmt.Errorf("toolsec.RugPull: load baseline %q: %w", p.baselinePath, err)
	}
	current, err = inv.ListTools(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("toolsec.RugPull: list tools: %w", err)
	}
	return baseline, current, nil
}

// loadToolSnapshot reads a JSON tool snapshot ([]map[string]any) from disk.
func loadToolSnapshot(path string) ([]map[string]any, error) {
	// #nosec G304 -- operator-supplied baseline_path; reading the operator-designated tool snapshot is this probe's purpose.
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var tools []map[string]any
	if err := json.Unmarshal(data, &tools); err != nil {
		return nil, err
	}
	return tools, nil
}
