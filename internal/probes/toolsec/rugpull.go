package toolsec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

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
// The baseline is either a trusted on-disk snapshot (config baseline_path) or,
// absent one, the target's own first enumeration — the probe then clears history
// and re-lists, catching servers that mutate their definitions immediately.
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

	baseline, current, err := p.snapshots(ctx, gen, inv)
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

// snapshots returns the baseline and current tool sets. With a configured
// baseline_path it reads the trusted on-disk snapshot as the baseline and the
// live ListTools as current; otherwise it lists twice across ClearHistory to
// catch a server that mutates its definitions between enumerations.
func (p *RugPull) snapshots(ctx context.Context, gen types.Generator, inv types.ToolInvoker) (baseline, current []map[string]any, err error) {
	if p.baselinePath != "" {
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

	baseline, err = inv.ListTools(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("toolsec.RugPull: list tools (baseline): %w", err)
	}
	gen.ClearHistory()
	current, err = inv.ListTools(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("toolsec.RugPull: list tools (current): %w", err)
	}
	return baseline, current, nil
}

// loadToolSnapshot reads a JSON tool snapshot ([]map[string]any) from disk.
func loadToolSnapshot(path string) ([]map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tools []map[string]any
	if err := json.Unmarshal(data, &tools); err != nil {
		return nil, err
	}
	return tools, nil
}
