package templates

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// TemplateProbe wraps a ProbeTemplate to implement types.Prober.
type TemplateProbe struct {
	template *ProbeTemplate
}

// NewTemplateProbe creates a new TemplateProbe from a template definition.
func NewTemplateProbe(tmpl *ProbeTemplate) *TemplateProbe {
	return &TemplateProbe{template: tmpl}
}

// Probe executes the probe against the generator.
// Implements types.Prober interface.
func (t *TemplateProbe) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	tools := t.GetTools()
	toolResults := t.template.Info.ToolResults

	// Use 2-turn mode when both tools and tool_results are defined.
	if len(tools) > 0 && len(toolResults) > 0 {
		return probes.RunTwoTurnPrompts(
			ctx, gen, t.template.Prompts, t.Name(), t.GetPrimaryDetector(),
			tools, t.GetToolChoice(), toolResults,
		)
	}

	// Standard single-turn mode.
	var toolsFn func() ([]map[string]any, string)
	if len(tools) > 0 {
		toolChoice := t.GetToolChoice()
		toolsFn = func() ([]map[string]any, string) { return tools, toolChoice }
	}
	return probes.RunPrompts(ctx, gen, t.template.Prompts, t.Name(), t.GetPrimaryDetector(), nil, toolsFn)
}

// Name returns the probe's fully qualified name.
func (t *TemplateProbe) Name() string {
	return t.template.ID
}

// Description returns a human-readable description.
func (t *TemplateProbe) Description() string {
	return t.template.Info.Description
}

// Goal returns the probe's objective.
func (t *TemplateProbe) Goal() string {
	return t.template.Info.Goal
}

// GetPrimaryDetector returns the recommended detector.
func (t *TemplateProbe) GetPrimaryDetector() string {
	return t.template.Info.Detector
}

// GetPrompts returns the prompts used by this probe.
func (t *TemplateProbe) GetPrompts() []string {
	return t.template.Prompts
}

// GetMode returns the deployment surfaces this probe targets.
func (t *TemplateProbe) GetMode() []string {
	return t.template.Info.Mode
}

// GetDetectorConfig returns per-probe detector configuration overrides.
// Returns nil when the template has no detector_config block.
func (t *TemplateProbe) GetDetectorConfig() map[string]any {
	return t.template.Info.DetectorConfig
}

// GetSecondaryDetectors returns additional detectors to run alongside the primary.
// Implements types.ProbeSecondaryDetectors. Returns nil when the template has
// no secondary_detectors block, preserving single-detector behavior unchanged.
func (t *TemplateProbe) GetSecondaryDetectors() []types.SecondaryDetector {
	if len(t.template.Info.SecondaryDetectors) == 0 {
		return nil
	}
	out := make([]types.SecondaryDetector, len(t.template.Info.SecondaryDetectors))
	for i, s := range t.template.Info.SecondaryDetectors {
		out[i] = types.SecondaryDetector{
			Name:   s.Name,
			Config: s.Config,
		}
	}
	return out
}

// GetTools returns tool definitions in the canonical map format for Conversation.Tools.
func (t *TemplateProbe) GetTools() []map[string]any {
	if len(t.template.Info.Tools) == 0 {
		return nil
	}
	tools := make([]map[string]any, len(t.template.Info.Tools))
	for i, td := range t.template.Info.Tools {
		tool := map[string]any{
			"name":        td.Name,
			"description": td.Description,
		}
		if td.Parameters != nil {
			tool["parameters"] = td.Parameters
		}
		tools[i] = tool
	}
	return tools
}

// GetToolChoice returns the tool_choice setting for this probe.
func (t *TemplateProbe) GetToolChoice() string {
	return t.template.Info.ToolChoice
}
