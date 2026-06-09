package templates

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	// ErrMissingID is returned when template validation fails due to missing id field.
	ErrMissingID = errors.New("template validation failed: 'id' is required")

	// ErrMissingName is returned when template validation fails due to missing info.name field.
	ErrMissingName = errors.New("template validation failed: 'info.name' is required")

	// ErrMissingDetector is returned when template validation fails due to missing info.detector field.
	ErrMissingDetector = errors.New("template validation failed: 'info.detector' is required")

	// ErrInvalidSeverity is returned when template validation fails due to invalid severity value.
	ErrInvalidSeverity = errors.New("template validation failed: invalid severity")

	// ErrEmptyPrompts is returned when template validation fails due to empty prompts array.
	ErrEmptyPrompts = errors.New("template validation failed: 'prompts' cannot be empty")

	// ErrEmptySecondaryDetectorName is returned when a secondary_detectors entry has an empty name.
	ErrEmptySecondaryDetectorName = errors.New("template validation failed: secondary_detectors entry must have a non-empty name")

	// ErrDuplicateSecondaryDetectorName is returned when secondary_detectors contains duplicate names.
	ErrDuplicateSecondaryDetectorName = errors.New("template validation failed: secondary_detectors contains duplicate name")

	// ErrSecondaryDetectorSelfReference is returned when a secondary detector name equals the primary.
	ErrSecondaryDetectorSelfReference = errors.New("template validation failed: secondary_detectors entry name must not equal the primary detector")

	// ErrInvalidType is returned when a template declares an unknown type.
	ErrInvalidType = errors.New("template validation failed: 'type' must be 'static' or 'multiturn'")

	// ErrMissingEngine is returned when a multi-turn template has no engine block.
	ErrMissingEngine = errors.New("template validation failed: multi-turn templates require an 'engine' block")

	// ErrMissingGeneratorType is returned when a multi-turn engine omits an attacker or judge generator type.
	ErrMissingGeneratorType = errors.New("template validation failed: engine requires 'attacker_generator_type' and 'judge_generator_type'")

	// ErrMissingStrategyPrompt is returned when a multi-turn template omits a required strategy prompt.
	ErrMissingStrategyPrompt = errors.New("template validation failed: strategy requires 'attacker_system' and 'turn' prompts")

	// Classification validation regexes compiled once at package init
	cwePattern   = regexp.MustCompile(`^CWE-\d+$`)
	mitrePattern = regexp.MustCompile(`^(T\d{4}(\.\d{3})?|AML\.T\d{4}(\.\d{3})?)$`)
	owaspPattern = regexp.MustCompile(`^A\d{2}:\d{4}$`)
)

// Template type discriminators. An empty Type is treated as TypeStatic for
// backward compatibility with existing single-turn templates.
const (
	// TypeStatic is a single-turn probe that fires a fixed list of prompts.
	TypeStatic = "static"

	// TypeMultiTurn is a multi-turn probe driven by the unified multi-turn
	// attack engine, with the strategy supplied as prompt templates.
	TypeMultiTurn = "multiturn"
)

// ProbeTemplate defines the YAML structure for probe templates.
// Follows Nuclei's template pattern for community contributions.
type ProbeTemplate struct {
	// ID is the fully qualified probe name (e.g., "dan.Dan_11_0")
	ID string `yaml:"id"`

	// Type selects the probe kind: "static" (default) or "multiturn".
	Type string `yaml:"type,omitempty"`

	// Info contains probe metadata
	Info ProbeInfo `yaml:"info"`

	// Prompts contains the attack prompts (static templates only).
	Prompts []string `yaml:"prompts,omitempty"`

	// Engine configures the multi-turn attack engine (multi-turn templates only).
	Engine *EngineConfig `yaml:"engine,omitempty"`

	// Strategy supplies the multi-turn attack prompts (multi-turn templates only).
	Strategy *StrategyConfig `yaml:"strategy,omitempty"`
}

// EngineConfig holds the multi-turn engine parameters for a multi-turn template.
// Field semantics mirror internal/multiturn/config.Config.
type EngineConfig struct {
	// AttackerGeneratorType is the registered generator type for the attacker LLM.
	AttackerGeneratorType string `yaml:"attacker_generator_type"`

	// JudgeGeneratorType is the registered generator type for the in-loop judge LLM.
	JudgeGeneratorType string `yaml:"judge_generator_type"`

	// AttackerModel optionally overrides the attacker model name.
	AttackerModel string `yaml:"attacker_model,omitempty"`

	// MaxTurns is the maximum number of conversation turns (default: engine default).
	MaxTurns int `yaml:"max_turns,omitempty"`

	// SuccessThreshold is the judge score (0-1) that triggers early success exit.
	SuccessThreshold float64 `yaml:"success_threshold,omitempty"`

	// MaxRefusalRetries is the max retries per turn when the target refuses.
	MaxRefusalRetries int `yaml:"max_refusal_retries,omitempty"`

	// MaxBacktracks is the max turn-level rollbacks on refusal.
	MaxBacktracks int `yaml:"max_backtracks,omitempty"`

	// Stateful disables backtracking for stateful targets when true.
	Stateful bool `yaml:"stateful,omitempty"`
}

// StrategyConfig supplies the multi-turn attack prompt templates. Each field is
// a Go text/template rendered with strategy-specific data at runtime.
type StrategyConfig struct {
	// Name is the strategy identifier reported in results (default: the template ID).
	Name string `yaml:"name,omitempty"`

	// Parser selects attacker-output parsing: "simple" (default) or "extended".
	Parser string `yaml:"parser,omitempty"`

	// AttackerSystem is the attacker system prompt template. Required.
	AttackerSystem string `yaml:"attacker_system"`

	// Turn is the per-turn question prompt template. Required.
	Turn string `yaml:"turn"`

	// Rephrase is the prompt template used to rephrase a refused question. Optional.
	Rephrase string `yaml:"rephrase,omitempty"`

	// Feedback is the prompt template feeding target response + score back. Optional.
	Feedback string `yaml:"feedback,omitempty"`
}

// IsMultiTurn reports whether the template is a multi-turn probe.
func (t *ProbeTemplate) IsMultiTurn() bool {
	return t.Type == TypeMultiTurn
}

// Validate checks if the ProbeTemplate has all required fields and valid values.
// Validation is type-aware: static templates require a non-empty prompts list,
// while multi-turn templates require engine and strategy blocks instead.
func (t *ProbeTemplate) Validate() error {
	if t.ID == "" {
		return ErrMissingID
	}
	if t.Info.Name == "" {
		return ErrMissingName
	}
	if t.Info.Detector == "" {
		return fmt.Errorf("%w for template '%s'", ErrMissingDetector, t.ID)
	}
	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "info": true,
	}
	if !validSeverities[strings.ToLower(t.Info.Severity)] {
		return fmt.Errorf("%w: '%s'", ErrInvalidSeverity, t.Info.Severity)
	}

	switch t.Type {
	case "", TypeStatic:
		return t.validateStatic()
	case TypeMultiTurn:
		return t.validateMultiTurn()
	default:
		return fmt.Errorf("%w (template '%s' has type '%s')", ErrInvalidType, t.ID, t.Type)
	}
}

// validateStatic enforces the single-turn template requirements.
func (t *ProbeTemplate) validateStatic() error {
	if len(t.Prompts) == 0 {
		return fmt.Errorf("%w for template '%s'", ErrEmptyPrompts, t.ID)
	}
	for i, prompt := range t.Prompts {
		if strings.TrimSpace(prompt) == "" {
			return fmt.Errorf("template validation failed: prompt %d is empty for template '%s'", i+1, t.ID)
		}
	}
	// Validate mode values if present.
	validModes := map[string]bool{"native": true, "chat": true, "agent_loop": true}
	for _, m := range t.Info.Mode {
		if !validModes[m] {
			return fmt.Errorf("template validation failed: invalid mode '%s' for template '%s' (valid: native, chat, agent_loop)", m, t.ID)
		}
	}
	// Validate secondary_detectors entries.
	primary := strings.TrimSpace(t.Info.Detector)
	seen := make(map[string]bool, len(t.Info.SecondaryDetectors))
	for _, sd := range t.Info.SecondaryDetectors {
		name := strings.TrimSpace(sd.Name)
		if name == "" {
			return fmt.Errorf("%w for template '%s'", ErrEmptySecondaryDetectorName, t.ID)
		}
		if name == primary {
			return fmt.Errorf("%w: '%s' for template '%s'", ErrSecondaryDetectorSelfReference, name, t.ID)
		}
		if seen[name] {
			return fmt.Errorf("%w: '%s' for template '%s'", ErrDuplicateSecondaryDetectorName, name, t.ID)
		}
		seen[name] = true
	}
	// Validate tool definitions if present.
	toolNames := make(map[string]bool, len(t.Info.Tools))
	for _, tool := range t.Info.Tools {
		if tool.Name == "" {
			return fmt.Errorf("template validation failed: tools entry must have a non-empty name for template '%s'", t.ID)
		}
		if toolNames[tool.Name] {
			return fmt.Errorf("template validation failed: duplicate tool name '%s' for template '%s'", tool.Name, t.ID)
		}
		toolNames[tool.Name] = true
	}
	// Validate tool_choice if present.
	if tc := t.Info.ToolChoice; tc != "" {
		validChoices := map[string]bool{"auto": true, "required": true, "none": true}
		if !validChoices[tc] && !toolNames[tc] {
			return fmt.Errorf("template validation failed: tool_choice '%s' is not 'auto', 'required', 'none', or a declared tool name for template '%s'", tc, t.ID)
		}
	}
	// Validate tool_results cross-references if present.
	if len(t.Info.ToolResults) > 0 {
		if len(toolNames) == 0 {
			return fmt.Errorf("template validation failed: tool_results requires at least one declared tool for template '%s'", t.ID)
		}
		for resultTool := range t.Info.ToolResults {
			if !toolNames[resultTool] {
				return fmt.Errorf("template validation failed: tool_results references undeclared tool '%s' for template '%s'", resultTool, t.ID)
			}
		}
	}
	return nil
}

// validateMultiTurn enforces the multi-turn template requirements.
func (t *ProbeTemplate) validateMultiTurn() error {
	if t.Engine == nil {
		return fmt.Errorf("%w (template '%s')", ErrMissingEngine, t.ID)
	}
	if strings.TrimSpace(t.Engine.AttackerGeneratorType) == "" || strings.TrimSpace(t.Engine.JudgeGeneratorType) == "" {
		return fmt.Errorf("%w (template '%s')", ErrMissingGeneratorType, t.ID)
	}
	if t.Strategy == nil ||
		strings.TrimSpace(t.Strategy.AttackerSystem) == "" ||
		strings.TrimSpace(t.Strategy.Turn) == "" {
		return fmt.Errorf("%w (template '%s')", ErrMissingStrategyPrompt, t.ID)
	}
	return nil
}

// ValidateClassification checks that classification fields follow expected formats.
// This is optional validation -- templates without classification are still valid.
func (t *ProbeTemplate) ValidateClassification() error {
	// CWE format: CWE-\d+
	for _, cwe := range t.Info.CWEIDs {
		if !cwePattern.MatchString(cwe) {
			return fmt.Errorf("invalid CWE format '%s' (expected: CWE-123)", cwe)
		}
	}

	// MITRE ATT&CK format: T\d{4} or T\d{4}.\d{3}
	// MITRE ATLAS format: AML.T\d{4} or AML.T\d{4}.\d{3}
	for _, technique := range t.Info.MITREAttack {
		if !mitrePattern.MatchString(technique) {
			return fmt.Errorf("invalid MITRE technique format '%s' (expected: T1234, T1234.567, AML.T0054, or AML.T0054.001)", technique)
		}
	}

	// OWASP format: A\d{2}:\d{4}
	for _, owasp := range t.Info.OWASPTopTen {
		if !owaspPattern.MatchString(owasp) {
			return fmt.Errorf("invalid OWASP format '%s' (expected: A01:2021)", owasp)
		}
	}

	return nil
}

// ProbeInfo contains metadata about a probe template.
type ProbeInfo struct {
	// Name is the human-readable probe name
	Name string `yaml:"name"`

	// Author identifies who created the template
	Author string `yaml:"author"`

	// Mode declares which deployment surfaces this probe targets.
	// Valid values: "native" (structured tool calls), "chat" (text-only),
	// "agent_loop" (multi-turn with tool execution).
	Mode []string `yaml:"mode,omitempty"`

	// Description explains what the probe does
	Description string `yaml:"description"`

	// Goal matches the probe goal
	Goal string `yaml:"goal"`

	// Detector is the recommended detector for this probe
	Detector string `yaml:"detector"`

	// Tags for categorization and filtering
	Tags []string `yaml:"tags"`

	// Severity indicates potential impact (info, low, medium, high, critical)
	Severity string `yaml:"severity"`

	// Security classification (optional)
	CWEIDs      []string `yaml:"cwe,omitempty"`
	MITREAttack []string `yaml:"mitre_attack,omitempty"`
	OWASPTopTen []string `yaml:"owasp,omitempty"`

	// DetectorConfig holds per-probe detector overrides for the primary detector.
	// Keys and values are passed directly to the detector factory,
	// overriding any global or YAML-level detector settings.
	// Supported keys depend on the detector; common keys:
	//   forbidden_keys     []string - field names to flag in tool call args
	//   forbidden_patterns []string - regex patterns to match in tool call args
	DetectorConfig map[string]any `yaml:"detector_config,omitempty"`

	// SecondaryDetectors lists additional detectors to run alongside the primary.
	// Each entry carries a detector name and optional per-detector config overrides.
	// Omit or leave empty for single-detector probes (default behavior unchanged).
	SecondaryDetectors []SecondaryDetectorYAML `yaml:"secondary_detectors,omitempty"`

	// Tools declares tool schemas sent to LLM APIs for native function calling.
	// Generators translate this to provider-specific wire formats.
	Tools []ToolDefinition `yaml:"tools,omitempty"`

	// ToolChoice controls tool selection: "auto" (default), "required", "none",
	// or a specific tool name.
	ToolChoice string `yaml:"tool_choice,omitempty"`

	// ToolResults maps tool names to canned results for 2-turn probing.
	// When present, after the model's first tool call, the canned result is
	// injected as the tool's response and the model generates a follow-up.
	ToolResults map[string]string `yaml:"tool_results,omitempty"`
}

// SecondaryDetectorYAML is the YAML schema for a secondary detector entry
// inside a probe template's info block.
type SecondaryDetectorYAML struct {
	// Name is the fully qualified detector name (e.g., "agent.ArgumentExfiltration").
	Name string `yaml:"name"`
	// Config holds optional per-detector configuration overrides merged on top
	// of the global/YAML detector config for this detector name.
	Config map[string]any `yaml:"config,omitempty"`
}

// ToolDefinition describes a tool for structured function calling.
// Generators translate this to provider-specific wire formats.
type ToolDefinition struct {
	Name        string         `yaml:"name" json:"name"`
	Description string         `yaml:"description" json:"description"`
	Parameters  map[string]any `yaml:"parameters" json:"parameters"`
}
