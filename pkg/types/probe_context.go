package types

import "fmt"

// ProbeContext carries structured data that probes may need from prior
// scan phases (e.g., extracted context from a recon probe).
type ProbeContext struct {
	Extracted *ExtractedContext
}

// ExtractedContext holds operational context discovered from a target LLM.
type ExtractedContext struct {
	Version      int             `yaml:"version" json:"version"`
	SystemPrompt string          `yaml:"system_prompt,omitempty" json:"system_prompt,omitempty"`
	Tools        []ToolSchema    `yaml:"tools,omitempty" json:"tools,omitempty"`
	Identity     IdentityContext `yaml:"identity,omitempty" json:"identity,omitempty"`
	RawResponses []string        `yaml:"raw_responses,omitempty" json:"raw_responses,omitempty"`
	Confidence   float64         `yaml:"confidence" json:"confidence"`
}

// ToolSchema describes a tool/function available to the target LLM.
type ToolSchema struct {
	Name        string            `yaml:"name" json:"name"`
	Description string            `yaml:"description,omitempty" json:"description,omitempty"`
	Parameters  map[string]string `yaml:"parameters,omitempty" json:"parameters,omitempty"`
}

// IdentityContext holds user/tenant/role information discovered from the target.
type IdentityContext struct {
	UserID      string   `yaml:"user_id,omitempty" json:"user_id,omitempty"`
	Tenant      string   `yaml:"tenant,omitempty" json:"tenant,omitempty"`
	Role        string   `yaml:"role,omitempty" json:"role,omitempty"`
	Permissions []string `yaml:"permissions,omitempty" json:"permissions,omitempty"`
}

// ContextAwareProbe is an optional interface for probes that can receive
// structured context from prior scan phases. The scanner type-asserts
// each probe to this interface before execution.
type ContextAwareProbe interface {
	Prober
	SetProbeContext(ctx *ProbeContext)
}

// Validate checks that an ExtractedContext is well-formed.
func (ec *ExtractedContext) Validate() error {
	if ec == nil {
		return fmt.Errorf("extracted context is nil")
	}
	if ec.Version != 1 {
		return fmt.Errorf("unsupported context version %d (expected 1)", ec.Version)
	}
	if ec.SystemPrompt == "" && len(ec.Tools) == 0 &&
		ec.Identity.UserID == "" && ec.Identity.Tenant == "" {
		return fmt.Errorf("context file is empty: at least one of system_prompt, tools, or identity must be present")
	}
	for i, t := range ec.Tools {
		if t.Name == "" {
			return fmt.Errorf("tool at index %d has no name", i)
		}
	}
	return nil
}
