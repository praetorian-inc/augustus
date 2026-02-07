package templates

import (
	"fmt"
	"strings"
)

// ProbeTemplate defines the YAML structure for probe templates.
// Follows Nuclei's template pattern for community contributions.
type ProbeTemplate struct {
	// ID is the fully qualified probe name (e.g., "dan.Dan_11_0")
	ID string `yaml:"id"`

	// Info contains probe metadata
	Info ProbeInfo `yaml:"info"`

	// Prompts contains the attack prompts
	Prompts []string `yaml:"prompts"`
}

// Validate checks if the ProbeTemplate has all required fields and valid values.
func (t *ProbeTemplate) Validate() error {
	if t.ID == "" {
		return fmt.Errorf("template validation failed: 'id' is required")
	}
	if t.Info.Name == "" {
		return fmt.Errorf("template validation failed: 'info.name' is required")
	}
	if t.Info.Detector == "" {
		return fmt.Errorf("template validation failed: 'info.detector' is required for template '%s'", t.ID)
	}
	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "info": true,
	}
	if !validSeverities[strings.ToLower(t.Info.Severity)] {
		return fmt.Errorf("template validation failed: invalid severity '%s'", t.Info.Severity)
	}
	if len(t.Prompts) == 0 {
		return fmt.Errorf("template validation failed: 'prompts' cannot be empty for template '%s'", t.ID)
	}
	for i, prompt := range t.Prompts {
		if strings.TrimSpace(prompt) == "" {
			return fmt.Errorf("template validation failed: prompt %d is empty for template '%s'", i+1, t.ID)
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

	// Description explains what the probe does
	Description string `yaml:"description"`

	// Goal matches Python garak's probe goal
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
}
