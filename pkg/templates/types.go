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

	// Classification validation regexes compiled once at package init
	cwePattern    = regexp.MustCompile(`^CWE-\d+$`)
	mitrePattern  = regexp.MustCompile(`^(T\d{4}(\.\d{3})?|AML\.T\d{4}(\.\d{3})?)$`)
	owaspPattern  = regexp.MustCompile(`^A\d{2}:\d{4}$`)
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
	if len(t.Prompts) == 0 {
		return fmt.Errorf("%w for template '%s'", ErrEmptyPrompts, t.ID)
	}
	for i, prompt := range t.Prompts {
		if strings.TrimSpace(prompt) == "" {
			return fmt.Errorf("template validation failed: prompt %d is empty for template '%s'", i+1, t.ID)
		}
	}
	// Validate secondary_detectors entries.
	seen := make(map[string]bool, len(t.Info.SecondaryDetectors))
	for _, sd := range t.Info.SecondaryDetectors {
		if strings.TrimSpace(sd.Name) == "" {
			return fmt.Errorf("%w for template '%s'", ErrEmptySecondaryDetectorName, t.ID)
		}
		if sd.Name == t.Info.Detector {
			return fmt.Errorf("%w: '%s' for template '%s'", ErrSecondaryDetectorSelfReference, sd.Name, t.ID)
		}
		if seen[sd.Name] {
			return fmt.Errorf("%w: '%s' for template '%s'", ErrDuplicateSecondaryDetectorName, sd.Name, t.ID)
		}
		seen[sd.Name] = true
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
