package templates

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
}
