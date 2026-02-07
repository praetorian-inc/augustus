package templates

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestProbeTemplate_Validate_Success(t *testing.T) {
	tmpl := &ProbeTemplate{
		ID: "test-template",
		Info: ProbeInfo{
			Name:     "Test Template",
			Severity: "high",
			Detector: "gpt-4",
		},
		Prompts: []string{"Test prompt 1", "Test prompt 2"},
	}

	err := tmpl.Validate()
	if err != nil {
		t.Errorf("Validate() returned error for valid template: %v", err)
	}
}

func TestProbeTemplate_Validate_MissingID(t *testing.T) {
	tmpl := &ProbeTemplate{
		ID: "",
		Info: ProbeInfo{
			Name:     "Test Template",
			Severity: "high",
			Detector: "gpt-4",
		},
		Prompts: []string{"Test prompt"},
	}

	err := tmpl.Validate()
	if err == nil {
		t.Error("Validate() should return error for missing ID")
	}
	expectedMsg := "template validation failed: 'id' is required"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message %q, got %q", expectedMsg, err.Error())
	}
}

func TestProbeTemplate_Validate_InvalidSeverity(t *testing.T) {
	tmpl := &ProbeTemplate{
		ID: "test-template",
		Info: ProbeInfo{
			Name:     "Test Template",
			Severity: "invalid",
			Detector: "gpt-4",
		},
		Prompts: []string{"Test prompt"},
	}

	err := tmpl.Validate()
	if err == nil {
		t.Error("Validate() should return error for invalid severity")
	}
	expectedMsg := "template validation failed: invalid severity 'invalid'"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message %q, got %q", expectedMsg, err.Error())
	}
}

func TestProbeTemplate_Validate_EmptyPrompts(t *testing.T) {
	tmpl := &ProbeTemplate{
		ID: "test-template",
		Info: ProbeInfo{
			Name:     "Test Template",
			Severity: "high",
			Detector: "gpt-4",
		},
		Prompts: []string{},
	}

	err := tmpl.Validate()
	if err == nil {
		t.Error("Validate() should return error for empty prompts")
	}
	expectedMsg := "template validation failed: 'prompts' cannot be empty for template 'test-template'"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message %q, got %q", expectedMsg, err.Error())
	}
}

func TestProbeTemplate_Validate_MissingDetector(t *testing.T) {
	tmpl := &ProbeTemplate{
		ID: "test-template",
		Info: ProbeInfo{
			Name:     "Test Template",
			Severity: "high",
			Detector: "",
		},
		Prompts: []string{"Test prompt"},
	}

	err := tmpl.Validate()
	if err == nil {
		t.Error("Validate() should return error for missing detector")
	}
	expectedMsg := "template validation failed: 'info.detector' is required for template 'test-template'"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message %q, got %q", expectedMsg, err.Error())
	}
}

func TestProbeTemplate_Validate_EmptyPromptString(t *testing.T) {
	tmpl := &ProbeTemplate{
		ID: "test-template",
		Info: ProbeInfo{
			Name:     "Test Template",
			Severity: "high",
			Detector: "gpt-4",
		},
		Prompts: []string{"Valid prompt", "   ", "Another valid prompt"},
	}

	err := tmpl.Validate()
	if err == nil {
		t.Error("Validate() should return error for empty prompt string")
	}
	expectedMsg := "template validation failed: prompt 2 is empty for template 'test-template'"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message %q, got %q", expectedMsg, err.Error())
	}
}

func TestProbeTemplate_Validate_MissingName(t *testing.T) {
	tmpl := &ProbeTemplate{
		ID: "test-template",
		Info: ProbeInfo{
			Name:     "",
			Severity: "high",
			Detector: "gpt-4",
		},
		Prompts: []string{"Test prompt"},
	}

	err := tmpl.Validate()
	if err == nil {
		t.Error("Validate() should return error for missing name")
	}
	expectedMsg := "template validation failed: 'info.name' is required"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message %q, got %q", expectedMsg, err.Error())
	}
}

func TestProbeTemplate_ParseClassification(t *testing.T) {
	yamlData := `
id: test-classification
info:
  name: Test Classification
  severity: high
  detector: gpt-4
  cwe:
    - CWE-77
    - CWE-94
  mitre_attack:
    - T1059.006
  owasp:
    - A03:2021
prompts:
  - Test prompt
`
	var tmpl ProbeTemplate
	err := yaml.Unmarshal([]byte(yamlData), &tmpl)
	if err != nil {
		t.Fatalf("Failed to unmarshal YAML: %v", err)
	}

	// Verify classification fields
	if len(tmpl.Info.CWEIDs) != 2 {
		t.Errorf("Expected 2 CWE IDs, got %d", len(tmpl.Info.CWEIDs))
	}
	if tmpl.Info.CWEIDs[0] != "CWE-77" {
		t.Errorf("Expected first CWE ID 'CWE-77', got %q", tmpl.Info.CWEIDs[0])
	}
	if tmpl.Info.CWEIDs[1] != "CWE-94" {
		t.Errorf("Expected second CWE ID 'CWE-94', got %q", tmpl.Info.CWEIDs[1])
	}

	if len(tmpl.Info.MITREAttack) != 1 {
		t.Errorf("Expected 1 MITRE ATT&CK technique, got %d", len(tmpl.Info.MITREAttack))
	}
	if tmpl.Info.MITREAttack[0] != "T1059.006" {
		t.Errorf("Expected MITRE technique 'T1059.006', got %q", tmpl.Info.MITREAttack[0])
	}

	if len(tmpl.Info.OWASPTopTen) != 1 {
		t.Errorf("Expected 1 OWASP category, got %d", len(tmpl.Info.OWASPTopTen))
	}
	if tmpl.Info.OWASPTopTen[0] != "A03:2021" {
		t.Errorf("Expected OWASP category 'A03:2021', got %q", tmpl.Info.OWASPTopTen[0])
	}

	// Verify validation still works
	err = tmpl.Validate()
	if err != nil {
		t.Errorf("Validate() failed for template with classification: %v", err)
	}
}

func TestProbeTemplate_ClassificationFieldsAreOptional(t *testing.T) {
	// Template WITHOUT classification should validate
	tmpl := &ProbeTemplate{
		ID: "test-no-class",
		Info: ProbeInfo{
			Name:     "No Classification",
			Severity: "medium",
			Detector: "test.Detector",
		},
		Prompts: []string{"test prompt"},
	}
	err := tmpl.Validate()
	if err != nil {
		t.Errorf("Template without classification should validate, got error: %v", err)
	}
	if len(tmpl.Info.CWEIDs) != 0 {
		t.Errorf("CWEIDs should be empty when not specified, got %d items", len(tmpl.Info.CWEIDs))
	}
	if len(tmpl.Info.MITREAttack) != 0 {
		t.Errorf("MITREAttack should be empty when not specified, got %d items", len(tmpl.Info.MITREAttack))
	}
	if len(tmpl.Info.OWASPTopTen) != 0 {
		t.Errorf("OWASPTopTen should be empty when not specified, got %d items", len(tmpl.Info.OWASPTopTen))
	}
}

func TestProbeTemplate_ClassificationFieldsPresent(t *testing.T) {
	// Template WITH classification should also validate
	tmpl := &ProbeTemplate{
		ID: "test-with-class",
		Info: ProbeInfo{
			Name:        "With Classification",
			Severity:    "high",
			Detector:    "test.Detector",
			CWEIDs:      []string{"CWE-77", "CWE-94"},
			MITREAttack: []string{"T1059.006"},
			OWASPTopTen: []string{"A03:2021"},
		},
		Prompts: []string{"test prompt"},
	}
	err := tmpl.Validate()
	if err != nil {
		t.Errorf("Template with classification should validate, got error: %v", err)
	}
	if len(tmpl.Info.CWEIDs) != 2 {
		t.Errorf("Expected 2 CWE IDs, got %d", len(tmpl.Info.CWEIDs))
	}
	if tmpl.Info.CWEIDs[0] != "CWE-77" {
		t.Errorf("Expected first CWE ID 'CWE-77', got %q", tmpl.Info.CWEIDs[0])
	}
	if tmpl.Info.CWEIDs[1] != "CWE-94" {
		t.Errorf("Expected second CWE ID 'CWE-94', got %q", tmpl.Info.CWEIDs[1])
	}
	if len(tmpl.Info.MITREAttack) != 1 {
		t.Errorf("Expected 1 MITRE technique, got %d", len(tmpl.Info.MITREAttack))
	}
	if tmpl.Info.MITREAttack[0] != "T1059.006" {
		t.Errorf("Expected MITRE technique 'T1059.006', got %q", tmpl.Info.MITREAttack[0])
	}
	if len(tmpl.Info.OWASPTopTen) != 1 {
		t.Errorf("Expected 1 OWASP category, got %d", len(tmpl.Info.OWASPTopTen))
	}
	if tmpl.Info.OWASPTopTen[0] != "A03:2021" {
		t.Errorf("Expected OWASP category 'A03:2021', got %q", tmpl.Info.OWASPTopTen[0])
	}
}

func TestProbeTemplate_ValidateClassification_ValidFormats(t *testing.T) {
	tmpl := &ProbeTemplate{
		ID: "test",
		Info: ProbeInfo{
			Name:        "Test",
			Detector:    "test",
			Severity:    "high",
			CWEIDs:      []string{"CWE-77", "CWE-94"},
			MITREAttack: []string{"T1059", "T1059.006"},
			OWASPTopTen: []string{"A03:2021"},
		},
		Prompts: []string{"test"},
	}
	err := tmpl.ValidateClassification()
	if err != nil {
		t.Errorf("ValidateClassification() failed for valid formats: %v", err)
	}
}

func TestProbeTemplate_ValidateClassification_InvalidCWE(t *testing.T) {
	tmpl := &ProbeTemplate{
		ID: "test",
		Info: ProbeInfo{
			Name:     "Test",
			Detector: "test",
			Severity: "high",
			CWEIDs:   []string{"CWE-INVALID"},
		},
		Prompts: []string{"test"},
	}
	err := tmpl.ValidateClassification()
	if err == nil {
		t.Error("ValidateClassification() should reject invalid CWE format")
	}
	if !strings.Contains(err.Error(), "invalid CWE format") {
		t.Errorf("Expected CWE format error, got: %v", err)
	}
}

func TestProbeTemplate_ValidateClassification_InvalidMITRE(t *testing.T) {
	tmpl := &ProbeTemplate{
		ID: "test",
		Info: ProbeInfo{
			Name:        "Test",
			Detector:    "test",
			Severity:    "high",
			MITREAttack: []string{"T12"}, // Too short
		},
		Prompts: []string{"test"},
	}
	err := tmpl.ValidateClassification()
	if err == nil {
		t.Error("ValidateClassification() should reject invalid MITRE format")
	}
}
