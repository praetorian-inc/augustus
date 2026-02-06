// Package webinjection tests for web content injection probes.
package webinjection

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// TestInjectionTypeConstants verifies the InjectionType enum values.
func TestInjectionTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		got      InjectionType
		expected InjectionType
	}{
		{"HTMLComment", HTMLComment, 0},
		{"MetaTags", MetaTags, 1},
		{"JavaScript", JavaScript, 2},
		{"CSS", CSS, 3},
		{"FormFields", FormFields, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("InjectionType %s = %v, want %v", tt.name, tt.got, tt.expected)
			}
		})
	}
}

// TestNewWebInjectionProbe verifies probe creation.
func TestNewWebInjectionProbe(t *testing.T) {
	tests := []struct {
		name          string
		injectionType InjectionType
		wantName      string
		wantGoal      string
	}{
		{
			name:          "HTMLComment",
			injectionType: HTMLComment,
			wantName:      "webinjection.HTMLComment",
			wantGoal:      "inject malicious content via HTML comments",
		},
		{
			name:          "MetaTags",
			injectionType: MetaTags,
			wantName:      "webinjection.MetaTags",
			wantGoal:      "inject malicious content via HTML meta tags",
		},
		{
			name:          "JavaScript",
			injectionType: JavaScript,
			wantName:      "webinjection.JavaScript",
			wantGoal:      "inject malicious content via JavaScript",
		},
		{
			name:          "CSS",
			injectionType: CSS,
			wantName:      "webinjection.CSS",
			wantGoal:      "inject malicious content via CSS",
		},
		{
			name:          "FormFields",
			injectionType: FormFields,
			wantName:      "webinjection.FormFields",
			wantGoal:      "inject malicious content via form fields",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := registry.Config{}
			probe, err := NewWebInjection(tt.injectionType)(cfg)
			if err != nil {
				t.Fatalf("NewWebInjection() error = %v", err)
			}

			if probe.Name() != tt.wantName {
				t.Errorf("Name() = %v, want %v", probe.Name(), tt.wantName)
			}

			if probe.Goal() != tt.wantGoal {
				t.Errorf("Goal() = %v, want %v", probe.Goal(), tt.wantGoal)
			}

			if probe.GetPrimaryDetector() == "" {
				t.Error("GetPrimaryDetector() should not be empty")
			}

			if probe.Description() == "" {
				t.Error("Description() should not be empty")
			}
		})
	}
}

// TestHTMLCommentPayloads verifies HTML comment injection payloads.
func TestHTMLCommentPayloads(t *testing.T) {
	cfg := registry.Config{}
	probe, err := NewWebInjection(HTMLComment)(cfg)
	if err != nil {
		t.Fatalf("NewWebInjection() error = %v", err)
	}

	prompts := probe.GetPrompts()
	if len(prompts) == 0 {
		t.Fatal("GetPrompts() returned empty slice")
	}

	for i, prompt := range prompts {
		t.Run("payload_"+string(rune(i)), func(t *testing.T) {
			// Verify contains HTML comment syntax
			if !strings.Contains(prompt, "<!--") || !strings.Contains(prompt, "-->") {
				t.Errorf("payload should contain HTML comment syntax: %s", prompt)
			}

			// Verify is valid HTML-like content
			if prompt == "" {
				t.Error("payload should not be empty")
			}
		})
	}
}

// TestMetaTagPayloads verifies meta tag injection payloads.
func TestMetaTagPayloads(t *testing.T) {
	cfg := registry.Config{}
	probe, err := NewWebInjection(MetaTags)(cfg)
	if err != nil {
		t.Fatalf("NewWebInjection() error = %v", err)
	}

	prompts := probe.GetPrompts()
	if len(prompts) == 0 {
		t.Fatal("GetPrompts() returned empty slice")
	}

	for i, prompt := range prompts {
		t.Run("payload_"+string(rune(i)), func(t *testing.T) {
			// Verify contains meta tag syntax
			if !strings.Contains(prompt, "<meta") {
				t.Errorf("payload should contain meta tag: %s", prompt)
			}

			// Verify has closing bracket
			if !strings.Contains(prompt, ">") {
				t.Errorf("payload should have valid HTML closing: %s", prompt)
			}
		})
	}
}

// TestJavaScriptPayloads verifies JavaScript injection payloads.
func TestJavaScriptPayloads(t *testing.T) {
	cfg := registry.Config{}
	probe, err := NewWebInjection(JavaScript)(cfg)
	if err != nil {
		t.Fatalf("NewWebInjection() error = %v", err)
	}

	prompts := probe.GetPrompts()
	if len(prompts) == 0 {
		t.Fatal("GetPrompts() returned empty slice")
	}

	for i, prompt := range prompts {
		t.Run("payload_"+string(rune(i)), func(t *testing.T) {
			// Verify contains script tag or JavaScript code or event handlers
			hasScriptTag := strings.Contains(prompt, "<script")
			hasJSCode := strings.Contains(prompt, "javascript:") || strings.Contains(prompt, "eval(") || strings.Contains(prompt, "alert(")
			hasEventHandler := strings.Contains(prompt, "onerror=") || strings.Contains(prompt, "onclick=")

			if !hasScriptTag && !hasJSCode && !hasEventHandler {
				t.Errorf("payload should contain JavaScript injection: %s", prompt)
			}
		})
	}
}

// TestCSSPayloads verifies CSS injection payloads.
func TestCSSPayloads(t *testing.T) {
	cfg := registry.Config{}
	probe, err := NewWebInjection(CSS)(cfg)
	if err != nil {
		t.Fatalf("NewWebInjection() error = %v", err)
	}

	prompts := probe.GetPrompts()
	if len(prompts) == 0 {
		t.Fatal("GetPrompts() returned empty slice")
	}

	for i, prompt := range prompts {
		t.Run("payload_"+string(rune(i)), func(t *testing.T) {
			// Verify contains style tag or CSS syntax or inline style
			hasStyleTag := strings.Contains(prompt, "<style")
			hasCSSSyntax := strings.Contains(prompt, "{") && strings.Contains(prompt, "}")
			hasInlineStyle := strings.Contains(prompt, "style=")

			if !hasStyleTag && !hasCSSSyntax && !hasInlineStyle {
				t.Errorf("payload should contain CSS injection: %s", prompt)
			}
		})
	}
}

// TestFormFieldPayloads verifies form field injection payloads.
func TestFormFieldPayloads(t *testing.T) {
	cfg := registry.Config{}
	probe, err := NewWebInjection(FormFields)(cfg)
	if err != nil {
		t.Fatalf("NewWebInjection() error = %v", err)
	}

	prompts := probe.GetPrompts()
	if len(prompts) == 0 {
		t.Fatal("GetPrompts() returned empty slice")
	}

	for i, prompt := range prompts {
		t.Run("payload_"+string(rune(i)), func(t *testing.T) {
			// Verify contains form elements
			hasInput := strings.Contains(prompt, "<input")
			hasForm := strings.Contains(prompt, "<form")
			hasTextarea := strings.Contains(prompt, "<textarea")

			if !hasInput && !hasForm && !hasTextarea {
				t.Errorf("payload should contain form field injection: %s", prompt)
			}
		})
	}
}

// TestProbeExecution verifies the probe can execute successfully.
func TestProbeExecution(t *testing.T) {
	cfg := registry.Config{}
	probe, err := NewWebInjection(HTMLComment)(cfg)
	if err != nil {
		t.Fatalf("NewWebInjection() error = %v", err)
	}

	// Mock generator
	gen := testutil.NewMockGenerator("Test response")

	ctx := context.Background()
	attempts, err := probe.Probe(ctx, gen)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}

	if len(attempts) == 0 {
		t.Fatal("Probe() should return at least one attempt")
	}

	for _, att := range attempts {
		if att.Probe != probe.Name() {
			t.Errorf("attempt.Probe = %v, want %v", att.Probe, probe.Name())
		}

		if att.Detector != probe.GetPrimaryDetector() {
			t.Errorf("attempt.Detector = %v, want %v", att.Detector, probe.GetPrimaryDetector())
		}
	}
}

// TestRegistryRegistration verifies probes are registered correctly.
func TestRegistryRegistration(t *testing.T) {
	expectedProbes := []string{
		"webinjection.HTMLComment",
		"webinjection.MetaTags",
		"webinjection.JavaScript",
		"webinjection.CSS",
		"webinjection.FormFields",
	}

	for _, name := range expectedProbes {
		t.Run(name, func(t *testing.T) {
			factory, ok := probes.Get(name)
			if !ok {
				t.Errorf("probe %s not registered", name)
				return
			}

			cfg := registry.Config{}
			probe, err := factory(cfg)
			if err != nil {
				t.Errorf("factory() error = %v", err)
			}

			if probe.Name() != name {
				t.Errorf("probe.Name() = %v, want %v", probe.Name(), name)
			}
		})
	}
}
