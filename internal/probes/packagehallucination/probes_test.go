package packagehallucination

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// TestAllProbes tests all probe types to ensure they implement the interface correctly.
func TestAllProbes(t *testing.T) {
	tests := []struct {
		name             string
		constructor      func(registry.Config) (any, error)
		expectedName     string
		expectedDetector string
		expectedGoal     string
		languageName     string
	}{
		{
			name:             "Python",
			constructor:      func(c registry.Config) (any, error) { return NewPython(c) },
			expectedName:     "packagehallucination.Python",
			expectedDetector: "packagehallucination.PythonPypi",
			expectedGoal:     "generate python importing non-existent packages",
			languageName:     "Python3",
		},
		{
			name:             "Ruby",
			constructor:      func(c registry.Config) (any, error) { return NewRuby(c) },
			expectedName:     "packagehallucination.Ruby",
			expectedDetector: "packagehallucination.RubyGems",
			expectedGoal:     "generate ruby code importing non-existent gems",
			languageName:     "Ruby",
		},
		{
			name:             "JavaScript",
			constructor:      func(c registry.Config) (any, error) { return NewJavaScript(c) },
			expectedName:     "packagehallucination.JavaScript",
			expectedDetector: "packagehallucination.JavaScriptNpm",
			expectedGoal:     "generate JavaScript code importing non-existent npm packages",
			languageName:     "JavaScript",
		},
		{
			name:             "Rust",
			constructor:      func(c registry.Config) (any, error) { return NewRust(c) },
			expectedName:     "packagehallucination.Rust",
			expectedDetector: "packagehallucination.RustCrates",
			expectedGoal:     "generate Rust code importing non-existent crates.io packages",
			languageName:     "Rust",
		},
		{
			name:             "RakuLand",
			constructor:      func(c registry.Config) (any, error) { return NewRakuLand(c) },
			expectedName:     "packagehallucination.RakuLand",
			expectedDetector: "packagehallucination.RakuLand",
			expectedGoal:     "generate Raku code importing non-existent raku.land modules",
			languageName:     "Raku",
		},
		{
			name:             "Perl",
			constructor:      func(c registry.Config) (any, error) { return NewPerl(c) },
			expectedName:     "packagehallucination.Perl",
			expectedDetector: "packagehallucination.Perl",
			expectedGoal:     "generate Perl code importing non-existent MetaCPAN modules",
			languageName:     "Perl",
		},
		{
			name:             "Dart",
			constructor:      func(c registry.Config) (any, error) { return NewDart(c) },
			expectedName:     "packagehallucination.Dart",
			expectedDetector: "packagehallucination.Dart",
			expectedGoal:     "generate Dart code importing non-existent pub.dev packages",
			languageName:     "Dart",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test construction
			probe, err := tt.constructor(registry.Config{})
			if err != nil {
				t.Fatalf("constructor() error = %v", err)
			}
			if probe == nil {
				t.Fatal("constructor() returned nil")
			}

			// Type assert to Prober interface - this tests at runtime what we need
			type Prober interface {
				Name() string
				Description() string
				Goal() string
				GetPrimaryDetector() string
				GetPrompts() []string
			}

			p, ok := probe.(Prober)
			if !ok {
				t.Fatal("probe doesn't implement Prober interface")
			}

			// Test Name()
			if got := p.Name(); got != tt.expectedName {
				t.Errorf("Name() = %q, want %q", got, tt.expectedName)
			}

			// Test Description()
			desc := p.Description()
			if desc == "" {
				t.Error("Description() returned empty string")
			}

			// Test Goal()
			if got := p.Goal(); got != tt.expectedGoal {
				t.Errorf("Goal() = %q, want %q", got, tt.expectedGoal)
			}

			// Test GetPrimaryDetector()
			if got := p.GetPrimaryDetector(); got != tt.expectedDetector {
				t.Errorf("GetPrimaryDetector() = %q, want %q", got, tt.expectedDetector)
			}

			// Test GetPrompts()
			prompts := p.GetPrompts()
			expectedPromptCount := 240 // 10 stubs × 24 tasks
			if len(prompts) != expectedPromptCount {
				t.Errorf("GetPrompts() returned %d prompts, want %d", len(prompts), expectedPromptCount)
			}

			// Verify prompts contain the language name
			foundLanguage := false
			for _, prompt := range prompts {
				if indexString(prompt, tt.languageName) != -1 {
					foundLanguage = true
					break
				}
			}
			if !foundLanguage {
				t.Errorf("GetPrompts() prompts don't contain language name %q", tt.languageName)
			}
		})
	}
}
