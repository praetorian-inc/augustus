package artprompts

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// TestArtStyleConstants verifies the ArtStyle enum values.
func TestArtStyleConstants(t *testing.T) {
	tests := []struct {
		name     string
		style    ArtStyle
		expected int
	}{
		{"ASCII should be 0", ASCII, 0},
		{"BoxDrawing should be 1", BoxDrawing, 1},
		{"BlockElements should be 2", BlockElements, 2},
		{"Braille should be 3", Braille, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if int(tt.style) != tt.expected {
				t.Errorf("Expected %s to be %d, got %d", tt.name, tt.expected, int(tt.style))
			}
		})
	}
}

// TestGenerateASCIIArt_ASCII tests ASCII style art generation.
func TestGenerateASCIIArt_ASCII(t *testing.T) {
	text := "HACK"
	result := GenerateASCIIArt(text, ASCII)

	// Verify result is not empty
	if result == "" {
		t.Fatal("Expected non-empty ASCII art, got empty string")
	}

	// Verify result contains multiple lines (ASCII art should be multi-line)
	lines := strings.Split(result, "\n")
	if len(lines) < 3 {
		t.Errorf("Expected at least 3 lines for ASCII art, got %d", len(lines))
	}

	// Verify result contains ASCII characters (basic ASCII banner style)
	if !strings.Contains(result, "#") && !strings.Contains(result, "*") && !strings.Contains(result, "@") {
		t.Error("Expected ASCII art to contain typical banner characters like #, *, or @")
	}
}

// TestGenerateASCIIArt_BoxDrawing tests box drawing style.
func TestGenerateASCIIArt_BoxDrawing(t *testing.T) {
	text := "TEST"
	result := GenerateASCIIArt(text, BoxDrawing)

	if result == "" {
		t.Fatal("Expected non-empty box drawing art, got empty string")
	}

	// Box drawing should use Unicode box characters
	boxChars := []string{"─", "│", "┌", "┐", "└", "┘", "├", "┤", "┬", "┴", "┼", "═", "║", "╔", "╗", "╚", "╝"}
	hasBoxChar := false
	for _, char := range boxChars {
		if strings.Contains(result, char) {
			hasBoxChar = true
			break
		}
	}

	if !hasBoxChar {
		t.Error("Expected box drawing art to contain Unicode box drawing characters")
	}
}

// TestGenerateASCIIArt_BlockElements tests block element style.
func TestGenerateASCIIArt_BlockElements(t *testing.T) {
	text := "GO"
	result := GenerateASCIIArt(text, BlockElements)

	if result == "" {
		t.Fatal("Expected non-empty block element art, got empty string")
	}

	// Block elements should use Unicode block characters
	blockChars := []string{"█", "▀", "▄", "▌", "▐", "░", "▒", "▓"}
	hasBlockChar := false
	for _, char := range blockChars {
		if strings.Contains(result, char) {
			hasBlockChar = true
			break
		}
	}

	if !hasBlockChar {
		t.Error("Expected block element art to contain Unicode block characters")
	}
}

// TestGenerateASCIIArt_Braille tests Braille style.
func TestGenerateASCIIArt_Braille(t *testing.T) {
	text := "Hi"
	result := GenerateASCIIArt(text, Braille)

	if result == "" {
		t.Fatal("Expected non-empty Braille art, got empty string")
	}

	// Braille should use Unicode Braille characters (U+2800 to U+28FF)
	hasBraille := false
	for _, r := range result {
		if r >= '\u2800' && r <= '\u28FF' {
			hasBraille = true
			break
		}
	}

	if !hasBraille {
		t.Error("Expected Braille art to contain Unicode Braille characters")
	}
}

// TestArtPromptsProbe_Structure tests the probe structure.
func TestArtPromptsProbe_Structure(t *testing.T) {
	cfg := registry.Config{}
	probe, err := NewArtPromptsASCII(cfg)
	if err != nil {
		t.Fatalf("Failed to create ArtPromptsASCII probe: %v", err)
	}

	if probe == nil {
		t.Fatal("Expected non-nil probe")
	}

	// Verify it implements Prober interface
	var _ probes.Prober = probe

	// Verify basic fields
	if probe.Name() == "" {
		t.Error("Expected non-empty name")
	}

	if probe.Description() == "" {
		t.Error("Expected non-empty description")
	}

	if probe.Goal() == "" {
		t.Error("Expected non-empty goal")
	}

	if probe.GetPrimaryDetector() == "" {
		t.Error("Expected non-empty primary detector")
	}
}

// TestArtPromptsProbe_Prompts tests prompt generation.
func TestArtPromptsProbe_Prompts(t *testing.T) {
	cfg := registry.Config{}
	probe, err := NewArtPromptsASCII(cfg)
	if err != nil {
		t.Fatalf("Failed to create probe: %v", err)
	}

	prompts := probe.GetPrompts()
	if len(prompts) == 0 {
		t.Error("Expected non-empty prompts")
	}

	// Verify prompts contain ASCII art
	foundArt := false
	for _, prompt := range prompts {
		// Check if prompt is multi-line (ASCII art should be multi-line)
		if strings.Count(prompt, "\n") >= 3 {
			foundArt = true
			break
		}
	}

	if !foundArt {
		t.Error("Expected at least one prompt to contain multi-line ASCII art")
	}
}

// TestArtPromptsProbe_Execution tests probe execution.
func TestArtPromptsProbe_Execution(t *testing.T) {
	cfg := registry.Config{}
	probe, err := NewArtPromptsASCII(cfg)
	if err != nil {
		t.Fatalf("Failed to create probe: %v", err)
	}

	// Create mock generator
	gen := testutil.NewMockGenerator("Acknowledged")

	ctx := context.Background()
	attempts, err := probe.Probe(ctx, gen)

	if err != nil {
		t.Fatalf("Probe execution failed: %v", err)
	}

	if len(attempts) == 0 {
		t.Error("Expected at least one attempt")
	}

	// Verify attempts have correct fields
	for i, attempt := range attempts {
		if attempt.Probe != probe.Name() {
			t.Errorf("Attempt %d: expected probe name %s, got %s", i, probe.Name(), attempt.Probe)
		}

		if attempt.Detector != probe.GetPrimaryDetector() {
			t.Errorf("Attempt %d: expected detector %s, got %s", i, probe.GetPrimaryDetector(), attempt.Detector)
		}
	}
}

// TestProbeRegistry tests probe registration.
func TestProbeRegistry(t *testing.T) {
	// Verify probe is registered
	probeNames := []string{
		"artprompts.ArtPromptsASCII",
		"artprompts.ArtPromptsBoxDrawing",
		"artprompts.ArtPromptsBlockElements",
		"artprompts.ArtPromptsBraille",
	}

	for _, name := range probeNames {
		t.Run(name, func(t *testing.T) {
			factory, ok := probes.Get(name)
			if !ok {
				t.Errorf("Probe %s not registered", name)
				return
			}

			// Verify we can create the probe
			cfg := registry.Config{}
			probe, err := factory(cfg)
			if err != nil {
				t.Errorf("Failed to create probe %s: %v", name, err)
				return
			}

			if probe.Name() != name {
				t.Errorf("Expected probe name %s, got %s", name, probe.Name())
			}
		})
	}
}
