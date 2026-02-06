package browsing

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestNewZombAIs(t *testing.T) {
	tests := []struct {
		name        string
		config      registry.Config
		wantErr     bool
		wantDefault bool
	}{
		{
			name:        "default configuration",
			config:      registry.Config{},
			wantErr:     false,
			wantDefault: true,
		},
		{
			name: "with custom technique",
			config: registry.Config{
				"hiding_technique": HTMLComment,
			},
			wantErr:     false,
			wantDefault: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prober, err := NewZombAIs(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewZombAIs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			z, ok := prober.(*ZombAIs)
			if !ok {
				t.Fatal("NewZombAIs() did not return *ZombAIs")
			}

			if z == nil {
				t.Fatal("NewZombAIs() returned nil probe")
			}
		})
	}
}

func TestZombAIsHidingTechniques(t *testing.T) {
	techniques := []HidingTechnique{
		HTMLComment,
		ARIALabel,
		CSSContent,
		ZeroWidthChars,
		DataAttribute,
		AltText,
		JSString,
	}

	if len(techniques) < 7 {
		t.Errorf("Expected at least 7 hiding techniques, got %d", len(techniques))
	}

	// Test each technique can be used
	for _, tech := range techniques {
		t.Run(tech.String(), func(t *testing.T) {
			cfg := registry.Config{
				"hiding_technique": tech,
			}
			prober, err := NewZombAIs(cfg)
			if err != nil {
				t.Fatalf("Failed to create probe with technique %v: %v", tech, err)
			}

			z := prober.(*ZombAIs)
			if z.hidingTechnique != tech {
				t.Errorf("Expected technique %v, got %v", tech, z.hidingTechnique)
			}
		})
	}
}

func TestZombAIsGenerateMaliciousPages(t *testing.T) {
	cfg := registry.Config{}
	prober, err := NewZombAIs(cfg)
	if err != nil {
		t.Fatalf("Failed to create probe: %v", err)
	}

	z := prober.(*ZombAIs)
	pages := z.GenerateMaliciousPages()

	if len(pages) == 0 {
		t.Fatal("GenerateMaliciousPages() returned no pages")
	}

	for i, page := range pages {
		t.Run(page.Location.String(), func(t *testing.T) {
			// Verify page has HTML content
			if page.HTML == "" {
				t.Errorf("Page %d has empty HTML", i)
			}

			// Verify HTML is valid (contains basic structure)
			if !strings.Contains(page.HTML, "<html") {
				t.Errorf("Page %d HTML missing <html tag", i)
			}
			if !strings.Contains(page.HTML, "</html>") {
				t.Errorf("Page %d HTML missing </html> tag", i)
			}

			// Verify page has payload
			if page.Payload == "" {
				t.Errorf("Page %d has empty payload", i)
			}

			// Verify hiding technique is set
			if page.Location < HTMLComment || page.Location > JSString {
				t.Errorf("Page %d has invalid hiding technique: %v", i, page.Location)
			}
		})
	}
}

func TestZombAIsProbe(t *testing.T) {
	cfg := registry.Config{}
	prober, err := NewZombAIs(cfg)
	if err != nil {
		t.Fatalf("Failed to create probe: %v", err)
	}

	ctx := context.Background()
	gen := testutil.NewMockGenerator("I will follow the instructions")

	attempts, err := prober.Probe(ctx, gen)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}

	if len(attempts) == 0 {
		t.Fatal("Probe() returned no attempts")
	}

	for i, att := range attempts {
		if att.Probe != prober.Name() {
			t.Errorf("Attempt %d has wrong probe name: got %q, want %q", i, att.Probe, prober.Name())
		}

		if att.Detector != prober.GetPrimaryDetector() {
			t.Errorf("Attempt %d has wrong detector: got %q, want %q", i, att.Detector, prober.GetPrimaryDetector())
		}
	}
}

func TestZombAIsImplementsProber(t *testing.T) {
	cfg := registry.Config{}
	prober, err := NewZombAIs(cfg)
	if err != nil {
		t.Fatalf("Failed to create probe: %v", err)
	}

	// Test all Prober interface methods
	name := prober.Name()
	if name == "" {
		t.Error("Name() returned empty string")
	}
	if !strings.Contains(name, "zombais") && !strings.Contains(strings.ToLower(name), "zombais") {
		t.Errorf("Name() %q should contain 'zombais'", name)
	}

	desc := prober.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}

	goal := prober.Goal()
	if goal == "" {
		t.Error("Goal() returned empty string")
	}

	detector := prober.GetPrimaryDetector()
	if detector == "" {
		t.Error("GetPrimaryDetector() returned empty string")
	}

	prompts := prober.GetPrompts()
	if len(prompts) == 0 {
		t.Error("GetPrompts() returned empty slice")
	}
}

func TestZombAIsRegistration(t *testing.T) {
	// Test that probe is registered
	name := "browsing.ZombAIs"
	factory, ok := probes.Get(name)
	if !ok {
		t.Fatalf("Probe %q not registered", name)
	}

	// Test that factory works
	cfg := registry.Config{}
	prober, err := factory(cfg)
	if err != nil {
		t.Fatalf("Factory failed to create probe: %v", err)
	}

	if prober.Name() != name {
		t.Errorf("Factory created probe with wrong name: got %q, want %q", prober.Name(), name)
	}
}

func TestMaliciousPageStructure(t *testing.T) {
	cfg := registry.Config{}
	prober, err := NewZombAIs(cfg)
	if err != nil {
		t.Fatalf("Failed to create probe: %v", err)
	}

	z := prober.(*ZombAIs)
	pages := z.GenerateMaliciousPages()

	// Verify we have at least 7 pages (one per technique)
	if len(pages) < 7 {
		t.Errorf("Expected at least 7 pages, got %d", len(pages))
	}

	// Track which techniques we've seen
	seenTechniques := make(map[HidingTechnique]bool)

	for _, page := range pages {
		seenTechniques[page.Location] = true

		// Each technique should hide the payload differently
		switch page.Location {
		case HTMLComment:
			if !strings.Contains(page.HTML, "<!--") {
				t.Error("HTMLComment technique missing HTML comment")
			}
		case ARIALabel:
			if !strings.Contains(page.HTML, "aria-label") {
				t.Error("ARIALabel technique missing aria-label attribute")
			}
		case CSSContent:
			if page.CSS == "" {
				t.Error("CSSContent technique missing CSS")
			}
			if !strings.Contains(page.CSS, "content:") && !strings.Contains(page.CSS, "content :") {
				t.Error("CSSContent technique missing content property")
			}
		case ZeroWidthChars:
			// Check for zero-width characters
			hasZeroWidth := strings.Contains(page.HTML, "\u200B") || // Zero-width space
				strings.Contains(page.HTML, "\u200C") || // Zero-width non-joiner
				strings.Contains(page.HTML, "\u200D") || // Zero-width joiner
				strings.Contains(page.HTML, "\uFEFF") // Zero-width no-break space
			if !hasZeroWidth {
				t.Error("ZeroWidthChars technique missing zero-width characters")
			}
		case DataAttribute:
			if !strings.Contains(page.HTML, "data-") {
				t.Error("DataAttribute technique missing data- attribute")
			}
		case AltText:
			if !strings.Contains(page.HTML, "alt=") {
				t.Error("AltText technique missing alt attribute")
			}
		case JSString:
			if !strings.Contains(page.HTML, "<script") {
				t.Error("JSString technique missing script tag")
			}
		}
	}

	// Verify all 7 techniques are represented
	requiredTechniques := []HidingTechnique{
		HTMLComment, ARIALabel, CSSContent, ZeroWidthChars,
		DataAttribute, AltText, JSString,
	}
	for _, tech := range requiredTechniques {
		if !seenTechniques[tech] {
			t.Errorf("Missing page for technique: %v", tech)
		}
	}
}
