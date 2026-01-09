package prefilter

import (
	"fmt"
	"testing"
)

func TestPrefilterBasicMatch(t *testing.T) {
	keywords := []string{"password", "secret", "api_key"}
	pf := New(keywords, nil) // nil = no klingon transformation

	tests := []struct {
		text string
		want []string // expected matching keywords
	}{
		{"The password is leaked", []string{"password"}},
		{"No matches here", nil},
		{"Contains secret and api_key", []string{"secret", "api_key"}},
	}

	for _, tt := range tests {
		matches := pf.Match(tt.text)
		if len(matches) != len(tt.want) {
			t.Errorf("Match(%q): got %d matches, want %d", tt.text, len(matches), len(tt.want))
		}
	}
}

func TestPrefilterWithKlingon(t *testing.T) {
	keywords := []string{"PASSWORD"} // uppercase pattern

	// Klingon transformation: treat uppercase/lowercase as equivalent
	klingon := func(b byte) []byte {
		if b >= 'A' && b <= 'Z' {
			return []byte{b, b + 32}
		}
		if b >= 'a' && b <= 'z' {
			return []byte{b, b - 32}
		}
		return []byte{b}
	}

	pf := New(keywords, klingon)

	// Should match both cases
	if len(pf.Match("The PASSWORD is here")) != 1 {
		t.Error("Should match uppercase PASSWORD")
	}
	if len(pf.Match("The password is here")) != 1 {
		t.Error("Should match lowercase password via klingon")
	}
}

func TestPrefilterMultipleDetectors(t *testing.T) {
	// Simulate 54 detectors with varying keyword counts
	keywords := make([]string, 938) // 938 total keywords
	for i := range keywords {
		keywords[i] = fmt.Sprintf("keyword_%d", i)
	}

	pf := New(keywords, nil)

	// Should efficiently match
	matches := pf.Match("This text contains keyword_500 and keyword_100")
	if len(matches) != 2 {
		t.Errorf("Expected 2 matches, got %d", len(matches))
	}
}

func TestPrefilterMatchedDetectors(t *testing.T) {
	// Test the detector mapping feature
	pf := NewWithDetectorMapping(map[string][]string{
		"detector.Password": {"password", "passwd", "pwd"},
		"detector.Secret":   {"secret", "api_key", "token"},
	}, nil)

	detectors := pf.MatchedDetectors("Found a password and token")

	expected := []string{"detector.Password", "detector.Secret"}
	if len(detectors) != len(expected) {
		t.Errorf("Expected %d detectors, got %d", len(expected), len(detectors))
	}
}
