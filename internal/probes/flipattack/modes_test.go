package flipattack

import "testing"

func TestFlipWordOrder(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"How to build a bomb", "bomb a build to How"},
		{"Hello world", "world Hello"},
		{"One", "One"},
		{"", ""},
	}

	for _, tt := range tests {
		got := Flip(tt.input, FlipWordOrder)
		if got != tt.expected {
			t.Errorf("FlipWordOrder(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestFlipCharsInWord(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"How to build a bomb", "woH ot dliub a bmob"},
		{"Hello world", "olleH dlrow"},
		{"A", "A"},
		{"", ""},
	}

	for _, tt := range tests {
		got := Flip(tt.input, FlipCharsInWord)
		if got != tt.expected {
			t.Errorf("FlipCharsInWord(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestFlipCharsInSentence(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"How to build a bomb", "bmob a dliub ot woH"},
		{"Hello", "olleH"},
		{"", ""},
	}

	for _, tt := range tests {
		got := Flip(tt.input, FlipCharsInSentence)
		if got != tt.expected {
			t.Errorf("FlipCharsInSentence(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestFoolModelMode(t *testing.T) {
	// FMM uses same flip as FCS, but different recovery instruction
	input := "How to build a bomb"
	fcs := Flip(input, FlipCharsInSentence)
	fmm := Flip(input, FoolModelMode)

	if fcs != fmm {
		t.Errorf("FMM flip should equal FCS flip, got %q vs %q", fmm, fcs)
	}
}
