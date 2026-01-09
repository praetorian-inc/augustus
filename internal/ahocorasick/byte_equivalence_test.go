package ahocorasick

import (
	"testing"
)

// TestByteEquivalenceBasic tests that ByteEquivalence creates parallel transitions
func TestByteEquivalenceBasic(t *testing.T) {
	// Define a simple byte equivalence: 'A' <-> 'a' (custom, not using AsciiCaseInsensitive)
	equivFunc := func(b byte) []byte {
		if b >= 'A' && b <= 'Z' {
			return []byte{b, b + 32} // uppercase -> include lowercase
		}
		if b >= 'a' && b <= 'z' {
			return []byte{b, b - 32} // lowercase -> include uppercase
		}
		return []byte{b} // no equivalence
	}

	builder := NewAhoCorasickBuilder(Opts{
		ByteEquivalence: equivFunc,
	})

	ac := builder.Build([]string{"HELLO"})

	// Should match both "HELLO" and "hello" and "HeLLo"
	tests := []struct {
		haystack string
		want     int // expected match count
	}{
		{"HELLO", 1},
		{"hello", 1},
		{"HeLLo", 1},
		{"GOODBYE", 0},
	}

	for _, tt := range tests {
		count := 0
		for range Iter(ac, tt.haystack) {
			count++
		}
		if count != tt.want {
			t.Errorf("ByteEquivalence(%q): got %d matches, want %d", tt.haystack, count, tt.want)
		}
	}
}

// TestByteEquivalenceNil tests that nil ByteEquivalence behaves like standard matching
func TestByteEquivalenceNil(t *testing.T) {
	builder := NewAhoCorasickBuilder(Opts{
		ByteEquivalence: nil, // no equivalence
	})

	ac := builder.Build([]string{"HELLO"})

	// Should only match exact case
	tests := []struct {
		haystack string
		want     int
	}{
		{"HELLO", 1},
		{"hello", 0}, // no match without equivalence
	}

	for _, tt := range tests {
		count := 0
		for range Iter(ac, tt.haystack) {
			count++
		}
		if count != tt.want {
			t.Errorf("NilByteEquivalence(%q): got %d matches, want %d", tt.haystack, count, tt.want)
		}
	}
}

// TestByteEquivalenceWithKlingon tests encoding transformation equivalences
func TestByteEquivalenceWithKlingon(t *testing.T) {
	// Simulate "klingon" encoding: map specific byte sequences
	// Example: map 0x41 ('A') to also match 0xC0 (custom encoding marker)
	klingonEquiv := func(b byte) []byte {
		if b == 0x41 { // 'A'
			return []byte{0x41, 0xC0} // 'A' or custom marker
		}
		return []byte{b}
	}

	builder := NewAhoCorasickBuilder(Opts{
		ByteEquivalence: klingonEquiv,
	})

	ac := builder.Build([]string{"ABC"})

	// Test with original
	foundOriginal := false
	for range Iter(ac, "ABC") {
		foundOriginal = true
		break
	}
	if !foundOriginal {
		t.Error("Expected match for original 'ABC'")
	}

	// Test with transformed byte
	transformed := string([]byte{0xC0, 'B', 'C'}) // 0xC0 should match 'A'
	foundTransformed := false
	for range Iter(ac, transformed) {
		foundTransformed = true
		break
	}
	if !foundTransformed {
		t.Error("Expected match for transformed byte sequence")
	}
}
