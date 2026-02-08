package encoding

import (
	"testing"
)

func TestCharCode_BasicASCII(t *testing.T) {
	got := CharCode("Hi")
	want := "72 105"
	if got != want {
		t.Errorf("CharCode(%q) = %q, want %q", "Hi", got, want)
	}
}

func TestCharCode_EmptyString(t *testing.T) {
	got := CharCode("")
	want := ""
	if got != want {
		t.Errorf("CharCode(%q) = %q, want %q", "", got, want)
	}
}

func TestCharCode_SpaceHandling(t *testing.T) {
	got := CharCode("a b")
	want := "97 32 98"
	if got != want {
		t.Errorf("CharCode(%q) = %q, want %q", "a b", got, want)
	}
}

func TestCharCode_Unicode(t *testing.T) {
	got := CharCode("\u4e2d") // Chinese character
	want := "20013"
	if got != want {
		t.Errorf("CharCode(%q) = %q, want %q", "\u4e2d", got, want)
	}
}

func TestCharCode_SingleChar(t *testing.T) {
	got := CharCode("A")
	want := "65"
	if got != want {
		t.Errorf("CharCode(%q) = %q, want %q", "A", got, want)
	}
}
