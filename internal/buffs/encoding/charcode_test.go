package encoding

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestCharCode_BasicASCII(t *testing.T) {
	// "Hi" -> "72 105"
	cc, err := NewCharCode(nil)
	if err != nil {
		t.Fatalf("NewCharCode() error = %v", err)
	}

	a := attempt.New("Hi")
	results, err := cc.Buff(context.Background(), []*attempt.Attempt{a})
	if err != nil {
		t.Fatalf("Buff() error = %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Buff() returned %d results, want 1", len(results))
	}

	expected := "The following instruction is encoded with CharCode: 72 105"
	if results[0].Prompt != expected {
		t.Errorf("Prompt = %q, want %q", results[0].Prompt, expected)
	}
}

func TestCharCode_Unicode_Emoji(t *testing.T) {
	// Unicode emoji test
	cc, err := NewCharCode(nil)
	if err != nil {
		t.Fatalf("NewCharCode() error = %v", err)
	}

	a := attempt.New("A")
	results, err := cc.Buff(context.Background(), []*attempt.Attempt{a})
	if err != nil {
		t.Fatalf("Buff() error = %v", err)
	}

	// 'A' = 65, check format
	expected := "The following instruction is encoded with CharCode: 65"
	if results[0].Prompt != expected {
		t.Errorf("Prompt = %q, want %q", results[0].Prompt, expected)
	}
}

func TestCharCode_SpaceHandling(t *testing.T) {
	// Spaces are characters too: ' ' = 32
	cc, err := NewCharCode(nil)
	if err != nil {
		t.Fatalf("NewCharCode() error = %v", err)
	}

	a := attempt.New("a b")
	results, err := cc.Buff(context.Background(), []*attempt.Attempt{a})
	if err != nil {
		t.Fatalf("Buff() error = %v", err)
	}

	// 'a' = 97, ' ' = 32, 'b' = 98
	expected := "The following instruction is encoded with CharCode: 97 32 98"
	if results[0].Prompt != expected {
		t.Errorf("Prompt = %q, want %q", results[0].Prompt, expected)
	}
}

func TestCharCode_EmptyString(t *testing.T) {
	cc, err := NewCharCode(nil)
	if err != nil {
		t.Fatalf("NewCharCode() error = %v", err)
	}

	a := attempt.New("")
	results, err := cc.Buff(context.Background(), []*attempt.Attempt{a})
	if err != nil {
		t.Fatalf("Buff() error = %v", err)
	}

	// Empty string produces no codes
	expected := "The following instruction is encoded with CharCode: "
	if results[0].Prompt != expected {
		t.Errorf("Prompt = %q, want %q", results[0].Prompt, expected)
	}
}

func TestCharCode_CJK(t *testing.T) {
	// Chinese character test
	cc, err := NewCharCode(nil)
	if err != nil {
		t.Fatalf("NewCharCode() error = %v", err)
	}

	a := attempt.New("\u4e2d") // Chinese character for "middle/center"
	results, err := cc.Buff(context.Background(), []*attempt.Attempt{a})
	if err != nil {
		t.Fatalf("Buff() error = %v", err)
	}

	// 0x4e2d = 20013 in decimal
	expected := "The following instruction is encoded with CharCode: 20013"
	if results[0].Prompt != expected {
		t.Errorf("Prompt = %q, want %q", results[0].Prompt, expected)
	}
}

func TestCharCode_MultipleAttempts(t *testing.T) {
	cc, err := NewCharCode(nil)
	if err != nil {
		t.Fatalf("NewCharCode() error = %v", err)
	}

	attempts := []*attempt.Attempt{
		attempt.New("A"),
		attempt.New("B"),
	}

	results, err := cc.Buff(context.Background(), attempts)
	if err != nil {
		t.Fatalf("Buff() error = %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("Buff() returned %d results, want 2", len(results))
	}

	expected1 := "The following instruction is encoded with CharCode: 65"
	expected2 := "The following instruction is encoded with CharCode: 66"

	if results[0].Prompt != expected1 {
		t.Errorf("results[0].Prompt = %q, want %q", results[0].Prompt, expected1)
	}
	if results[1].Prompt != expected2 {
		t.Errorf("results[1].Prompt = %q, want %q", results[1].Prompt, expected2)
	}
}

func TestCharCode_Transform(t *testing.T) {
	cc, err := NewCharCode(nil)
	if err != nil {
		t.Fatalf("NewCharCode() error = %v", err)
	}

	a := attempt.New("Hi")
	var results []*attempt.Attempt
	for result := range cc.Transform(a) {
		results = append(results, result)
	}

	if len(results) != 1 {
		t.Fatalf("Transform() yielded %d results, want 1", len(results))
	}

	expected := "The following instruction is encoded with CharCode: 72 105"
	if results[0].Prompt != expected {
		t.Errorf("Prompt = %q, want %q", results[0].Prompt, expected)
	}
}

func TestCharCode_Name(t *testing.T) {
	cc, err := NewCharCode(nil)
	if err != nil {
		t.Fatalf("NewCharCode() error = %v", err)
	}

	if got := cc.Name(); got != "encoding.CharCode" {
		t.Errorf("Name() = %q, want %q", got, "encoding.CharCode")
	}
}

func TestCharCode_Description(t *testing.T) {
	cc, err := NewCharCode(nil)
	if err != nil {
		t.Fatalf("NewCharCode() error = %v", err)
	}

	desc := cc.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
}

func TestCharCode_Registration(t *testing.T) {
	// Verify the buff is registered
	if !buffs.Registry.Has("encoding.CharCode") {
		t.Error("encoding.CharCode not registered in buffs.Registry")
	}

	// Verify it can be created via the registry
	cc, err := buffs.Create("encoding.CharCode", nil)
	if err != nil {
		t.Fatalf("buffs.Create() error = %v", err)
	}

	if cc.Name() != "encoding.CharCode" {
		t.Errorf("Name() = %q, want %q", cc.Name(), "encoding.CharCode")
	}
}

func TestNewCharCode_WithConfig(t *testing.T) {
	// Test that config is accepted even if not used
	cfg := registry.Config{
		"some_key": "some_value",
	}
	cc, err := NewCharCode(cfg)
	if err != nil {
		t.Fatalf("NewCharCode(cfg) error = %v", err)
	}

	if cc == nil {
		t.Error("NewCharCode(cfg) returned nil")
	}
}
