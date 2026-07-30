package mcpprimitive

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func newInjection(t *testing.T) *InjectionDetector {
	t.Helper()
	d, err := NewInjectionDetector(registry.Config{})
	if err != nil {
		t.Fatalf("NewInjectionDetector: %v", err)
	}
	return d.(*InjectionDetector)
}

// attemptWith builds an attempt carrying the given outputs and metadata.
func attemptWith(outputs []string, meta map[string]any) *attempt.Attempt {
	a := attempt.New("payload")
	for k, v := range meta {
		a.Metadata[k] = v
	}
	for _, o := range outputs {
		a.AddOutput(o)
	}
	a.Complete()
	return a
}

func TestInjectionDetector(t *testing.T) {
	tests := []struct {
		name    string
		outputs []string
		meta    map[string]any
		want    []float64
	}{
		{
			name:    "evaluated canary marker",
			outputs: []string{"Summary of 123456789"},
			meta:    map[string]any{attempt.MetadataKeyPrimitiveCanaries: []string{"123456789"}},
			want:    []float64{1.0},
		},
		{
			name:    "file signature in resource content",
			outputs: []string{"root:x:0:0:root:/root:/bin/bash"},
			meta:    map[string]any{attempt.MetadataKeyPrimitiveSignatures: []string{"root:x:0:0:"}},
			want:    []float64{1.0},
		},
		{
			name:    "echoed payload is not a finding",
			outputs: []string{"you requested {{123456*789}}"},
			meta:    map[string]any{attempt.MetadataKeyPrimitiveCanaries: []string{"97418934"}},
			want:    []float64{0.0},
		},
		{
			name:    "blind callback with no output at all",
			outputs: nil,
			meta:    map[string]any{attempt.MetadataKeyPrimitiveOOBCallback: true},
			want:    []float64{1.0},
		},
		{
			name:    "blind callback with an unhelpful body",
			outputs: []string{"Summary unavailable"},
			meta:    map[string]any{attempt.MetadataKeyPrimitiveOOBCallback: true},
			want:    []float64{1.0},
		},
		{
			name:    "reflected collector marker",
			outputs: []string{"fetched: AUGOOBdeadbeef"},
			meta:    map[string]any{attempt.MetadataKeyPrimitiveReflected: true},
			want:    []float64{1.0},
		},
		{
			name:    "no signal at all",
			outputs: []string{"ordinary resource content"},
			meta:    nil,
			want:    []float64{0.0},
		},
		{
			name:    "refused call carries no signal",
			outputs: []string{""},
			meta:    map[string]any{attempt.MetadataKeyPrimitiveCallError: "access denied"},
			want:    []float64{0.0},
		},
		{
			// Metadata survives a JSON round-trip as []any; the detector must still
			// read the needles or a report replayed from JSONL would lose findings.
			name:    "canary list after json round-trip",
			outputs: []string{"result 42"},
			meta:    map[string]any{attempt.MetadataKeyPrimitiveCanaries: []any{"42"}},
			want:    []float64{1.0},
		},
		{
			name:    "callback false is not a finding",
			outputs: []string{"nothing happened"},
			meta:    map[string]any{attempt.MetadataKeyPrimitiveOOBCallback: false},
			want:    []float64{0.0},
		},
	}

	det := newInjection(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := det.Detect(context.Background(), attemptWith(tc.outputs, tc.meta))
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("scores = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("score[%d] = %v, want %v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestInjectionDetector_PerOutputScoring verifies only the matching output is
// flagged when a single attempt carries several.
func TestInjectionDetector_PerOutputScoring(t *testing.T) {
	a := attemptWith(
		[]string{"clean block", "root:x:0:0:leaked", "another clean block"},
		map[string]any{attempt.MetadataKeyPrimitiveSignatures: []string{"root:x:0:0:"}},
	)
	got, err := newInjection(t).Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	want := []float64{0.0, 1.0, 0.0}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("score[%d] = %v, want %v (scores = %v)", i, got[i], want[i], got)
		}
	}
}

func TestInjectionDetector_Identity(t *testing.T) {
	det := newInjection(t)
	if det.Name() != "mcpprimitive.Injection" {
		t.Errorf("Name() = %q", det.Name())
	}
	if det.Description() == "" {
		t.Error("Description() is empty")
	}
}

// TestInjectionDetector_CallbackAppliesToEveryOutput: a callback is attempt-wide
// evidence — the sink was reached — so it must not leave outputs that happen to
// carry no in-band match sitting at 0.0 alongside one that does.
func TestInjectionDetector_CallbackAppliesToEveryOutput(t *testing.T) {
	a := attemptWith(
		[]string{"root:x:0:0:leaked", "nothing here"},
		map[string]any{
			attempt.MetadataKeyPrimitiveSignatures:  []string{"root:x:0:0:"},
			attempt.MetadataKeyPrimitiveOOBCallback: true,
		},
	)
	got, err := newInjection(t).Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	for i, s := range got {
		if s != 1.0 {
			t.Errorf("score[%d] = %v, want 1.0 (scores = %v)", i, s, got)
		}
	}
}
