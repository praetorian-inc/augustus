package test

import (
	"context"
	"errors"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// newTestProbe is a test helper that constructs a Test with the given prompts.
func newTestProbe(prompts []string) *Test {
	return &Test{
		SimpleProbe: probes.NewSimpleProbe(
			"test.Test",
			"send some test strings, ignore the response",
			"always.Pass",
			"Test probe - Poses some test strings to a model; for use in tests",
			prompts,
		),
	}
}

func TestTestProbe_Name(t *testing.T) {
	p := newTestProbe(defaultTestPrompts)
	if got := p.Name(); got != "test.Test" {
		t.Errorf("Name() = %q, want %q", got, "test.Test")
	}
}

func TestTestProbe_Description(t *testing.T) {
	p := newTestProbe(defaultTestPrompts)
	desc := p.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
	if len(desc) < 10 {
		t.Errorf("Description() too short: %q", desc)
	}
}

func TestTestProbe_Goal(t *testing.T) {
	p := newTestProbe(defaultTestPrompts)
	want := "send some test strings, ignore the response"
	if got := p.Goal(); got != want {
		t.Errorf("Goal() = %q, want %q", got, want)
	}
}

func TestTestProbe_GetPrimaryDetector(t *testing.T) {
	p := newTestProbe(defaultTestPrompts)
	if got := p.GetPrimaryDetector(); got != "always.Pass" {
		t.Errorf("GetPrimaryDetector() = %q, want %q", got, "always.Pass")
	}
}

func TestTestProbe_GetPrompts(t *testing.T) {
	customPrompts := []string{"prompt1", "prompt2"}
	tests := []struct {
		name     string
		prompts  []string
		wantLen  int
		wantVals []string
	}{
		{
			name:     "default prompts",
			prompts:  defaultTestPrompts,
			wantLen:  len(defaultTestPrompts),
			wantVals: defaultTestPrompts,
		},
		{
			name:     "custom prompts",
			prompts:  customPrompts,
			wantLen:  2,
			wantVals: customPrompts,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestProbe(tt.prompts)
			got := p.GetPrompts()
			if len(got) != tt.wantLen {
				t.Errorf("GetPrompts() returned %d prompts, want %d", len(got), tt.wantLen)
			}
			for i := range got {
				if got[i] != tt.wantVals[i] {
					t.Errorf("GetPrompts()[%d] = %q, want %q", i, got[i], tt.wantVals[i])
				}
			}
		})
	}
}

func TestTestProbe_Probe_Success(t *testing.T) {
	customPrompts := []string{"test1", "test2", "test3"}
	p := newTestProbe(customPrompts)

	gen := &mockGenerator{
		responses: []attempt.Message{
			attempt.NewAssistantMessage("response"),
		},
	}

	attempts, err := p.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe() error = %v, want nil", err)
	}

	if len(attempts) != len(customPrompts) {
		t.Fatalf("Probe() returned %d attempts, want %d", len(attempts), len(customPrompts))
	}

	// Check each attempt
	for i, a := range attempts {
		if a.Probe != "test.Test" {
			t.Errorf("attempt[%d].Probe = %q, want %q", i, a.Probe, "test.Test")
		}
		if a.Detector != "always.Pass" {
			t.Errorf("attempt[%d].Detector = %q, want %q", i, a.Detector, "always.Pass")
		}
		if a.Prompt != customPrompts[i] {
			t.Errorf("attempt[%d].Prompt = %q, want %q", i, a.Prompt, customPrompts[i])
		}
		if len(a.Outputs) != 1 {
			t.Fatalf("len(attempt[%d].Outputs) = %d, want 1", i, len(a.Outputs))
		}
		if a.Outputs[0] != "response" {
			t.Errorf("attempt[%d].Outputs[0] = %q, want %q", i, a.Outputs[0], "response")
		}
		if a.Status != attempt.StatusComplete {
			t.Errorf("attempt[%d].Status = %q, want %q", i, a.Status, attempt.StatusComplete)
		}
	}
}

func TestTestProbe_Probe_GeneratorError(t *testing.T) {
	customPrompts := []string{"test1", "test2"}
	p := newTestProbe(customPrompts)

	testErr := errors.New("generator error")
	gen := &mockGenerator{
		err: testErr,
	}

	attempts, err := p.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe() error = %v, want nil (errors should be in attempts)", err)
	}

	if len(attempts) != len(customPrompts) {
		t.Fatalf("Probe() returned %d attempts, want %d", len(attempts), len(customPrompts))
	}

	// All attempts should have error status
	for i, a := range attempts {
		if a.Status != attempt.StatusError {
			t.Errorf("attempt[%d].Status = %q, want %q", i, a.Status, attempt.StatusError)
		}
		if a.Error == "" {
			t.Errorf("attempt[%d].Error is empty, want error message", i)
		}
	}
}

func TestTestProbe_Probe_MixedResults(t *testing.T) {
	customPrompts := []string{"test1", "test2"}
	p := newTestProbe(customPrompts)

	// Generator succeeds on first call, fails on second
	callCount := 0
	testErr := errors.New("second call fails")
	gen := &mockGenerator{
		generateFunc: func(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
			callCount++
			if callCount == 1 {
				return []attempt.Message{attempt.NewAssistantMessage("success")}, nil
			}
			return nil, testErr
		},
	}

	attempts, err := p.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe() error = %v, want nil", err)
	}

	if len(attempts) != 2 {
		t.Fatalf("Probe() returned %d attempts, want 2", len(attempts))
	}

	// First should succeed
	if attempts[0].Status != attempt.StatusComplete {
		t.Errorf("attempt[0].Status = %q, want %q", attempts[0].Status, attempt.StatusComplete)
	}

	// Second should fail
	if attempts[1].Status != attempt.StatusError {
		t.Errorf("attempt[1].Status = %q, want %q", attempts[1].Status, attempt.StatusError)
	}
}

func TestTestProbe_Registration(t *testing.T) {
	// Test that the probe is registered via init()
	factory, ok := probes.Get("test.Test")
	if !ok {
		t.Fatal("test.Test not registered in probes registry")
	}

	// Test factory creates valid probe
	p, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory() error = %v, want nil", err)
	}

	if p.Name() != "test.Test" {
		t.Errorf("factory created probe with name %q, want %q", p.Name(), "test.Test")
	}
}

func TestNewTest(t *testing.T) {
	tests := []struct {
		name        string
		config      registry.Config
		wantPrompts []string
	}{
		{
			name:        "default prompts",
			config:      registry.Config{},
			wantPrompts: defaultTestPrompts,
		},
		{
			name: "custom prompts",
			config: registry.Config{
				"prompts": []string{"custom1", "custom2"},
			},
			wantPrompts: []string{"custom1", "custom2"},
		},
		{
			name: "invalid prompts type ignored",
			config: registry.Config{
				"prompts": "not a slice",
			},
			wantPrompts: defaultTestPrompts,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewTest(tt.config)
			if err != nil {
				t.Fatalf("NewTest() error = %v, want nil", err)
			}
			if p == nil {
				t.Fatal("NewTest() returned nil probe")
			}

			got := p.GetPrompts()
			if len(got) != len(tt.wantPrompts) {
				t.Fatalf("probe has %d prompts, want %d", len(got), len(tt.wantPrompts))
			}
			for i := range got {
				if got[i] != tt.wantPrompts[i] {
					t.Errorf("prompts[%d] = %q, want %q", i, got[i], tt.wantPrompts[i])
				}
			}
		})
	}
}

func TestDefaultTestPrompts(t *testing.T) {
	// Verify default prompts match Python garak's test.Test prompts
	// Note: First prompt is intentionally empty (matches garak)
	if len(defaultTestPrompts) != 8 {
		t.Fatalf("defaultTestPrompts has %d prompts, want 8 (matching garak)", len(defaultTestPrompts))
	}

	// First prompt should be empty (garak behavior)
	if defaultTestPrompts[0] != "" {
		t.Errorf("defaultTestPrompts[0] = %q, want empty string (matching garak)", defaultTestPrompts[0])
	}

	// Other prompts should have various test content
	expectedPrompts := []string{
		"",
		"The quick brown fox jumps over the lazy dog",
		"Liberté, égalité, fraternité",
		"有朋自远方来，不亦乐乎?",
	}
	for i, want := range expectedPrompts {
		if defaultTestPrompts[i] != want {
			t.Errorf("defaultTestPrompts[%d] = %q, want %q", i, defaultTestPrompts[i], want)
		}
	}
}
