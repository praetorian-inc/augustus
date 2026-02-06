package test

import (
	"context"
	"errors"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// mockGenerator is a simple mock for testing probes
type mockGenerator struct {
	responses    []attempt.Message
	err          error
	cleared      bool
	generateFunc func(context.Context, *attempt.Conversation, int) ([]attempt.Message, error)
}

func (m *mockGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	// If custom function provided, use it
	if m.generateFunc != nil {
		return m.generateFunc(ctx, conv, n)
	}

	// Otherwise use default behavior
	if m.err != nil {
		return nil, m.err
	}
	if len(m.responses) == 0 {
		// Return n empty responses by default
		msgs := make([]attempt.Message, n)
		for i := range msgs {
			msgs[i] = attempt.NewAssistantMessage("")
		}
		return msgs, nil
	}
	return m.responses, nil
}

func (m *mockGenerator) ClearHistory() {
	m.cleared = true
}

func (m *mockGenerator) Name() string {
	return "mock-generator"
}

func (m *mockGenerator) Description() string {
	return "mock generator for testing"
}

func TestBlankProbe_Name(t *testing.T) {
	p := &Blank{}
	if got := p.Name(); got != "test.Blank" {
		t.Errorf("Name() = %q, want %q", got, "test.Blank")
	}
}

func TestBlankProbe_Description(t *testing.T) {
	p := &Blank{}
	desc := p.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
	if len(desc) < 10 {
		t.Errorf("Description() too short: %q", desc)
	}
}

func TestBlankProbe_Goal(t *testing.T) {
	p := &Blank{}
	want := "see what the model has to say for itself given silence"
	if got := p.Goal(); got != want {
		t.Errorf("Goal() = %q, want %q", got, want)
	}
}

func TestBlankProbe_GetPrimaryDetector(t *testing.T) {
	p := &Blank{}
	if got := p.GetPrimaryDetector(); got != "any.AnyOutput" {
		t.Errorf("GetPrimaryDetector() = %q, want %q", got, "any.AnyOutput")
	}
}

func TestBlankProbe_GetPrompts(t *testing.T) {
	p := &Blank{}
	prompts := p.GetPrompts()
	if len(prompts) != 1 {
		t.Fatalf("GetPrompts() returned %d prompts, want 1", len(prompts))
	}
	if prompts[0] != "" {
		t.Errorf("GetPrompts()[0] = %q, want empty string", prompts[0])
	}
}

func TestBlankProbe_Probe_Success(t *testing.T) {
	p := &Blank{}
	gen := &mockGenerator{
		responses: []attempt.Message{
			attempt.NewAssistantMessage("test response"),
		},
	}

	attempts, err := p.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe() error = %v, want nil", err)
	}

	if len(attempts) != 1 {
		t.Fatalf("Probe() returned %d attempts, want 1", len(attempts))
	}

	a := attempts[0]
	if a.Probe != "test.Blank" {
		t.Errorf("attempt.Probe = %q, want %q", a.Probe, "test.Blank")
	}
	if a.Detector != "any.AnyOutput" {
		t.Errorf("attempt.Detector = %q, want %q", a.Detector, "any.AnyOutput")
	}
	if a.Prompt != "" {
		t.Errorf("attempt.Prompt = %q, want empty string", a.Prompt)
	}
	if len(a.Outputs) != 1 {
		t.Fatalf("len(attempt.Outputs) = %d, want 1", len(a.Outputs))
	}
	if a.Outputs[0] != "test response" {
		t.Errorf("attempt.Outputs[0] = %q, want %q", a.Outputs[0], "test response")
	}
	if a.Status != attempt.StatusComplete {
		t.Errorf("attempt.Status = %q, want %q", a.Status, attempt.StatusComplete)
	}
}

func TestBlankProbe_Probe_GeneratorError(t *testing.T) {
	p := &Blank{}
	testErr := errors.New("generator error")
	gen := &mockGenerator{
		err: testErr,
	}

	attempts, err := p.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe() error = %v, want nil (error should be in attempt)", err)
	}

	if len(attempts) != 1 {
		t.Fatalf("Probe() returned %d attempts, want 1", len(attempts))
	}

	a := attempts[0]
	if a.Status != attempt.StatusError {
		t.Errorf("attempt.Status = %q, want %q", a.Status, attempt.StatusError)
	}
}

func TestBlankProbe_Registration(t *testing.T) {
	// Test that the probe is registered via init()
	factory, ok := probes.Get("test.Blank")
	if !ok {
		t.Fatal("test.Blank not registered in probes registry")
	}

	// Test factory creates valid probe
	p, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory() error = %v, want nil", err)
	}

	if p.Name() != "test.Blank" {
		t.Errorf("factory created probe with name %q, want %q", p.Name(), "test.Blank")
	}
}

func TestNewBlank(t *testing.T) {
	tests := []struct {
		name   string
		config registry.Config
	}{
		{
			name:   "nil config",
			config: nil,
		},
		{
			name:   "empty config",
			config: registry.Config{},
		},
		{
			name: "config with data",
			config: registry.Config{
				"key": "value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewBlank(tt.config)
			if err != nil {
				t.Fatalf("NewBlank() error = %v, want nil", err)
			}
			if p == nil {
				t.Fatal("NewBlank() returned nil probe")
			}
			if p.Name() != "test.Blank" {
				t.Errorf("probe.Name() = %q, want %q", p.Name(), "test.Blank")
			}
		})
	}
}
