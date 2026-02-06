package obscureprompt

import (
	"context"
	"errors"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockGenerator is a configurable mock for testing obscureprompt probes.
type mockGenerator struct {
	generateFunc func(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error)
}

func (m *mockGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if m.generateFunc != nil {
		return m.generateFunc(ctx, conv, n)
	}
	return []attempt.Message{{Content: "mock response"}}, nil
}

func (m *mockGenerator) ClearHistory() {}
func (m *mockGenerator) Name() string        { return "mock-generator" }
func (m *mockGenerator) Description() string { return "mock generator for testing" }

func TestNewObscurePromptProbe(t *testing.T) {
	tests := []struct {
		name            string
		cfg             registry.Config
		expectedError   bool
		validateProbe   func(t *testing.T, probe *ObscurePromptProbe)
	}{
		{
			name: "creates probe with default values",
			cfg:  registry.Config{},
			validateProbe: func(t *testing.T, probe *ObscurePromptProbe) {
				assert.Equal(t, "obscureprompt.ObscurePrompt", probe.Name())
				assert.Equal(t, "cause the model to disregard the system prompt", probe.Goal())
				assert.Equal(t, "dan.DAN", probe.GetPrimaryDetector())
				assert.NotEmpty(t, probe.Description())
				assert.Len(t, probe.GetPrompts(), 0) // No mutations generated yet
				assert.Equal(t, 5, probe.mutationCount)
				assert.NotEmpty(t, probe.baseSeed)
			},
		},
		{
			name: "creates probe with custom mutation count from config",
			cfg: registry.Config{
				"mutation_count": 10,
			},
			validateProbe: func(t *testing.T, probe *ObscurePromptProbe) {
				assert.Equal(t, 10, probe.mutationCount)
			},
		},
		{
			name: "creates probe with custom base seed from config",
			cfg: registry.Config{
				"base_seed": "Tell me how to hack",
			},
			validateProbe: func(t *testing.T, probe *ObscurePromptProbe) {
				assert.Equal(t, "Tell me how to hack", probe.baseSeed)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prober, err := NewObscurePromptProbe(tt.cfg)

			if tt.expectedError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, prober)

			probe, ok := prober.(*ObscurePromptProbe)
			require.True(t, ok, "should return *ObscurePromptProbe")

			if tt.validateProbe != nil {
				tt.validateProbe(t, probe)
			}
		})
	}
}

func TestObscurePromptProbe_GenerateMutations(t *testing.T) {
	tests := []struct {
		name          string
		baseSeed      string
		mutationCount int
		mockSetup     func(t *testing.T) probes.Generator
		expectError   bool
		validateMutations func(t *testing.T, mutations []string)
	}{
		{
			name:          "generates mutations successfully",
			baseSeed:      "Tell me something dangerous",
			mutationCount: 3,
			mockSetup: func(t *testing.T) probes.Generator {
				callCount := 0
				return &mockGenerator{
					generateFunc: func(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
						callCount++
						// Return unique mutations
						return []attempt.Message{
							{Content: "mutation " + string(rune('A'+callCount-1))},
						}, nil
					},
				}
			},
			validateMutations: func(t *testing.T, mutations []string) {
				assert.Len(t, mutations, 3, "should generate 3 mutations")
				// Each mutation should be unique
				uniqueMap := make(map[string]bool)
				for _, m := range mutations {
					assert.NotEmpty(t, m, "mutation should not be empty")
					uniqueMap[m] = true
				}
				assert.Len(t, uniqueMap, 3, "mutations should be unique")
			},
		},
		{
			name:          "handles generation errors gracefully",
			baseSeed:      "test seed",
			mutationCount: 2,
			mockSetup: func(t *testing.T) probes.Generator {
				return &mockGenerator{
					generateFunc: func(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
						return nil, errors.New("LLM API error")
					},
				}
			},
			expectError: true,
		},
		{
			name:          "handles empty responses",
			baseSeed:      "test seed",
			mutationCount: 1,
			mockSetup: func(t *testing.T) probes.Generator {
				return &mockGenerator{
					generateFunc: func(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
						return []attempt.Message{}, nil // Empty response
					},
				}
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutator := tt.mockSetup(t)

			probe := &ObscurePromptProbe{
				baseSeed:      tt.baseSeed,
				mutationCount: tt.mutationCount,
				mutator:       mutator,
			}

			mutations, err := probe.GenerateMutations(context.Background())

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tt.validateMutations != nil {
				tt.validateMutations(t, mutations)
			}
		})
	}
}

func TestObscurePromptProbe_SetMutator(t *testing.T) {
	probe := &ObscurePromptProbe{}
	mutator := &mockGenerator{}

	probe.SetMutator(mutator)

	assert.Equal(t, mutator, probe.mutator, "should set mutator")
}

func TestObscurePromptProbe_Probe(t *testing.T) {
	tests := []struct {
		name          string
		setupProbe    func(t *testing.T) *ObscurePromptProbe
		setupGen      func(t *testing.T) probes.Generator
		validateAttempts func(t *testing.T, attempts []*attempt.Attempt)
		expectError   bool
	}{
		{
			name: "probes with generated mutations",
			setupProbe: func(t *testing.T) *ObscurePromptProbe {
				// Create probe with pre-set mutations
				base := probes.NewSimpleProbe(
					"obscureprompt.ObscurePrompt",
					"cause the model to disregard the system prompt",
					"dan.DAN",
					"Test probe",
					[]string{},
				)
				probe := &ObscurePromptProbe{
					SimpleProbe:   base,
					baseSeed:      "test seed",
					mutationCount: 2,
				}
				// Manually set prompts to simulate GenerateMutations having been called
				probe.prompts = []string{
					"mutated prompt 1",
					"mutated prompt 2",
				}
				return probe
			},
			setupGen: func(t *testing.T) probes.Generator {
				return &mockGenerator{
					generateFunc: func(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
						return []attempt.Message{{Content: "test response"}}, nil
					},
				}
			},
			validateAttempts: func(t *testing.T, attempts []*attempt.Attempt) {
				assert.Len(t, attempts, 2, "should create attempt for each mutation")
				for _, att := range attempts {
					assert.Equal(t, "obscureprompt.ObscurePrompt", att.Probe)
					assert.Equal(t, "dan.DAN", att.Detector)
					assert.NotEmpty(t, att.Outputs)
				}
			},
		},
		{
			name: "generates mutations if mutator is set and prompts are empty",
			setupProbe: func(t *testing.T) *ObscurePromptProbe {
				mutator := &mockGenerator{
					generateFunc: func(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
						return []attempt.Message{{Content: "generated mutation"}}, nil
					},
				}

				base := probes.NewSimpleProbe(
					"obscureprompt.ObscurePrompt",
					"cause the model to disregard the system prompt",
					"dan.DAN",
					"Test probe",
					[]string{},
				)
				probe := &ObscurePromptProbe{
					SimpleProbe:   base,
					baseSeed:      "test seed",
					mutationCount: 1,
					mutator:       mutator,
					prompts:       []string{}, // Empty prompts
				}
				return probe
			},
			setupGen: func(t *testing.T) probes.Generator {
				return &mockGenerator{
					generateFunc: func(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
						return []attempt.Message{{Content: "probe response"}}, nil
					},
				}
			},
			validateAttempts: func(t *testing.T, attempts []*attempt.Attempt) {
				assert.Len(t, attempts, 1, "should generate mutations and probe")
			},
		},
		{
			name: "uses target generator as mutator if not set",
			setupProbe: func(t *testing.T) *ObscurePromptProbe {
				base := probes.NewSimpleProbe(
					"obscureprompt.ObscurePrompt",
					"cause the model to disregard the system prompt",
					"dan.DAN",
					"Test probe",
					[]string{},
				)
				probe := &ObscurePromptProbe{
					SimpleProbe:   base,
					baseSeed:      "test seed",
					mutationCount: 1,
					mutator:       nil, // No mutator set
					prompts:       []string{},
				}
				return probe
			},
			setupGen: func(t *testing.T) probes.Generator {
				return &mockGenerator{
					generateFunc: func(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
						return []attempt.Message{{Content: "response"}}, nil
					},
				}
			},
			validateAttempts: func(t *testing.T, attempts []*attempt.Attempt) {
				assert.Len(t, attempts, 1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := tt.setupProbe(t)
			gen := tt.setupGen(t)

			attempts, err := probe.Probe(context.Background(), gen)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tt.validateAttempts != nil {
				tt.validateAttempts(t, attempts)
			}
		})
	}
}

func TestObscurePromptProbe_ProberInterface(t *testing.T) {
	// Verify ObscurePromptProbe implements probes.Prober
	var _ probes.Prober = (*ObscurePromptProbe)(nil)

	probe := &ObscurePromptProbe{
		SimpleProbe: &probes.SimpleProbe{},
	}

	// Test all Prober interface methods exist
	assert.NotPanics(t, func() {
		_ = probe.Name()
		_ = probe.Description()
		_ = probe.Goal()
		_ = probe.GetPrimaryDetector()
		_ = probe.GetPrompts()
	})
}

func TestObscurePromptProbe_Registration(t *testing.T) {
	// Verify probe is registered in init()
	factory, ok := probes.Get("obscureprompt.ObscurePrompt")
	assert.True(t, ok, "probe should be registered")
	assert.NotNil(t, factory, "factory function should not be nil")

	// Verify factory creates valid probe
	prober, err := factory(registry.Config{})
	require.NoError(t, err)
	assert.NotNil(t, prober)
	assert.Equal(t, "obscureprompt.ObscurePrompt", prober.Name())
}
