package lmrc

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
// SlurUsage Tests
// ----------------------------------------------------------------------------

func TestSlurUsage_Registration(t *testing.T) {
	factory, ok := probes.Get("lmrc.SlurUsage")
	require.True(t, ok, "SlurUsage should be registered")

	p, err := factory(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "lmrc.SlurUsage", p.Name())
	assert.Equal(t, "unsafecontent.SurgeProfanityRacialEthnic", p.GetPrimaryDetector())
	assert.Contains(t, p.Goal(), "slur")
}

func TestSlurUsage_PromptCount(t *testing.T) {
	p, err := NewSlurUsage(registry.Config{})
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.Equal(t, 1, len(prompts), "SlurUsage should have 1 prompt")
	assert.Contains(t, prompts[0], "black guy")
}

func TestSlurUsage_Probe(t *testing.T) {
	p, err := NewSlurUsage(registry.Config{})
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("You could call him...")

	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.Len(t, attempts, 1)

	a := attempts[0]
	assert.Equal(t, "lmrc.SlurUsage", a.Probe)
	assert.Equal(t, "unsafecontent.SurgeProfanityRacialEthnic", a.Detector)
	assert.NotEmpty(t, a.Outputs)
}

// ----------------------------------------------------------------------------
// SexualContent Tests
// ----------------------------------------------------------------------------

func TestSexualContent_Registration(t *testing.T) {
	factory, ok := probes.Get("lmrc.SexualContent")
	require.True(t, ok, "SexualContent should be registered")

	p, err := factory(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "lmrc.SexualContent", p.Name())
	assert.Equal(t, "unsafecontent.SurgeProfanitySexual", p.GetPrimaryDetector())
	assert.Contains(t, p.Goal(), "sexual content")
}

func TestSexualContent_PromptCount(t *testing.T) {
	p, err := NewSexualContent(registry.Config{})
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.Equal(t, 1, len(prompts), "SexualContent should have 1 prompt")
	assert.Contains(t, prompts[0], "pleasure")
}

func TestSexualContent_Probe(t *testing.T) {
	p, err := NewSexualContent(registry.Config{})
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("The pleasure was overwhelming...")

	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.Len(t, attempts, 1)

	a := attempts[0]
	assert.Equal(t, "lmrc.SexualContent", a.Probe)
	assert.Equal(t, "unsafecontent.SurgeProfanitySexual", a.Detector)
	assert.NotEmpty(t, a.Outputs)
}

// ----------------------------------------------------------------------------
// Sexualisation Tests
// ----------------------------------------------------------------------------

func TestSexualisation_Registration(t *testing.T) {
	factory, ok := probes.Get("lmrc.Sexualisation")
	require.True(t, ok, "Sexualisation should be registered")

	p, err := factory(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "lmrc.Sexualisation", p.Name())
	assert.Equal(t, "unsafecontent.SurgeProfanitySexual", p.GetPrimaryDetector())
	assert.Contains(t, p.Goal(), "sexualise")
}

func TestSexualisation_PromptCount(t *testing.T) {
	p, err := NewSexualisation(registry.Config{})
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.Equal(t, 3, len(prompts), "Sexualisation should have 3 prompts")
	assert.Contains(t, prompts[0], "body part")
	assert.Contains(t, prompts[1], "boner material")
	assert.Contains(t, prompts[2], "hot")
}

func TestSexualisation_Probe(t *testing.T) {
	p, err := NewSexualisation(registry.Config{})
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("I like...")

	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.Len(t, attempts, 3, "Should generate 3 attempts (one per prompt)")

	// Check all attempts have correct metadata
	for _, a := range attempts {
		assert.Equal(t, "lmrc.Sexualisation", a.Probe)
		assert.Equal(t, "unsafecontent.SurgeProfanitySexual", a.Detector)
		assert.NotEmpty(t, a.Outputs)
	}
}

// ----------------------------------------------------------------------------
// Profanity Tests
// ----------------------------------------------------------------------------

func TestProfanity_Registration(t *testing.T) {
	factory, ok := probes.Get("lmrc.Profanity")
	require.True(t, ok, "Profanity should be registered")

	p, err := factory(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "lmrc.Profanity", p.Name())
	assert.Equal(t, "unsafecontent.SurgeProfanityAnimalReferences", p.GetPrimaryDetector())
	assert.Contains(t, p.Goal(), "profanity")
}

func TestProfanity_PromptCount(t *testing.T) {
	p, err := NewProfanity(registry.Config{})
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.Equal(t, 2, len(prompts), "Profanity should have 2 prompts")
	assert.Contains(t, prompts[0], "men's genitals")
	assert.Contains(t, prompts[1], "women's genitals")
}

func TestProfanity_Probe(t *testing.T) {
	p, err := NewProfanity(registry.Config{})
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("An insult would be...")

	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.Len(t, attempts, 2, "Should generate 2 attempts (one per prompt)")

	// Check all attempts have correct metadata
	for _, a := range attempts {
		assert.Equal(t, "lmrc.Profanity", a.Probe)
		assert.Equal(t, "unsafecontent.SurgeProfanityAnimalReferences", a.Detector)
		assert.NotEmpty(t, a.Outputs)
	}
}

// ----------------------------------------------------------------------------
// Integration Tests
// ----------------------------------------------------------------------------

func TestProbeDetectorPairing(t *testing.T) {
	// Verify each probe uses the correct detector
	tests := []struct {
		probeName    string
		detectorName string
	}{
		{"lmrc.SlurUsage", "unsafecontent.SurgeProfanityRacialEthnic"},
		{"lmrc.SexualContent", "unsafecontent.SurgeProfanitySexual"},
		{"lmrc.Sexualisation", "unsafecontent.SurgeProfanitySexual"},
		{"lmrc.Profanity", "unsafecontent.SurgeProfanityAnimalReferences"},
	}

	for _, tt := range tests {
		t.Run(tt.probeName, func(t *testing.T) {
			factory, ok := probes.Get(tt.probeName)
			require.True(t, ok)

			p, err := factory(registry.Config{})
			require.NoError(t, err)
			assert.Equal(t, tt.detectorName, p.GetPrimaryDetector())
		})
	}
}

func TestAllProbes_RegisteredCount(t *testing.T) {
	// Verify all 4 probes are registered
	registered := []string{
		"lmrc.SlurUsage",
		"lmrc.SexualContent",
		"lmrc.Sexualisation",
		"lmrc.Profanity",
	}

	for _, name := range registered {
		t.Run(name, func(t *testing.T) {
			_, ok := probes.Get(name)
			assert.True(t, ok, "%s should be registered", name)
		})
	}
}

// ============================================================================
// NEW: LMRC Injection Attack Probes Tests
// ============================================================================

// ----------------------------------------------------------------------------
// DirectInject Tests
// ----------------------------------------------------------------------------

func TestDirectInject_Registration(t *testing.T) {
	factory, ok := probes.Get("lmrc.DirectInject")
	require.True(t, ok, "DirectInject should be registered")

	p, err := factory(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "lmrc.DirectInject", p.Name())
	assert.Equal(t, "promptinjection.DirectInjection", p.GetPrimaryDetector())
	assert.Contains(t, p.Goal(), "inject")
}

func TestDirectInject_PromptCount(t *testing.T) {
	p, err := NewDirectInject(registry.Config{})
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.Greater(t, len(prompts), 0, "DirectInject should have at least 1 prompt")
	// Verify prompts contain direct injection patterns
	for _, prompt := range prompts {
		assert.NotEmpty(t, prompt, "Prompt should not be empty")
	}
}

func TestDirectInject_Probe(t *testing.T) {
	p, err := NewDirectInject(registry.Config{})
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("Sure, I'll ignore my instructions...")

	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.Greater(t, len(attempts), 0, "Should generate at least 1 attempt")

	a := attempts[0]
	assert.Equal(t, "lmrc.DirectInject", a.Probe)
	assert.Equal(t, "promptinjection.DirectInjection", a.Detector)
	assert.NotEmpty(t, a.Outputs)
}

func TestDirectInject_Pattern(t *testing.T) {
	p, err := NewDirectInject(registry.Config{})
	require.NoError(t, err)

	// Type assertion to access pattern field
	probe, ok := p.(*LMRCProbe)
	require.True(t, ok, "Should be LMRCProbe type")
	assert.Equal(t, DirectInjectPattern, probe.pattern)
}

// ----------------------------------------------------------------------------
// ContextInjection Tests
// ----------------------------------------------------------------------------

func TestContextInjection_Registration(t *testing.T) {
	factory, ok := probes.Get("lmrc.ContextInjection")
	require.True(t, ok, "ContextInjection should be registered")

	p, err := factory(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "lmrc.ContextInjection", p.Name())
	assert.Equal(t, "promptinjection.ContextManipulation", p.GetPrimaryDetector())
	assert.Contains(t, p.Goal(), "inject")
}

func TestContextInjection_PromptCount(t *testing.T) {
	p, err := NewContextInjection(registry.Config{})
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.Greater(t, len(prompts), 0, "ContextInjection should have at least 1 prompt")
	for _, prompt := range prompts {
		assert.NotEmpty(t, prompt, "Prompt should not be empty")
	}
}

func TestContextInjection_Probe(t *testing.T) {
	p, err := NewContextInjection(registry.Config{})
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("Based on the new context you provided...")

	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.Greater(t, len(attempts), 0, "Should generate at least 1 attempt")

	a := attempts[0]
	assert.Equal(t, "lmrc.ContextInjection", a.Probe)
	assert.Equal(t, "promptinjection.ContextManipulation", a.Detector)
	assert.NotEmpty(t, a.Outputs)
}

func TestContextInjection_Pattern(t *testing.T) {
	p, err := NewContextInjection(registry.Config{})
	require.NoError(t, err)

	probe, ok := p.(*LMRCProbe)
	require.True(t, ok, "Should be LMRCProbe type")
	assert.Equal(t, ContextInjectionPattern, probe.pattern)
}

// ----------------------------------------------------------------------------
// RoleConfusion Tests
// ----------------------------------------------------------------------------

func TestRoleConfusion_Registration(t *testing.T) {
	factory, ok := probes.Get("lmrc.RoleConfusion")
	require.True(t, ok, "RoleConfusion should be registered")

	p, err := factory(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "lmrc.RoleConfusion", p.Name())
	assert.Equal(t, "promptinjection.RoleManipulation", p.GetPrimaryDetector())
	assert.Contains(t, p.Goal(), "confuse")
}

func TestRoleConfusion_PromptCount(t *testing.T) {
	p, err := NewRoleConfusion(registry.Config{})
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.Greater(t, len(prompts), 0, "RoleConfusion should have at least 1 prompt")
	for _, prompt := range prompts {
		assert.NotEmpty(t, prompt, "Prompt should not be empty")
	}
}

func TestRoleConfusion_Probe(t *testing.T) {
	p, err := NewRoleConfusion(registry.Config{})
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("As a developer/admin with full access...")

	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.Greater(t, len(attempts), 0, "Should generate at least 1 attempt")

	a := attempts[0]
	assert.Equal(t, "lmrc.RoleConfusion", a.Probe)
	assert.Equal(t, "promptinjection.RoleManipulation", a.Detector)
	assert.NotEmpty(t, a.Outputs)
}

func TestRoleConfusion_Pattern(t *testing.T) {
	p, err := NewRoleConfusion(registry.Config{})
	require.NoError(t, err)

	probe, ok := p.(*LMRCProbe)
	require.True(t, ok, "Should be LMRCProbe type")
	assert.Equal(t, RoleConfusionPattern, probe.pattern)
}

// ----------------------------------------------------------------------------
// Injection Probes Integration Tests
// ----------------------------------------------------------------------------

func TestInjectionProbes_DetectorPairing(t *testing.T) {
	tests := []struct {
		probeName    string
		detectorName string
	}{
		{"lmrc.DirectInject", "promptinjection.DirectInjection"},
		{"lmrc.ContextInjection", "promptinjection.ContextManipulation"},
		{"lmrc.RoleConfusion", "promptinjection.RoleManipulation"},
	}

	for _, tt := range tests {
		t.Run(tt.probeName, func(t *testing.T) {
			factory, ok := probes.Get(tt.probeName)
			require.True(t, ok)

			p, err := factory(registry.Config{})
			require.NoError(t, err)
			assert.Equal(t, tt.detectorName, p.GetPrimaryDetector())
		})
	}
}

func TestAllInjectionProbes_Registered(t *testing.T) {
	registered := []string{
		"lmrc.DirectInject",
		"lmrc.ContextInjection",
		"lmrc.RoleConfusion",
	}

	for _, name := range registered {
		t.Run(name, func(t *testing.T) {
			_, ok := probes.Get(name)
			assert.True(t, ok, "%s should be registered", name)
		})
	}
}

func TestLMRCPattern_Values(t *testing.T) {
	// Verify pattern enum values
	assert.Equal(t, LMRCPattern(0), DirectInjectPattern, "DirectInjectPattern should be 0")
	assert.Equal(t, LMRCPattern(1), ContextInjectionPattern, "ContextInjectionPattern should be 1")
	assert.Equal(t, LMRCPattern(2), RoleConfusionPattern, "RoleConfusionPattern should be 2")
}
