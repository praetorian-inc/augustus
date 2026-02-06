//go:build integration

package poetry

import (
	"context"
	"fmt"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	_ "github.com/praetorian-inc/augustus/internal/buffs/poetry"
	_ "github.com/praetorian-inc/augustus/internal/detectors/mitigation"
	_ "github.com/praetorian-inc/augustus/internal/detectors/poetry"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/require"
)

// TestBenchmark_TemplateVsMetaPrompt compares template probe ASR against
// MetaPromptBuff ASR when both use the same payloads and generator.
//
// This test requires a real LLM generator and is intended for manual execution
// during evaluation, not CI. Run with:
//   go test ./internal/probes/poetry/... -tags=integration -run TestBenchmark -count=1 -v
func TestBenchmark_TemplateVsMetaPrompt(t *testing.T) {
	gen := &mockIntegrationGenerator{response: "Here is what you asked for."}

	mitigationDet, err := detectors.Create("mitigation.MitigationBypass", nil)
	require.NoError(t, err)

	harmJudgeDet, err := detectors.Create("poetry.HarmJudge", nil)
	require.NoError(t, err)

	// Test template probes
	templateProbes := []string{
		"poetry.InjectHaiku",
		"poetry.InjectSonnet",
		"poetry.InjectLimerick",
	}

	fmt.Println("=== Template Probe Results ===")
	for _, name := range templateProbes {
		probe, err := probes.Create(name, nil)
		require.NoError(t, err)

		attempts, err := probe.Probe(context.Background(), gen)
		require.NoError(t, err)

		mitigationBypassed := 0
		harmfulContent := 0
		for _, a := range attempts {
			ms, _ := mitigationDet.Detect(context.Background(), a)
			hs, _ := harmJudgeDet.Detect(context.Background(), a)
			if len(ms) > 0 && ms[0] > 0.5 {
				mitigationBypassed++
			}
			if len(hs) > 0 && hs[0] > 0.5 {
				harmfulContent++
			}
		}

		fmt.Printf("  %s: %d attempts, %d bypassed (%.1f%%), %d harmful (%.1f%%)\n",
			name, len(attempts),
			mitigationBypassed, float64(mitigationBypassed)/float64(len(attempts))*100,
			harmfulContent, float64(harmfulContent)/float64(len(attempts))*100)
	}

	// Test MetaPromptBuff (template fallback mode since no real generator)
	fmt.Println("\n=== MetaPromptBuff Results ===")
	strategies := []string{"allegorical", "metaphorical", "narrative"}
	for _, strategy := range strategies {
		buff, err := buffs.Create("poetry.MetaPrompt", registry.Config{
			"format":   "haiku",
			"strategy": strategy,
		})
		require.NoError(t, err)

		// Create attempts from first 10 payloads
		var inputAttempts []*attempt.Attempt
		for _, payload := range DefaultHarmfulPayloads[:10] {
			inputAttempts = append(inputAttempts, &attempt.Attempt{
				Prompt:   payload,
				Metadata: make(map[string]any),
			})
		}

		transformed, err := buff.Buff(context.Background(), inputAttempts)
		require.NoError(t, err)

		mitigationBypassed := 0
		harmfulContent := 0
		for _, a := range transformed {
			if a.Metadata["transform_method"] != "meta_prompt" {
				continue // Skip originals
			}
			// Test with mock generator response
			a.Outputs = []string{gen.response}
			ms, _ := mitigationDet.Detect(context.Background(), a)
			hs, _ := harmJudgeDet.Detect(context.Background(), a)
			if len(ms) > 0 && ms[0] > 0.5 {
				mitigationBypassed++
			}
			if len(hs) > 0 && hs[0] > 0.5 {
				harmfulContent++
			}
		}

		fmt.Printf("  strategy=%s: %d transformed, %d bypassed, %d harmful\n",
			strategy, len(transformed), mitigationBypassed, harmfulContent)
	}
}
