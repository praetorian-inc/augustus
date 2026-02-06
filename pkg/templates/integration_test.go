//go:build integration

package templates_test

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
	_ "github.com/praetorian-inc/augustus/internal/probes/advpatch"
	_ "github.com/praetorian-inc/augustus/internal/probes/dan"
	_ "github.com/praetorian-inc/augustus/internal/probes/goodside"
	_ "github.com/praetorian-inc/augustus/internal/probes/latentinjection"
	_ "github.com/praetorian-inc/augustus/internal/probes/pair"
	_ "github.com/praetorian-inc/augustus/internal/probes/tap"
	"github.com/stretchr/testify/assert"
)

func TestAllProbesRegistered(t *testing.T) {
	expectedProbes := []string{
		// DAN (14)
		"dan.Dan_11_0", "dan.Dan_10_0", "dan.Dan_9_0", "dan.Dan_8_0",
		"dan.Dan_7_0", "dan.Dan_6_2", "dan.Dan_6_0", "dan.DUDE",
		"dan.STAN", "dan.DAN_Jailbreak", "dan.AntiDAN",
		"dan.ChatGPT_Developer_Mode_v2", "dan.ChatGPT_Developer_Mode_RANTI",
		"dan.ChatGPT_Image_Markdown",
		// TAP (2)
		"tap.TAPv1", "tap.TAPv2",
		// PAIR (2)
		"pair.PAIR", "pair.PAIRBasic",
		// Goodside (6)
		"goodside.WhoIsRiley", "goodside.ThreatenJSON", "goodside.PoemExfiltration",
		"goodside.PayloadSplitting", "goodside.ChatMLExploit", "goodside.SystemPromptConfusion",
		// AdvPatch (3)
		"advpatch.UniversalPatch", "advpatch.TargetedPatch", "advpatch.TransferPatch",
		// LatentInjection (3)
		"latentinjection.LatentJailbreak", "latentinjection.LatentRefusal",
		"latentinjection.LatentExtraction",
	}

	registered := probes.List()

	for _, name := range expectedProbes {
		assert.Contains(t, registered, name, "probe %s should be registered", name)
	}

	// Verify count: 14 + 2 + 2 + 6 + 3 + 3 = 30 probes
	assert.GreaterOrEqual(t, len(registered), 30, "should have at least 30 probes registered")
}

func TestAllProbesExecutable(t *testing.T) {
	probeNames := []string{
		"dan.Dan_11_0", "tap.TAPv1", "pair.PAIR",
		"goodside.WhoIsRiley", "advpatch.UniversalPatch",
		"latentinjection.LatentJailbreak",
	}

	for _, name := range probeNames {
		t.Run(name, func(t *testing.T) {
			probe, err := probes.Create(name, nil)
			assert.NoError(t, err)
			assert.NotEmpty(t, probe.GetPrompts())
		})
	}
}
