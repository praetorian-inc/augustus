package multimodal

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProbeConstruction(t *testing.T) {
	tests := []struct {
		name         string
		factory      func(registry.Config) (probes.Prober, error)
		expectedName string
		promptCount  int
	}{
		{"InstructionImage", newInstructionImageProbe, "multimodal.InstructionImage", 3},
		{"InvisibleText", newInvisibleTextProbe, "multimodal.InvisibleText", 3},
		{"TextOverlay", newTextOverlayProbe, "multimodal.TextOverlay", 3},
		{"ScalingNearestNeighbor", newScalingNearestNeighborProbe, "multimodal.ScalingNearestNeighbor", 1},
		{"ScalingBicubic", newScalingBicubicProbe, "multimodal.ScalingBicubic", 1},
		{"ScalingBilinear", newScalingBilinearProbe, "multimodal.ScalingBilinear", 1},
		{"SteganographicLSB", newSteganographicLSBProbe, "multimodal.SteganographicLSB", 1},
		{"MetadataInjection", newMetadataInjectionProbe, "multimodal.MetadataInjection", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := tt.factory(nil)
			require.NoError(t, err)
			require.NotNil(t, p)

			// Verify probe name via Prober interface.
			assert.Equal(t, tt.expectedName, p.Name())

			// Cast to BaseMultimodalProbe to access full metadata.
			bp, ok := p.(*BaseMultimodalProbe)
			require.True(t, ok, "probe should be a *BaseMultimodalProbe")

			assert.Equal(t, "multimodal.Canary", bp.GetPrimaryDetector())
			assert.NotEmpty(t, bp.Description())
			assert.NotEmpty(t, bp.Goal())

			// Verify prompts.
			prompts := bp.GetPrompts()
			assert.Len(t, prompts, tt.promptCount)
			for i, prompt := range prompts {
				assert.NotEmpty(t, prompt, "prompt %d should not be empty", i)
			}

			// Verify images via MultimodalProbe interface.
			images := bp.GetImages()
			assert.Len(t, images, tt.promptCount, "should have one image per prompt")
			for i, img := range images {
				assert.Equal(t, "image/png", img.MimeType, "image %d should be PNG", i)
				assert.NotEmpty(t, img.Data, "image %d should have non-empty data", i)
			}

			// Verify audio is nil (image-only probes).
			assert.Nil(t, bp.GetAudio())
		})
	}
}

func TestProbeRegistration(t *testing.T) {
	names := []string{
		"multimodal.InstructionImage",
		"multimodal.InvisibleText",
		"multimodal.TextOverlay",
		"multimodal.ScalingNearestNeighbor",
		"multimodal.ScalingBicubic",
		"multimodal.ScalingBilinear",
		"multimodal.SteganographicLSB",
		"multimodal.MetadataInjection",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			factory, ok := probes.Get(name)
			assert.True(t, ok, "%s should be registered in the global probe registry", name)
			assert.NotNil(t, factory)
		})
	}
}
