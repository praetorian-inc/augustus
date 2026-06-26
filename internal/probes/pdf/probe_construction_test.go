package pdf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/internal/probes/multimodal"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestPDFProbeConstruction(t *testing.T) {
	names := []string{
		"pdf.InvisibleText", "pdf.OffPageText", "pdf.OnePointFont",
		"pdf.MetadataInjection", "pdf.AnnotationInjection",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			factory, ok := probes.Get(name)
			require.True(t, ok, "%s must be registered", name)

			p, err := factory(nil)
			require.NoError(t, err)
			require.Equal(t, name, p.Name())

			bp, ok := p.(*multimodal.BaseMultimodalProbe)
			require.True(t, ok)
			assert.Equal(t, "multimodal.Canary", bp.GetPrimaryDetector())
			assert.True(t, bp.Covert)
			assert.NotEmpty(t, bp.Description())
			assert.NotEmpty(t, bp.Goal())

			docs := bp.GetDocuments()
			require.Len(t, docs, 1)
			assert.Equal(t, "application/pdf", docs[0].MimeType)
			assert.NotEmpty(t, docs[0].Data)
		})
	}
}

// TestPDFProbeCanaryOverride verifies an operator-supplied canary actually
// propagates to the prompt rather than the factory silently falling back to
// defaultCanary.
func TestPDFProbeCanaryOverride(t *testing.T) {
	const override = "PURPLE WALRUS 9931"
	names := []string{
		"pdf.InvisibleText", "pdf.OffPageText", "pdf.OnePointFont",
		"pdf.MetadataInjection", "pdf.AnnotationInjection",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			factory, ok := probes.Get(name)
			require.True(t, ok, "%s must be registered", name)

			p, err := factory(registry.Config{"canary": override})
			require.NoError(t, err)

			bp, ok := p.(*multimodal.BaseMultimodalProbe)
			require.True(t, ok)
			require.Len(t, bp.Prompts, 1)
			assert.Equal(t, override, bp.Prompts[0].Canary)
		})
	}
}
