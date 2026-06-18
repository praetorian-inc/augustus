package pdf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/internal/probes/multimodal"
	"github.com/praetorian-inc/augustus/pkg/probes"
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
