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

// TestPDFProbeRejectsMalformedCanary verifies an operator-supplied canary
// containing a character that cannot round-trip through the PDF channels is
// rejected at construction rather than silently scoring 0.0 at scan time.
func TestPDFProbeRejectsMalformedCanary(t *testing.T) {
	names := []string{
		"pdf.InvisibleText", "pdf.OffPageText", "pdf.OnePointFont",
		"pdf.MetadataInjection", "pdf.AnnotationInjection",
	}
	for _, bad := range []string{"with(paren", "comma,split", "semi;colon", "back\\slash", "new\nline"} {
		for _, name := range names {
			t.Run(name+"/"+bad, func(t *testing.T) {
				factory, ok := probes.Get(name)
				require.True(t, ok, "%s must be registered", name)

				_, err := factory(registry.Config{"canary": bad})
				require.Error(t, err, "malformed canary %q must be rejected", bad)
			})
		}
	}
}

// TestPDFProbeAcceptsValidCanaryOverride confirms a well-formed override is
// accepted and embedded.
func TestPDFProbeAcceptsValidCanaryOverride(t *testing.T) {
	factory, ok := probes.Get("pdf.InvisibleText")
	require.True(t, ok)

	p, err := factory(registry.Config{"canary": "PURPLE WALRUS 9931"})
	require.NoError(t, err)

	bp, ok := p.(*multimodal.BaseMultimodalProbe)
	require.True(t, ok)
	require.Len(t, bp.GetDocuments(), 1)
	assert.NotEmpty(t, bp.GetDocuments()[0].Data)
}
