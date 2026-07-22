package pdf

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/internal/probes/multimodal"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// pdfProbeNames is the list of all registered PDF probe names, shared across the
// construction and canary tests so adding a probe updates coverage in one place.
var pdfProbeNames = []string{
	"pdf.InvisibleText", "pdf.OffPageText", "pdf.OnePointFont",
	"pdf.MetadataInjection", "pdf.AnnotationInjection",
}

func TestPDFProbeConstruction(t *testing.T) {
	for _, name := range pdfProbeNames {
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
	for _, name := range pdfProbeNames {
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

// TestValidateCanary checks the charset enforcement directly: compliant canaries
// pass, and each forbidden-character class is rejected with a descriptive error.
func TestValidateCanary(t *testing.T) {
	t.Run("compliant", func(t *testing.T) {
		for _, ok := range []string{
			defaultCanary,           // the default must always pass
			"PURPLE WALRUS 9931",    // spaces and digits are fine
			"canary-with_symbols!?", // other printable ASCII is fine
		} {
			assert.NoError(t, validateCanary(ok), "expected %q to be accepted", ok)
		}
	})

	t.Run("forbidden", func(t *testing.T) {
		for _, bad := range []string{
			"open (paren",
			"close paren)",
			`back\slash`,
			"comma,delimited",
			"semi;colon",
			"line\nbreak",                       // newline is not printable ASCII
			"tab\tinside",                       // control character
			"unicode-é",                         // non-ASCII rune
			strings.Repeat("A", maxCanaryLen+1), // exceeds the length bound
		} {
			assert.Error(t, validateCanary(bad), "expected %q to be rejected", bad)
		}
	})

	t.Run("max length boundary", func(t *testing.T) {
		assert.NoError(t, validateCanary(strings.Repeat("A", maxCanaryLen)),
			"a canary exactly at the length bound should be accepted")
	})
}

// TestPDFProbeRejectsMalformedCanary verifies a forbidden operator canary fails at
// probe construction with an actionable error naming the probe, rather than
// surfacing later as a broken PDF/metadata round-trip mid-scan.
func TestPDFProbeRejectsMalformedCanary(t *testing.T) {
	for _, name := range pdfProbeNames {
		t.Run(name, func(t *testing.T) {
			factory, ok := probes.Get(name)
			require.True(t, ok, "%s must be registered", name)

			p, err := factory(registry.Config{"canary": "bad,canary;value"})
			require.Error(t, err)
			assert.Nil(t, p)
			assert.Contains(t, err.Error(), name, "error should name the probe")
			assert.Contains(t, err.Error(), "canary", "error should describe the problem")
		})
	}
}
