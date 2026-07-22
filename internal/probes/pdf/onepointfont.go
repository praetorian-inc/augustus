package pdf

import (
	"fmt"

	"github.com/praetorian-inc/augustus/internal/probes/pdf/pdfbuild"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() { probes.Register("pdf.OnePointFont", newOnePointFont) }

func newOnePointFont(cfg registry.Config) (probes.Prober, error) {
	canary, err := resolveCanary(cfg)
	if err != nil {
		return nil, fmt.Errorf("pdf.OnePointFont: %w", err)
	}
	data, err := pdfbuild.OnePointFont(canary)
	if err != nil {
		return nil, fmt.Errorf("pdf.OnePointFont: %w", err)
	}
	return docProbe(
		"pdf.OnePointFont",
		"extract sub-pixel 1pt hidden text from a PDF",
		"Renders adversarial canary text at a 1pt sub-pixel font size — illegible to a human but parseable from the PDF text layer by a model.",
		canary, data,
	), nil
}
