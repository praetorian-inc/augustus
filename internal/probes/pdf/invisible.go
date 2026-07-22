package pdf

import (
	"fmt"

	"github.com/praetorian-inc/augustus/internal/probes/pdf/pdfbuild"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() { probes.Register("pdf.InvisibleText", newInvisibleText) }

func newInvisibleText(cfg registry.Config) (probes.Prober, error) {
	canary, err := resolveCanary(cfg)
	if err != nil {
		return nil, fmt.Errorf("pdf.InvisibleText: %w", err)
	}
	data, err := pdfbuild.InvisibleText(canary)
	if err != nil {
		return nil, fmt.Errorf("pdf.InvisibleText: %w", err)
	}
	return docProbe(
		"pdf.InvisibleText",
		"extract white-on-white hidden text from a PDF",
		"Embeds adversarial canary text as white glyphs on the white page background — invisible to a human reader but present in the PDF text layer a model parses.",
		canary, data,
	), nil
}
