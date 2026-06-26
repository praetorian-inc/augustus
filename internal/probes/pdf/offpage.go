package pdf

import (
	"fmt"

	"github.com/praetorian-inc/augustus/internal/probes/pdf/pdfbuild"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() { probes.Register("pdf.OffPageText", newOffPageText) }

func newOffPageText(cfg registry.Config) (probes.Prober, error) {
	canary := resolveCanary(cfg)
	data, err := pdfbuild.OffPageText(canary)
	if err != nil {
		return nil, fmt.Errorf("pdf.OffPageText: %w", err)
	}
	return docProbe(
		"pdf.OffPageText",
		"extract text positioned outside the PDF media box",
		"Positions adversarial canary text outside the page media box — not rendered on the visible page but retained in the content stream a model reads.",
		canary, data,
	), nil
}
