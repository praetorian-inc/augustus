package pdf

import (
	"fmt"

	"github.com/praetorian-inc/augustus/internal/probes/pdf/pdfbuild"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() { probes.Register("pdf.MetadataInjection", newMetadataInjection) }

func newMetadataInjection(cfg registry.Config) (probes.Prober, error) {
	canary := resolveCanary(cfg)
	data, err := pdfbuild.MetadataInjection(canary)
	if err != nil {
		return nil, fmt.Errorf("pdf.MetadataInjection: %w", err)
	}
	return docProbe(
		"pdf.MetadataInjection",
		"extract adversarial text from PDF metadata",
		"Hides adversarial canary text in the PDF Info dictionary (Title/Subject) and Keywords — metadata a model ingests but a human reading the page never sees.",
		canary, data,
	), nil
}
