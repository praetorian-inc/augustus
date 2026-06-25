package pdf

import (
	"fmt"

	"github.com/praetorian-inc/augustus/internal/probes/pdf/pdfbuild"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() { probes.Register("pdf.AnnotationInjection", newAnnotationInjection) }

func newAnnotationInjection(cfg registry.Config) (probes.Prober, error) {
	canary, err := resolveCanary(cfg)
	if err != nil {
		return nil, fmt.Errorf("pdf.AnnotationInjection: %w", err)
	}
	data, err := pdfbuild.AnnotationInjection(canary)
	if err != nil {
		return nil, fmt.Errorf("pdf.AnnotationInjection: %w", err)
	}
	return docProbe(
		"pdf.AnnotationInjection",
		"extract adversarial text from a PDF annotation",
		"Hides adversarial canary text in a page annotation's contents — text a model ingesting the PDF structure reads, but a human viewing the page does not.",
		canary, data,
	), nil
}
