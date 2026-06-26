package pdfbuild

import (
	"bytes"
	"strings"
	"testing"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/stretchr/testify/require"
)

func TestAnnotationInjection(t *testing.T) {
	const canary = "MARITIME GIRAFFE 4827"
	data, err := AnnotationInjection(canary)
	require.NoError(t, err)
	require.NoError(t, api.Validate(bytes.NewReader(data), model.NewDefaultConfiguration()))

	annots, err := api.Annotations(bytes.NewReader(data), nil, model.NewDefaultConfiguration())
	require.NoError(t, err)

	// api.Annotations returns map[int]model.PgAnnots, where
	// PgAnnots = map[AnnotationType]Annot and Annot.Map = map[int]AnnotationRenderer.
	// ContentString() lives on the AnnotationRenderer (3rd level), NOT on Annot.
	// Verified against pdfcpu v0.13.0 source.
	found := false
	for _, pgAnnots := range annots { // map[AnnotationType]Annot
		for _, annot := range pgAnnots { // model.Annot
			for _, ar := range annot.Map { // model.AnnotationRenderer
				if strings.Contains(ar.ContentString(), canary) {
					found = true
				}
			}
		}
	}
	require.True(t, found, "canary must appear in an annotation's contents")
}
