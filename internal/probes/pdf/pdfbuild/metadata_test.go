package pdfbuild

import (
	"bytes"
	"testing"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/stretchr/testify/require"
)

func TestMetadataInjection(t *testing.T) {
	const canary = "MARITIME GIRAFFE 4827"
	data, err := MetadataInjection(canary)
	require.NoError(t, err)
	require.NoError(t, api.Validate(bytes.NewReader(data), model.NewDefaultConfiguration()))

	// pdfcpu intercepts the standard Info keys (Title/Subject/Keywords) on READ and
	// routes them to dedicated fields — they do NOT appear in api.Properties()'s map
	// (verified against v0.13.0: pkg/pdfcpu/validate/info.go:113 has `case "Title":`).
	// Read them back via api.PDFInfo, which exposes Title/Subject/Keywords directly
	// (pkg/pdfcpu/info.go:579 `info.Title = ctx.Title`, :603 Keywords, :605 Properties).
	// NOTE: info.Keywords is a []string (NOT a string) — Contains here asserts the
	// canary is an exact slice element, which holds only because the default canary
	// has no comma/semicolon delimiter (see resolveCanary note in Task 7).
	info, err := api.PDFInfo(bytes.NewReader(data), "", nil, false, model.NewDefaultConfiguration())
	require.NoError(t, err)
	require.Equal(t, canary, info.Title)
	require.Equal(t, canary, info.Subject)
	require.Contains(t, info.Keywords, canary)
}
