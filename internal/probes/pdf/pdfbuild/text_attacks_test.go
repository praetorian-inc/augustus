package pdfbuild

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/stretchr/testify/require"
)

// contentContains reports whether the canary appears in any page content stream.
func contentContains(t *testing.T, pdf []byte, canary string) bool {
	t.Helper()
	found := false
	// ExtractContent's digest callback is func(io.Reader, int) error in pdfcpu
	// v0.13.0 (the int is the 1-based page number) — verified against source.
	err := api.ExtractContent(bytes.NewReader(pdf), nil, func(r io.Reader, _ int) error {
		b, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), canary) {
			found = true
		}
		return nil
	}, model.NewDefaultConfiguration())
	require.NoError(t, err)
	return found
}

func TestTextAttacks(t *testing.T) {
	const canary = "MARITIME GIRAFFE 4827"
	builders := map[string]func(string) ([]byte, error){
		"InvisibleText": InvisibleText,
		"OffPageText":   OffPageText,
		"OnePointFont":  OnePointFont,
	}
	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			data, err := build(canary)
			require.NoError(t, err)
			require.NoError(t, api.Validate(bytes.NewReader(data), model.NewDefaultConfiguration()))
			require.True(t, contentContains(t, data, canary), "canary must be present in the content stream")
		})
	}
}
