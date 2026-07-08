package pdfbuild

import (
	"bytes"
	"testing"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/stretchr/testify/require"
)

func TestTextPagePDF_ValidAndContainsText(t *testing.T) {
	data, err := textPagePDF([]textElem{
		{value: "HELLO CANARY", pos: [2]int{72, 700}, size: 12, col: "Black"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, data)
	require.Equal(t, "%PDF", string(data[:4]), "must be a PDF")
	require.NoError(t, api.Validate(bytes.NewReader(data), model.NewDefaultConfiguration()))
}
