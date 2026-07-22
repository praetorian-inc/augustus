package googleai

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

func TestBuildDocumentParts_PDF(t *testing.T) {
	data := []byte("%PDF-1.4 fake pdf bytes")
	docs := []attempt.Document{{Data: data, MimeType: "application/pdf"}}

	parts, err := BuildDocumentParts(docs)
	require.NoError(t, err)
	require.Len(t, parts, 1)
	require.NotNil(t, parts[0].InlineData)
	assert.Equal(t, "application/pdf", parts[0].InlineData.MimeType)
	assert.Equal(t, base64.StdEncoding.EncodeToString(data), parts[0].InlineData.Data)
	assert.Empty(t, parts[0].Text)
}

func TestBuildDocumentParts_MultipleAndBase64Source(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte("second"))
	docs := []attempt.Document{
		{Data: []byte("first"), MimeType: "application/pdf"},
		{Base64: b64, MimeType: "application/pdf"},
	}

	parts, err := BuildDocumentParts(docs)
	require.NoError(t, err)
	require.Len(t, parts, 2)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("first")), parts[0].InlineData.Data)
	assert.Equal(t, b64, parts[1].InlineData.Data)
}

func TestBuildDocumentParts_EmptyInput(t *testing.T) {
	parts, err := BuildDocumentParts(nil)
	require.NoError(t, err)
	assert.Empty(t, parts)
}

func TestBuildDocumentParts_EmptyMIME(t *testing.T) {
	_, err := BuildDocumentParts([]attempt.Document{{Data: []byte("x")}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty MIME type")
}

func TestBuildDocumentParts_UnsupportedMIME(t *testing.T) {
	_, err := BuildDocumentParts([]attempt.Document{{Data: []byte("x"), MimeType: "image/png"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported document MIME type")
}

func TestBuildDocumentParts_NoData(t *testing.T) {
	_, err := BuildDocumentParts([]attempt.Document{{MimeType: "application/pdf"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no data")
}
