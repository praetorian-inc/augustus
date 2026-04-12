package attempt

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestImage_ToBase64_WithBase64Field(t *testing.T) {
	img := &Image{
		MimeType: "image/png",
		Base64:   "dGVzdGRhdGE=",
	}
	assert.Equal(t, "dGVzdGRhdGE=", img.ToBase64())
}

func TestImage_ToBase64_WithDataField(t *testing.T) {
	raw := []byte("testdata")
	img := &Image{
		MimeType: "image/png",
		Data:     raw,
	}
	expected := base64.StdEncoding.EncodeToString(raw)
	assert.Equal(t, expected, img.ToBase64())
}

func TestImage_ToBase64_Base64TakesPriorityOverData(t *testing.T) {
	img := &Image{
		MimeType: "image/png",
		Base64:   "frombase64",
		Data:     []byte("fromdata"),
	}
	// Base64 field has priority
	assert.Equal(t, "frombase64", img.ToBase64())
}

func TestImage_ToBase64_WithPathField(t *testing.T) {
	tmp := t.TempDir()
	fpath := filepath.Join(tmp, "test.png")
	content := []byte("fakepngdata")
	require.NoError(t, os.WriteFile(fpath, content, 0644))

	img := &Image{
		MimeType: "image/png",
		Path:     fpath,
	}
	expected := base64.StdEncoding.EncodeToString(content)
	assert.Equal(t, expected, img.ToBase64())
}

func TestImage_ToBase64_Empty(t *testing.T) {
	img := &Image{MimeType: "image/png"}
	assert.Equal(t, "", img.ToBase64())
}

func TestImage_ToBase64_InvalidPath(t *testing.T) {
	img := &Image{
		MimeType: "image/png",
		Path:     "/nonexistent/path/image.png",
	}
	assert.Equal(t, "", img.ToBase64())
}
