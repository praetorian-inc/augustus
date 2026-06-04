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

func TestAudio_ToBase64_AllSources(t *testing.T) {
	// Base64 field takes precedence over Data; Data over Path.
	t.Run("Base64 field", func(t *testing.T) {
		a := &Audio{MimeType: "audio/wav", Base64: "QUJDRA=="}
		assert.Equal(t, "QUJDRA==", a.ToBase64())
	})
	t.Run("Data field", func(t *testing.T) {
		raw := []byte("wavdata")
		a := &Audio{MimeType: "audio/wav", Data: raw}
		assert.Equal(t, base64.StdEncoding.EncodeToString(raw), a.ToBase64())
	})
	t.Run("Path field", func(t *testing.T) {
		tmp := t.TempDir()
		fpath := filepath.Join(tmp, "test.wav")
		content := []byte("riff-fake")
		require.NoError(t, os.WriteFile(fpath, content, 0644))
		a := &Audio{MimeType: "audio/wav", Path: fpath}
		assert.Equal(t, base64.StdEncoding.EncodeToString(content), a.ToBase64())
	})
	t.Run("Empty", func(t *testing.T) {
		a := &Audio{MimeType: "audio/wav"}
		assert.Equal(t, "", a.ToBase64())
	})
	t.Run("Base64 takes priority over Data", func(t *testing.T) {
		a := &Audio{Base64: "frombase64", Data: []byte("fromdata")}
		assert.Equal(t, "frombase64", a.ToBase64())
	})
}

func TestDocument_ToBase64_AllSources(t *testing.T) {
	t.Run("Base64 field", func(t *testing.T) {
		d := &Document{MimeType: "application/pdf", Base64: "JVBERi0="}
		assert.Equal(t, "JVBERi0=", d.ToBase64())
	})
	t.Run("Data field", func(t *testing.T) {
		raw := []byte("%PDF-1.4")
		d := &Document{MimeType: "application/pdf", Data: raw}
		assert.Equal(t, base64.StdEncoding.EncodeToString(raw), d.ToBase64())
	})
	t.Run("Path field", func(t *testing.T) {
		tmp := t.TempDir()
		fpath := filepath.Join(tmp, "test.pdf")
		content := []byte("%PDF-fake")
		require.NoError(t, os.WriteFile(fpath, content, 0644))
		d := &Document{MimeType: "application/pdf", Path: fpath}
		assert.Equal(t, base64.StdEncoding.EncodeToString(content), d.ToBase64())
	})
	t.Run("Empty", func(t *testing.T) {
		d := &Document{MimeType: "application/pdf"}
		assert.Equal(t, "", d.ToBase64())
	})
	t.Run("Base64 takes priority over Data", func(t *testing.T) {
		d := &Document{Base64: "p1", Data: []byte("p2")}
		assert.Equal(t, "p1", d.ToBase64())
	})
}
