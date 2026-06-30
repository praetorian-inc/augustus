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
	got, err := img.ToBase64()
	require.NoError(t, err)
	assert.Equal(t, "dGVzdGRhdGE=", got)
}

func TestImage_ToBase64_WithDataField(t *testing.T) {
	raw := []byte("testdata")
	img := &Image{
		MimeType: "image/png",
		Data:     raw,
	}
	expected := base64.StdEncoding.EncodeToString(raw)
	got, err := img.ToBase64()
	require.NoError(t, err)
	assert.Equal(t, expected, got)
}

func TestImage_ToBase64_Base64TakesPriorityOverData(t *testing.T) {
	img := &Image{
		MimeType: "image/png",
		Base64:   "frombase64",
		Data:     []byte("fromdata"),
	}
	// Base64 field has priority
	got, err := img.ToBase64()
	require.NoError(t, err)
	assert.Equal(t, "frombase64", got)
}

func TestImage_ToBase64_WithPathField(t *testing.T) {
	tmp := t.TempDir()
	fpath := filepath.Join(tmp, "test.png")
	content := []byte("fakepngdata")
	require.NoError(t, os.WriteFile(fpath, content, 0o644))

	img := &Image{
		MimeType: "image/png",
		Path:     fpath,
	}
	expected := base64.StdEncoding.EncodeToString(content)
	got, err := img.ToBase64()
	require.NoError(t, err)
	assert.Equal(t, expected, got)
}

func TestImage_ToBase64_Empty(t *testing.T) {
	img := &Image{MimeType: "image/png"}
	got, err := img.ToBase64()
	require.NoError(t, err)
	assert.Equal(t, "", got)
}

func TestImage_ToBase64_InvalidPath(t *testing.T) {
	img := &Image{
		MimeType: "image/png",
		Path:     "/nonexistent/path/image.png",
	}
	// A configured-but-unreadable Path must surface the I/O error rather than
	// silently returning an empty string (which would ship an empty image part).
	got, err := img.ToBase64()
	require.Error(t, err)
	assert.Empty(t, got)
}

func TestAudio_ToBase64_AllSources(t *testing.T) {
	// Base64 field takes precedence over Data; Data over Path.
	t.Run("Base64 field", func(t *testing.T) {
		a := &Audio{MimeType: "audio/wav", Base64: "QUJDRA=="}
		got, err := a.ToBase64()
		require.NoError(t, err)
		assert.Equal(t, "QUJDRA==", got)
	})
	t.Run("Data field", func(t *testing.T) {
		raw := []byte("wavdata")
		a := &Audio{MimeType: "audio/wav", Data: raw}
		got, err := a.ToBase64()
		require.NoError(t, err)
		assert.Equal(t, base64.StdEncoding.EncodeToString(raw), got)
	})
	t.Run("Path field", func(t *testing.T) {
		tmp := t.TempDir()
		fpath := filepath.Join(tmp, "test.wav")
		content := []byte("riff-fake")
		require.NoError(t, os.WriteFile(fpath, content, 0o644))
		a := &Audio{MimeType: "audio/wav", Path: fpath}
		got, err := a.ToBase64()
		require.NoError(t, err)
		assert.Equal(t, base64.StdEncoding.EncodeToString(content), got)
	})
	t.Run("Empty", func(t *testing.T) {
		a := &Audio{MimeType: "audio/wav"}
		got, err := a.ToBase64()
		require.NoError(t, err)
		assert.Equal(t, "", got)
	})
	t.Run("Base64 takes priority over Data", func(t *testing.T) {
		a := &Audio{Base64: "frombase64", Data: []byte("fromdata")}
		got, err := a.ToBase64()
		require.NoError(t, err)
		assert.Equal(t, "frombase64", got)
	})
}

func TestImage_Bytes_WithDataField(t *testing.T) {
	img := &Image{
		MimeType: "image/png",
		Data:     []byte("hello"),
	}
	got, err := img.Bytes()
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), got)
}

func TestImage_Bytes_WithBase64Field(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("hello"))
	img := &Image{
		MimeType: "image/png",
		Base64:   encoded,
		// Data intentionally nil to exercise Base64 path
	}
	got, err := img.Bytes()
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), got)
}

func TestImage_Bytes_WithPathField(t *testing.T) {
	tmp := t.TempDir()
	fpath := filepath.Join(tmp, "test.png")
	content := []byte("filebytes")
	require.NoError(t, os.WriteFile(fpath, content, 0o644))

	img := &Image{
		MimeType: "image/png",
		Path:     fpath,
		// Data and Base64 intentionally unset to exercise Path path
	}
	got, err := img.Bytes()
	require.NoError(t, err)
	assert.Equal(t, content, got)
}

func TestImage_Bytes_Empty(t *testing.T) {
	img := &Image{}
	got, err := img.Bytes()
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestImage_Bytes_InvalidBase64(t *testing.T) {
	img := &Image{
		MimeType: "image/png",
		Base64:   "!!!not base64!!!",
	}
	got, err := img.Bytes()
	require.Error(t, err)
	assert.Nil(t, got)
}

func TestImage_Bytes_InvalidPath(t *testing.T) {
	img := &Image{
		MimeType: "image/png",
		Path:     "/nonexistent/does-not-exist.png",
	}
	got, err := img.Bytes()
	require.Error(t, err)
	assert.Nil(t, got)
}

func TestDocument_ToBase64_AllSources(t *testing.T) {
	t.Run("Base64 field", func(t *testing.T) {
		d := &Document{MimeType: "application/pdf", Base64: "JVBERi0="}
		got, err := d.ToBase64()
		require.NoError(t, err)
		assert.Equal(t, "JVBERi0=", got)
	})
	t.Run("Data field", func(t *testing.T) {
		raw := []byte("%PDF-1.4")
		d := &Document{MimeType: "application/pdf", Data: raw}
		got, err := d.ToBase64()
		require.NoError(t, err)
		assert.Equal(t, base64.StdEncoding.EncodeToString(raw), got)
	})
	t.Run("Path field", func(t *testing.T) {
		tmp := t.TempDir()
		fpath := filepath.Join(tmp, "test.pdf")
		content := []byte("%PDF-fake")
		require.NoError(t, os.WriteFile(fpath, content, 0o644))
		d := &Document{MimeType: "application/pdf", Path: fpath}
		got, err := d.ToBase64()
		require.NoError(t, err)
		assert.Equal(t, base64.StdEncoding.EncodeToString(content), got)
	})
	t.Run("Empty", func(t *testing.T) {
		d := &Document{MimeType: "application/pdf"}
		got, err := d.ToBase64()
		require.NoError(t, err)
		assert.Equal(t, "", got)
	})
	t.Run("Base64 takes priority over Data", func(t *testing.T) {
		d := &Document{Base64: "p1", Data: []byte("p2")}
		got, err := d.ToBase64()
		require.NoError(t, err)
		assert.Equal(t, "p1", got)
	})
}
