package multimodal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestMimeFromExt(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"image.png", "image/png"},
		{"photo.jpg", "image/jpeg"},
		{"photo.jpeg", "image/jpeg"},
		{"anim.gif", "image/gif"},
		{"pic.webp", "image/webp"},
		{"UPPER.PNG", "image/png"},
		{"/abs/path/to/file.JPG", "image/jpeg"},
		{"noext", ""},
		{"file.bmp", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, mimeFromExt(tt.path))
		})
	}
}

func TestResolveAsset_DefaultPath(t *testing.T) {
	img, canary, err := resolveAsset(
		nil,
		"data/instruction/instruction_canary1.png",
		"image/png",
		"PINEAPPLE SUNSET 7319",
	)
	require.NoError(t, err)
	assert.NotEmpty(t, img.Data, "embedded default should yield non-empty bytes")
	assert.Equal(t, "image/png", img.MimeType)
	assert.Equal(t, "PINEAPPLE SUNSET 7319", canary)
}

func TestResolveAsset_CustomImageAndCanary(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "custom.png")
	want := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A} // PNG header bytes
	require.NoError(t, os.WriteFile(custom, want, 0o600))

	img, canary, err := resolveAsset(
		registry.Config{"image": custom, "canary": "CUSTOM PHRASE 1234"},
		"data/instruction/instruction_canary1.png",
		"image/png",
		"PINEAPPLE SUNSET 7319",
	)
	require.NoError(t, err)
	assert.Equal(t, want, img.Data, "custom image bytes should be returned verbatim")
	assert.Equal(t, "image/png", img.MimeType)
	assert.Equal(t, "CUSTOM PHRASE 1234", canary)
}

func TestResolveAsset_ImagePathAlias(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "custom.jpg")
	want := []byte{0xFF, 0xD8, 0xFF} // JPEG header bytes
	require.NoError(t, os.WriteFile(custom, want, 0o600))

	img, canary, err := resolveAsset(
		registry.Config{"image_path": custom},
		"data/instruction/instruction_canary1.png",
		"image/png",
		"PINEAPPLE SUNSET 7319",
	)
	require.NoError(t, err)
	assert.Equal(t, want, img.Data)
	assert.Equal(t, "image/jpeg", img.MimeType, "MIME inferred from .jpg extension")
	assert.Equal(t, "PINEAPPLE SUNSET 7319", canary, "default canary kept when none provided")
}

func TestResolveAsset_CustomMimeOverride(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "blob.dat")
	require.NoError(t, os.WriteFile(custom, []byte("data"), 0o600))

	img, _, err := resolveAsset(
		registry.Config{"image": custom, "mime_type": "image/webp"},
		"data/instruction/instruction_canary1.png",
		"image/png",
		"PINEAPPLE SUNSET 7319",
	)
	require.NoError(t, err)
	assert.Equal(t, "image/webp", img.MimeType, "explicit mime_type overrides extension inference")
}

func TestResolveAsset_UnknownExtensionNoMime(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "blob.dat")
	require.NoError(t, os.WriteFile(custom, []byte("data"), 0o600))

	_, _, err := resolveAsset(
		registry.Config{"image": custom},
		"data/instruction/instruction_canary1.png",
		"image/png",
		"PINEAPPLE SUNSET 7319",
	)
	require.Error(t, err, "unknown extension without mime_type must error")
	assert.Contains(t, err.Error(), "mime_type")
}

func TestResolveAsset_MimeTypeValidation(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "blob.dat")
	require.NoError(t, os.WriteFile(custom, []byte("data"), 0o600))

	t.Run("non-image mime_type errors", func(t *testing.T) {
		_, _, err := resolveAsset(
			registry.Config{"image": custom, "mime_type": "text/plain"},
			"data/instruction/instruction_canary1.png",
			"image/png",
			"PINEAPPLE SUNSET 7319",
		)
		require.Error(t, err, "non-image mime_type must error")
		assert.Contains(t, err.Error(), "expected image/*")
	})

	t.Run("image mime_type succeeds", func(t *testing.T) {
		img, _, err := resolveAsset(
			registry.Config{"image": custom, "mime_type": "image/png"},
			"data/instruction/instruction_canary1.png",
			"image/png",
			"PINEAPPLE SUNSET 7319",
		)
		require.NoError(t, err)
		assert.Equal(t, "image/png", img.MimeType)
	})
}

func TestResolveAsset_MissingCustomFile(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.png")
	_, _, err := resolveAsset(
		registry.Config{"image": missing},
		"data/instruction/instruction_canary1.png",
		"image/png",
		"PINEAPPLE SUNSET 7319",
	)
	require.Error(t, err, "unreadable custom image must surface a wrapped error")
}

func TestInstructionProbe_CustomCanaryFlowsToPrompt(t *testing.T) {
	p, err := newInstructionImageProbe(registry.Config{"canary": "CUSTOM PHRASE 1234"})
	require.NoError(t, err)

	bp, ok := p.(*BaseMultimodalProbe)
	require.True(t, ok)
	require.Len(t, bp.Prompts, 1)
	assert.Equal(t, "CUSTOM PHRASE 1234", bp.Prompts[0].Canary)
}

func TestSceneTAP_CustomImageProducesSinglePrompt(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "scene.png")
	require.NoError(t, os.WriteFile(custom, []byte{0x89, 0x50, 0x4E, 0x47}, 0o600))

	p, err := newSceneTAPTypographicProbe(registry.Config{"image": custom, "canary": "STEERED 5555"})
	require.NoError(t, err)

	bp, ok := p.(*BaseMultimodalProbe)
	require.True(t, ok)
	require.Len(t, bp.Prompts, 1, "custom image steers SceneTAP to a single prompt")
	assert.Equal(t, "STEERED 5555", bp.Prompts[0].Canary)
}

func TestSceneTAP_DefaultKeepsBothScenes(t *testing.T) {
	p, err := newSceneTAPTypographicProbe(nil)
	require.NoError(t, err)

	bp, ok := p.(*BaseMultimodalProbe)
	require.True(t, ok)
	require.Len(t, bp.Prompts, 2, "no custom image keeps both default scenes")
	assert.Equal(t, "CRIMSON TORNADO 4825", bp.Prompts[0].Canary)
	assert.Equal(t, "VIOLET HORIZON 6037", bp.Prompts[1].Canary)
}
