package stego

import (
	"image"
	"image/color"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLSBEmbed_EmbedsTextInImage verifies LSB embedding works.
func TestLSBEmbed_EmbedsTextInImage(t *testing.T) {
	// Create a small test image (10x10 RGBA)
	img := image.NewRGBA(image.Rect(0, 0, 10, 10))
	// Fill with white
	for y := 0; y < 10; y++ {
		for x := 0; x < 10; x++ {
			img.Set(x, y, color.RGBA{R: 255, G: 255, B: 255, A: 255})
		}
	}

	message := "Hello"

	result, err := LSBEmbed(img, message)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify result is an image
	bounds := result.Bounds()
	assert.Equal(t, img.Bounds(), bounds, "embedded image should have same dimensions")
}

// TestLSBEmbed_ErrorsOnNilImage verifies error handling for nil image.
func TestLSBEmbed_ErrorsOnNilImage(t *testing.T) {
	_, err := LSBEmbed(nil, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "image")
}

// TestLSBEmbed_ErrorsOnEmptyMessage verifies error handling for empty message.
func TestLSBEmbed_ErrorsOnEmptyMessage(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 10, 10))
	_, err := LSBEmbed(img, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "message")
}

// TestLSBEmbed_ErrorsOnMessageTooLarge verifies error when message doesn't fit.
func TestLSBEmbed_ErrorsOnMessageTooLarge(t *testing.T) {
	// Create very small image (2x2)
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))

	// Try to embed a message that's too large
	// Each pixel can store 3 bits (R, G, B LSBs), so 2x2 = 4 pixels = 12 bits = 1.5 bytes
	// A message of 10 bytes should fail
	longMessage := "1234567890"

	_, err := LSBEmbed(img, longMessage)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

// TestLSBExtract_ExtractsEmbeddedText verifies extraction of embedded text.
func TestLSBExtract_ExtractsEmbeddedText(t *testing.T) {
	// Create image
	img := image.NewRGBA(image.Rect(0, 0, 20, 20))
	for y := 0; y < 20; y++ {
		for x := 0; x < 20; x++ {
			img.Set(x, y, color.RGBA{R: 255, G: 255, B: 255, A: 255})
		}
	}

	message := "Secret"

	// Embed
	embedded, err := LSBEmbed(img, message)
	require.NoError(t, err)

	// Extract
	extracted, err := LSBExtract(embedded)
	require.NoError(t, err)
	assert.Equal(t, message, extracted)
}

// TestLSBExtract_ErrorsOnNilImage verifies error handling for nil image.
func TestLSBExtract_ErrorsOnNilImage(t *testing.T) {
	_, err := LSBExtract(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "image")
}

// TestLSBEmbed_ModifiesOnlyLSBs verifies only least significant bits are changed.
func TestLSBEmbed_ModifiesOnlyLSBs(t *testing.T) {
	// Create image with known pixel values
	img := image.NewRGBA(image.Rect(0, 0, 10, 10))
	// Fill with specific color (even values so LSB is 0)
	testColor := color.RGBA{R: 200, G: 150, B: 100, A: 255}
	for y := 0; y < 10; y++ {
		for x := 0; x < 10; x++ {
			img.Set(x, y, testColor)
		}
	}

	message := "Hi"

	embedded, err := LSBEmbed(img, message)
	require.NoError(t, err)

	// Check that pixel values changed by at most 1 (LSB flip)
	rgba, ok := embedded.(*image.RGBA)
	require.True(t, ok, "embedded image should be RGBA")

	for y := 0; y < 10; y++ {
		for x := 0; x < 10; x++ {
			r, g, b, a := rgba.At(x, y).RGBA()
			// Convert from uint32 (0-65535 range) to uint8 (0-255 range)
			rByte := uint8(r >> 8)
			gByte := uint8(g >> 8)
			bByte := uint8(b >> 8)

			// Each channel should differ by at most 1 from original
			assert.LessOrEqual(t, abs(int(rByte)-int(testColor.R)), 1)
			assert.LessOrEqual(t, abs(int(gByte)-int(testColor.G)), 1)
			assert.LessOrEqual(t, abs(int(bByte)-int(testColor.B)), 1)
			assert.Equal(t, uint8(a>>8), testColor.A, "alpha should not change")
		}
	}
}

// TestLSBEmbed_RoundTrip verifies embed + extract returns original message.
func TestLSBEmbed_RoundTrip(t *testing.T) {
	testCases := []struct {
		name    string
		message string
	}{
		{"simple", "Test"},
		{"withspaces", "Hello World"},
		{"withpunctuation", "Hi! How are you?"},
		{"numbers", "12345"},
		{"mixed", "Test123!@#"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			img := image.NewRGBA(image.Rect(0, 0, 30, 30))
			for y := 0; y < 30; y++ {
				for x := 0; x < 30; x++ {
					img.Set(x, y, color.RGBA{R: 128, G: 128, B: 128, A: 255})
				}
			}

			embedded, err := LSBEmbed(img, tc.message)
			require.NoError(t, err)

			extracted, err := LSBExtract(embedded)
			require.NoError(t, err)
			assert.Equal(t, tc.message, extracted)
		})
	}
}

// Helper function for absolute value
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
