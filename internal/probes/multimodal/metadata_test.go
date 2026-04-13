package multimodal

import (
	"bytes"
	"image"
	"image/png"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreatePNGWithTextChunk(t *testing.T) {
	t.Run("produces valid PNG with tEXt chunk", func(t *testing.T) {
		data, err := createPNGWithTextChunk("Comment", "test value")
		require.NoError(t, err)
		require.NotEmpty(t, data)

		// Must be decodable as a valid PNG.
		_, err = png.Decode(bytes.NewReader(data))
		require.NoError(t, err)

		// tEXt chunk must be present.
		offset := findChunkOffset(data, "tEXt")
		assert.Greater(t, offset, 0, "tEXt chunk should be found in the PNG")
	})

	t.Run("tEXt chunk is inserted before IDAT", func(t *testing.T) {
		data, err := createPNGWithTextChunk("Key", "Value")
		require.NoError(t, err)

		textOffset := findChunkOffset(data, "tEXt")
		idatOffset := findChunkOffset(data, "IDAT")
		require.Greater(t, textOffset, 0)
		require.Greater(t, idatOffset, 0)
		assert.Less(t, textOffset, idatOffset, "tEXt should appear before IDAT")
	})

	t.Run("tEXt chunk contains keyword and value", func(t *testing.T) {
		keyword := "Description"
		value := "Hello World"
		data, err := createPNGWithTextChunk(keyword, value)
		require.NoError(t, err)

		textOffset := findChunkOffset(data, "tEXt")
		require.Greater(t, textOffset, 0)

		// The chunk data starts after 4-byte length + 4-byte type = offset+8.
		// It contains: keyword + \x00 + value.
		expected := append([]byte(keyword), 0x00)
		expected = append(expected, []byte(value)...)

		// Read chunk length to know how much data to check.
		chunkDataStart := textOffset + 8
		chunkDataEnd := chunkDataStart + len(expected)
		require.LessOrEqual(t, chunkDataEnd, len(data))
		assert.Equal(t, expected, data[chunkDataStart:chunkDataEnd])
	})
}

func TestFindChunkOffset(t *testing.T) {
	// Create a standard PNG to search within.
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	var buf bytes.Buffer
	require.NoError(t, png.Encode(&buf, img))
	data := buf.Bytes()

	t.Run("finds IHDR chunk", func(t *testing.T) {
		offset := findChunkOffset(data, "IHDR")
		assert.Greater(t, offset, 0)
	})

	t.Run("finds IDAT chunk", func(t *testing.T) {
		offset := findChunkOffset(data, "IDAT")
		assert.Greater(t, offset, 0)
	})

	t.Run("finds IEND chunk", func(t *testing.T) {
		offset := findChunkOffset(data, "IEND")
		assert.Greater(t, offset, 0)
	})

	t.Run("returns -1 for missing chunk", func(t *testing.T) {
		assert.Equal(t, -1, findChunkOffset(data, "zzzz"))
	})

	t.Run("returns -1 for nil input", func(t *testing.T) {
		assert.Equal(t, -1, findChunkOffset(nil, "IHDR"))
	})

	t.Run("returns -1 for short input", func(t *testing.T) {
		assert.Equal(t, -1, findChunkOffset([]byte{1, 2, 3}, "IHDR"))
	})
}
