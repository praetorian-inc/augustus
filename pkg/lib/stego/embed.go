// Package stego provides steganography utilities for embedding and extracting
// hidden messages in images using LSB (Least Significant Bit) techniques.
package stego

import (
	"encoding/binary"
	"errors"
	"image"
	"image/color"
)

// LSBEmbed embeds text in an image using least significant bit steganography.
// The message length is encoded in the first 4 bytes (32 bits), followed by
// the message data. Each byte of data is spread across 8 pixels (1 bit per pixel).
//
// Only the LSB of the RGB channels is modified, preserving visual quality.
// Alpha channel is not used to avoid transparency artifacts.
//
// Returns an error if the image is nil, message is empty, or the message
// doesn't fit in the available image capacity.
func LSBEmbed(img image.Image, message string) (image.Image, error) {
	if img == nil {
		return nil, errors.New("image cannot be nil")
	}
	if message == "" {
		return nil, errors.New("message cannot be empty")
	}

	// Calculate capacity: 3 bits per pixel (R, G, B)
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()
	pixelCount := width * height
	capacityBits := pixelCount * 3

	// Message encoding: 4 bytes for length + message bytes
	// Each byte needs 8 bits
	messageBytes := []byte(message)
	requiredBits := (4 + len(messageBytes)) * 8

	if requiredBits > capacityBits {
		return nil, errors.New("message too large for image capacity")
	}

	// Create output image (copy dimensions)
	output := image.NewRGBA(bounds)

	// Copy original image to output
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			output.Set(x, y, img.At(x, y))
		}
	}

	// Prepare data to embed: 4-byte length prefix + message
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, uint32(len(messageBytes)))
	data := append(lengthBytes, messageBytes...)

	// Embed data using LSB
	bitIndex := 0
	for _, byteVal := range data {
		for bit := 7; bit >= 0; bit-- { // Process bits from MSB to LSB
			if bitIndex >= capacityBits {
				return nil, errors.New("exceeded image capacity during embedding")
			}

			// Calculate pixel coordinates
			pixelIndex := bitIndex / 3
			channelIndex := bitIndex % 3
			x := bounds.Min.X + (pixelIndex % width)
			y := bounds.Min.Y + (pixelIndex / width)

			// Get current pixel
			r, g, b, a := output.At(x, y).RGBA()
			// Convert from uint32 (0-65535) to uint8 (0-255)
			rByte := uint8(r >> 8)
			gByte := uint8(g >> 8)
			bByte := uint8(b >> 8)
			aByte := uint8(a >> 8)

			// Extract bit to embed
			bitValue := (byteVal >> bit) & 1

			// Modify LSB of appropriate channel
			switch channelIndex {
			case 0: // R channel
				rByte = (rByte & 0xFE) | bitValue
			case 1: // G channel
				gByte = (gByte & 0xFE) | bitValue
			case 2: // B channel
				bByte = (bByte & 0xFE) | bitValue
			}

			// Set modified pixel
			output.Set(x, y, color.RGBA{R: rByte, G: gByte, B: bByte, A: aByte})
			bitIndex++
		}
	}

	return output, nil
}

// LSBExtract extracts a hidden message from an image using LSB steganography.
// Expects the message to be encoded with a 4-byte length prefix followed by
// the message data, as created by LSBEmbed.
//
// Returns an error if the image is nil or the extracted data is invalid.
func LSBExtract(img image.Image) (string, error) {
	if img == nil {
		return "", errors.New("image cannot be nil")
	}

	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()
	pixelCount := width * height
	capacityBits := pixelCount * 3

	// Extract length prefix (4 bytes = 32 bits)
	if capacityBits < 32 {
		return "", errors.New("image too small to contain message length")
	}

	lengthBytes := make([]byte, 4)
	bitIndex := 0

	// Extract 4 bytes for length
	for byteIdx := 0; byteIdx < 4; byteIdx++ {
		var byteVal byte
		for bit := 7; bit >= 0; bit-- {
			// Calculate pixel coordinates
			pixelIndex := bitIndex / 3
			channelIndex := bitIndex % 3
			x := bounds.Min.X + (pixelIndex % width)
			y := bounds.Min.Y + (pixelIndex / width)

			// Get pixel
			r, g, b, _ := img.At(x, y).RGBA()
			rByte := uint8(r >> 8)
			gByte := uint8(g >> 8)
			bByte := uint8(b >> 8)

			// Extract LSB from appropriate channel
			var bitValue byte
			switch channelIndex {
			case 0: // R channel
				bitValue = rByte & 1
			case 1: // G channel
				bitValue = gByte & 1
			case 2: // B channel
				bitValue = bByte & 1
			}

			byteVal |= (bitValue << bit)
			bitIndex++
		}
		lengthBytes[byteIdx] = byteVal
	}

	// Decode length
	messageLength := binary.BigEndian.Uint32(lengthBytes)

	// Sanity check length
	if messageLength > uint32(capacityBits/8-4) {
		return "", errors.New("invalid message length extracted")
	}
	if messageLength == 0 {
		return "", nil
	}

	// Extract message bytes
	messageBytes := make([]byte, messageLength)
	for byteIdx := uint32(0); byteIdx < messageLength; byteIdx++ {
		var byteVal byte
		for bit := 7; bit >= 0; bit-- {
			if bitIndex >= capacityBits {
				return "", errors.New("exceeded image capacity during extraction")
			}

			// Calculate pixel coordinates
			pixelIndex := bitIndex / 3
			channelIndex := bitIndex % 3
			x := bounds.Min.X + (pixelIndex % width)
			y := bounds.Min.Y + (pixelIndex / width)

			// Get pixel
			r, g, b, _ := img.At(x, y).RGBA()
			rByte := uint8(r >> 8)
			gByte := uint8(g >> 8)
			bByte := uint8(b >> 8)

			// Extract LSB from appropriate channel
			var bitValue byte
			switch channelIndex {
			case 0: // R channel
				bitValue = rByte & 1
			case 1: // G channel
				bitValue = gByte & 1
			case 2: // B channel
				bitValue = bByte & 1
			}

			byteVal |= (bitValue << bit)
			bitIndex++
		}
		messageBytes[byteIdx] = byteVal
	}

	return string(messageBytes), nil
}
