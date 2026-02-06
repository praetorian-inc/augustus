package advpatch

import (
	"errors"
	"image"
	"image/color"
	"math/rand"
)

// GeneratePatch generates an adversarial patch on the given image.
//
// This function applies a simple adversarial perturbation to the image
// for the specified target. In a production system, this would use
// gradient-based optimization methods like PGD or patch optimization.
//
// For testing purposes, this generates a simple random perturbation.
//
// Parameters:
//   - img: The input image to patch
//   - target: The target label or behavior (e.g., "person", "safe")
//
// Returns:
//   - The patched image
//   - An error if the operation fails
func GeneratePatch(img image.Image, target string) (image.Image, error) {
	if img == nil {
		return nil, errors.New("input image cannot be nil")
	}

	if target == "" {
		return nil, errors.New("target cannot be empty")
	}

	// Get image bounds
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	// Create output image
	patchedImg := image.NewRGBA(bounds)

	// Copy original image
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			patchedImg.Set(x, y, img.At(x, y))
		}
	}

	// Define patch region (10% of image size, centered)
	patchWidth := width / 10
	patchHeight := height / 10
	patchX := (width - patchWidth) / 2
	patchY := (height - patchHeight) / 2

	// Apply simple random perturbation to patch region
	// In production: This would use gradient-based methods like:
	//   - Fast Gradient Sign Method (FGSM)
	//   - Projected Gradient Descent (PGD)
	//   - Adversarial patch optimization
	for y := patchY; y < patchY+patchHeight; y++ {
		for x := patchX; x < patchX+patchWidth; x++ {
			// Get original color
			r, g, b, a := patchedImg.At(x, y).RGBA()

			// Apply perturbation (±10% random noise)
			perturbation := uint8(rand.Intn(51) - 25) // -25 to +25

			// Apply perturbation to each channel
			newR := clamp(int(r>>8) + int(perturbation))
			newG := clamp(int(g>>8) + int(perturbation))
			newB := clamp(int(b>>8) + int(perturbation))

			// Set perturbed color
			patchedImg.Set(x, y, color.RGBA{
				R: uint8(newR),
				G: uint8(newG),
				B: uint8(newB),
				A: uint8(a >> 8),
			})
		}
	}

	return patchedImg, nil
}

// clamp ensures a value stays within the valid uint8 range [0, 255].
func clamp(value int) int {
	if value < 0 {
		return 0
	}
	if value > 255 {
		return 255
	}
	return value
}
