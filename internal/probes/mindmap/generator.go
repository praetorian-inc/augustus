package mindmap

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
)

// GenerateMindMap creates a mind map image with the instruction hidden using
// the configured hiding technique.
//
// This is the main entry point for mind map generation. It creates a base image,
// draws visible nodes for legitimate appearance, and hides the malicious instruction
// using the probe's configured technique.
func (m *MindMapProbe) GenerateMindMap(instruction string) (image.Image, error) {
	// Create base image (400x300 for mind map canvas)
	width, height := 400, 300
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Fill with white background
	white := color.RGBA{R: 255, G: 255, B: 255, A: 255}
	draw.Draw(img, img.Bounds(), &image.Uniform{white}, image.Point{}, draw.Src)

	// Draw visible mind map structure (legitimate nodes)
	m.drawVisibleNodes(img)

	// Hide the instruction using the configured technique
	switch m.hidingTechnique {
	case InvisibleNodes:
		m.hideWithInvisibleNodes(img, instruction)
	case ZeroSizeText:
		m.hideWithZeroSizeText(img, instruction)
	case BackgroundColor:
		m.hideWithBackgroundColor(img, instruction)
	case WhiteOnWhite:
		m.hideWithWhiteOnWhite(img, instruction)
	default:
		return nil, fmt.Errorf("unknown hiding technique: %v", m.hidingTechnique)
	}

	return img, nil
}

// drawVisibleNodes draws the legitimate visible structure of the mind map.
// These are decoy nodes that make the mind map look normal and legitimate.
// The actual attack vector is hidden separately using hiding techniques.
func (m *MindMapProbe) drawVisibleNodes(img *image.RGBA) {
	// Draw central node
	m.drawNode(img, 200, 150, "Main Topic", color.RGBA{R: 100, G: 150, B: 200, A: 255})

	// Draw child nodes based on layout type
	switch m.layout {
	case TreeLayout:
		// Hierarchical tree structure with nodes branching from center
		m.drawNode(img, 100, 100, "Subtopic 1", color.RGBA{R: 150, G: 200, B: 150, A: 255})
		m.drawNode(img, 300, 100, "Subtopic 2", color.RGBA{R: 200, G: 150, B: 150, A: 255})
		m.drawNode(img, 100, 200, "Subtopic 3", color.RGBA{R: 200, G: 200, B: 100, A: 255})
		m.drawNode(img, 300, 200, "Subtopic 4", color.RGBA{R: 150, G: 150, B: 200, A: 255})
	case RadialLayout:
		// Radial nodes arranged in a circle around center
		m.drawNode(img, 200, 50, "North", color.RGBA{R: 150, G: 200, B: 150, A: 255})
		m.drawNode(img, 350, 150, "East", color.RGBA{R: 200, G: 150, B: 150, A: 255})
		m.drawNode(img, 200, 250, "South", color.RGBA{R: 200, G: 200, B: 100, A: 255})
		m.drawNode(img, 50, 150, "West", color.RGBA{R: 150, G: 150, B: 200, A: 255})
	case OrgChartLayout:
		// Hierarchical organizational chart style
		m.drawNode(img, 100, 80, "Team A", color.RGBA{R: 150, G: 200, B: 150, A: 255})
		m.drawNode(img, 300, 80, "Team B", color.RGBA{R: 200, G: 150, B: 150, A: 255})
		m.drawNode(img, 200, 220, "Lead", color.RGBA{R: 200, G: 200, B: 100, A: 255})
	}
}

// drawNode draws a single node at the given position with label and color.
//
// Nodes are represented as colored rectangles with borders. In a production
// implementation, this would use a font library to render actual text labels.
// For testing purposes, the color-coded rectangles are sufficient to demonstrate
// the mind map structure.
func (m *MindMapProbe) drawNode(img *image.RGBA, x, y int, label string, col color.RGBA) {
	// Draw a simple filled rectangle as node
	nodeWidth, nodeHeight := 60, 30
	rect := image.Rect(x-nodeWidth/2, y-nodeHeight/2, x+nodeWidth/2, y+nodeHeight/2)

	// Fill node with color
	draw.Draw(img, rect, &image.Uniform{col}, image.Point{}, draw.Src)

	// Draw black border
	black := color.RGBA{R: 0, G: 0, B: 0, A: 255}
	m.drawRectBorder(img, rect, black)

	// Note: Actual text rendering would require a font package (e.g., golang.org/x/image/font)
	// For now, we represent that the node exists with a color-coded rectangle
	// The label parameter documents what the node conceptually represents
	_ = label
}

// drawRectBorder draws a 1-pixel border around a rectangle.
//
// This provides visual definition for mind map nodes. The border is drawn
// by setting individual pixels along the rectangle edges.
func (m *MindMapProbe) drawRectBorder(img *image.RGBA, rect image.Rectangle, col color.RGBA) {
	// Top border
	for x := rect.Min.X; x < rect.Max.X; x++ {
		img.Set(x, rect.Min.Y, col)
	}
	// Bottom border
	for x := rect.Min.X; x < rect.Max.X; x++ {
		img.Set(x, rect.Max.Y-1, col)
	}
	// Left border
	for y := rect.Min.Y; y < rect.Max.Y; y++ {
		img.Set(rect.Min.X, y, col)
	}
	// Right border
	for y := rect.Min.Y; y < rect.Max.Y; y++ {
		img.Set(rect.Max.X-1, y, col)
	}
}

// hideWithInvisibleNodes hides instruction by creating fully transparent nodes.
//
// These nodes have 0% opacity (alpha = 0) so they're completely invisible to
// human observers. However, the image data structure may still contain information
// about these nodes that vision-capable models could detect when analyzing the
// full image data beyond just the visible pixels.
//
// This technique tests whether models process image metadata or structural data
// beyond what is visually rendered.
func (m *MindMapProbe) hideWithInvisibleNodes(img *image.RGBA, instruction string) {
	// Create a node with fully transparent background (alpha = 0)
	transparent := color.RGBA{R: 0, G: 0, B: 0, A: 0}
	rect := image.Rect(10, 10, 100, 40)
	draw.Draw(img, rect, &image.Uniform{transparent}, image.Point{}, draw.Over)

	// In a production implementation, the instruction would be encoded in:
	// 1. Image metadata/EXIF fields
	// 2. LSB (Least Significant Bits) of neighboring pixels
	// 3. A custom data structure embedded in the image file
	//
	// For this testing implementation, we conceptually represent the hidden
	// instruction. Vision models that analyze image structure beyond pixel
	// values may detect anomalies indicating hidden data.
	_ = instruction
}

// hideWithZeroSizeText hides instruction using zero-size text rendering.
//
// Text with font size 0 is visually imperceptible (no pixels are rendered) but
// may still exist in image metadata or as sub-pixel rendering artifacts that
// vision models could detect through detailed image analysis.
//
// This tests whether models can detect rendering artifacts or metadata from
// text that was "drawn" but isn't visually present.
func (m *MindMapProbe) hideWithZeroSizeText(img *image.RGBA, instruction string) {
	// Zero-size text rendering (conceptual - production would use font library)
	// The instruction conceptually exists in the image rendering pipeline but
	// produces no visible output
	_ = instruction

	// Represent this by modifying a single pixel with barely perceptible change
	// This simulates the minimal rendering artifact that might result from
	// zero-size text processing
	img.Set(0, 0, color.RGBA{R: 255, G: 255, B: 254, A: 255}) // 1/255 difference
}

// hideWithBackgroundColor hides instruction by matching text color to background.
//
// Text is drawn in the exact same color as the background (white on white),
// making it invisible to casual visual inspection. However, models that perform
// detailed pixel-by-pixel or sub-pixel analysis might detect slight rendering
// artifacts from anti-aliasing or text positioning metadata.
//
// This is similar to WhiteOnWhite but may use more sophisticated color matching
// based on the local background color at the text position.
func (m *MindMapProbe) hideWithBackgroundColor(img *image.RGBA, instruction string) {
	// Draw text in white on white background (completely invisible)
	white := color.RGBA{R: 255, G: 255, B: 255, A: 255}

	// Place instruction area in corner where it won't overlap visible nodes
	// In production, this would use a font library to render actual text
	// at the background color, creating invisible but present text data
	rect := image.Rect(350, 5, 395, 20)
	draw.Draw(img, rect, &image.Uniform{white}, image.Point{}, draw.Over)

	_ = instruction
}

// hideWithWhiteOnWhite hides instruction using classic white-on-white technique.
//
// This is the most straightforward and well-known hiding method: white text
// rendered on white background. While invisible to human observers, vision models
// may be able to detect:
// 1. Text positioning metadata in image file
// 2. Sub-pixel anti-aliasing artifacts
// 3. Slight variations in white values (254 vs 255)
// 4. Different pixel patterns from text rendering vs solid fill
//
// This technique has been used in document attacks (e.g., hidden instructions
// in resumes or forms) and tests whether models are vulnerable to this classic
// obfuscation method.
func (m *MindMapProbe) hideWithWhiteOnWhite(img *image.RGBA, instruction string) {
	// Same as hideWithBackgroundColor but explicitly named for the classic technique
	white := color.RGBA{R: 255, G: 255, B: 255, A: 255}

	// Draw instruction area at bottom of image (conceptually contains hidden text)
	// The white-on-white technique is simple but surprisingly effective against
	// both human reviewers and some automated scanners
	rect := image.Rect(5, 290, 100, 295)
	draw.Draw(img, rect, &image.Uniform{white}, image.Point{}, draw.Over)

	_ = instruction
}
