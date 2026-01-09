package artprompts

import (
	"strings"
)

// GenerateASCIIArt converts text to ASCII art using the specified style.
func GenerateASCIIArt(text string, style ArtStyle) string {
	switch style {
	case ASCII:
		return generateASCIIBanner(text)
	case BoxDrawing:
		return generateBoxDrawing(text)
	case BlockElements:
		return generateBlockElements(text)
	case Braille:
		return generateBraille(text)
	default:
		return generateASCIIBanner(text)
	}
}

// generateASCIIBanner creates banner-style ASCII art using # characters.
// This is a simple implementation that creates readable banner text.
func generateASCIIBanner(text string) string {
	text = strings.ToUpper(text)
	var lines [7]strings.Builder // Standard ASCII banners are typically 7 lines high

	for _, ch := range text {
		font, ok := asciiBannerFont[ch]
		if !ok {
			font = asciiBannerFont[' '] // Default to space for unknown characters
		}

		// Append each line of the character to the corresponding line builder
		for i, line := range font {
			lines[i].WriteString(line)
			lines[i].WriteString(" ") // Space between characters
		}
	}

	// Combine all lines
	var result strings.Builder
	for _, line := range lines {
		result.WriteString(line.String())
		result.WriteString("\n")
	}

	return result.String()
}

// asciiBannerFont defines simple ASCII banner characters.
// Each character is 5 lines tall and up to 5 characters wide.
var asciiBannerFont = map[rune][]string{
	'A': {
		" ### ",
		"#   #",
		"#####",
		"#   #",
		"#   #",
		"#   #",
		"#   #",
	},
	'B': {
		"#### ",
		"#   #",
		"#### ",
		"#   #",
		"#   #",
		"#   #",
		"#### ",
	},
	'C': {
		" ####",
		"#    ",
		"#    ",
		"#    ",
		"#    ",
		"#    ",
		" ####",
	},
	'D': {
		"#### ",
		"#   #",
		"#   #",
		"#   #",
		"#   #",
		"#   #",
		"#### ",
	},
	'E': {
		"#####",
		"#    ",
		"#    ",
		"#### ",
		"#    ",
		"#    ",
		"#####",
	},
	'G': {
		" ####",
		"#    ",
		"#    ",
		"# ###",
		"#   #",
		"#   #",
		" ####",
	},
	'H': {
		"#   #",
		"#   #",
		"#   #",
		"#####",
		"#   #",
		"#   #",
		"#   #",
	},
	'I': {
		"#####",
		"  #  ",
		"  #  ",
		"  #  ",
		"  #  ",
		"  #  ",
		"#####",
	},
	'K': {
		"#   #",
		"#  # ",
		"# #  ",
		"##   ",
		"# #  ",
		"#  # ",
		"#   #",
	},
	'M': {
		"#   #",
		"## ##",
		"# # #",
		"#   #",
		"#   #",
		"#   #",
		"#   #",
	},
	'N': {
		"#   #",
		"##  #",
		"# # #",
		"# # #",
		"#  ##",
		"#   #",
		"#   #",
	},
	'O': {
		" ### ",
		"#   #",
		"#   #",
		"#   #",
		"#   #",
		"#   #",
		" ### ",
	},
	'P': {
		"#### ",
		"#   #",
		"#   #",
		"#### ",
		"#    ",
		"#    ",
		"#    ",
	},
	'R': {
		"#### ",
		"#   #",
		"#   #",
		"#### ",
		"# #  ",
		"#  # ",
		"#   #",
	},
	'S': {
		" ####",
		"#    ",
		"#    ",
		" ### ",
		"    #",
		"    #",
		"#### ",
	},
	'T': {
		"#####",
		"  #  ",
		"  #  ",
		"  #  ",
		"  #  ",
		"  #  ",
		"  #  ",
	},
	'U': {
		"#   #",
		"#   #",
		"#   #",
		"#   #",
		"#   #",
		"#   #",
		" ### ",
	},
	'Y': {
		"#   #",
		"#   #",
		" # # ",
		"  #  ",
		"  #  ",
		"  #  ",
		"  #  ",
	},
	' ': {
		"  ",
		"  ",
		"  ",
		"  ",
		"  ",
		"  ",
		"  ",
	},
}

// generateBoxDrawing creates ASCII art using Unicode box drawing characters.
func generateBoxDrawing(text string) string {
	text = strings.ToUpper(text)
	var result strings.Builder

	// Top border
	result.WriteString("╔")
	for range text {
		result.WriteString("═══════")
	}
	result.WriteString("╗\n")

	// Text in box
	result.WriteString("║")
	for _, ch := range text {
		result.WriteString("   ")
		result.WriteRune(ch)
		result.WriteString("   ")
	}
	result.WriteString("║\n")

	// Middle decoration
	result.WriteString("║")
	for range text {
		result.WriteString("═══════")
	}
	result.WriteString("║\n")

	// Bottom border
	result.WriteString("╚")
	for range text {
		result.WriteString("═══════")
	}
	result.WriteString("╝\n")

	return result.String()
}

// generateBlockElements creates ASCII art using Unicode block characters.
func generateBlockElements(text string) string {
	text = strings.ToUpper(text)
	var lines [5]strings.Builder

	for _, ch := range text {
		font, ok := blockElementFont[ch]
		if !ok {
			font = blockElementFont[' ']
		}

		for i, line := range font {
			lines[i].WriteString(line)
			lines[i].WriteString(" ")
		}
	}

	var result strings.Builder
	for _, line := range lines {
		result.WriteString(line.String())
		result.WriteString("\n")
	}

	return result.String()
}

// blockElementFont defines characters using Unicode block elements.
var blockElementFont = map[rune][]string{
	'A': {
		" ███ ",
		"█   █",
		"█████",
		"█   █",
		"█   █",
	},
	'B': {
		"████ ",
		"█   █",
		"████ ",
		"█   █",
		"████ ",
	},
	'C': {
		" ████",
		"█    ",
		"█    ",
		"█    ",
		" ████",
	},
	'D': {
		"████ ",
		"█   █",
		"█   █",
		"█   █",
		"████ ",
	},
	'E': {
		"█████",
		"█    ",
		"████ ",
		"█    ",
		"█████",
	},
	'G': {
		" ████",
		"█    ",
		"█ ███",
		"█   █",
		" ████",
	},
	'H': {
		"█   █",
		"█   █",
		"█████",
		"█   █",
		"█   █",
	},
	'I': {
		"█████",
		"  █  ",
		"  █  ",
		"  █  ",
		"█████",
	},
	'K': {
		"█   █",
		"█  █ ",
		"███  ",
		"█  █ ",
		"█   █",
	},
	'M': {
		"█   █",
		"██ ██",
		"█ █ █",
		"█   █",
		"█   █",
	},
	'N': {
		"█   █",
		"██  █",
		"█ █ █",
		"█  ██",
		"█   █",
	},
	'O': {
		" ███ ",
		"█   █",
		"█   █",
		"█   █",
		" ███ ",
	},
	'P': {
		"████ ",
		"█   █",
		"████ ",
		"█    ",
		"█    ",
	},
	'R': {
		"████ ",
		"█   █",
		"████ ",
		"█  █ ",
		"█   █",
	},
	'S': {
		" ████",
		"█    ",
		" ███ ",
		"    █",
		"████ ",
	},
	'T': {
		"█████",
		"  █  ",
		"  █  ",
		"  █  ",
		"  █  ",
	},
	'U': {
		"█   █",
		"█   █",
		"█   █",
		"█   █",
		" ███ ",
	},
	'Y': {
		"█   █",
		" █ █ ",
		"  █  ",
		"  █  ",
		"  █  ",
	},
	' ': {
		"  ",
		"  ",
		"  ",
		"  ",
		"  ",
	},
}

// generateBraille creates ASCII art using Unicode Braille patterns.
// This creates a simple pattern representation using Braille characters.
func generateBraille(text string) string {
	text = strings.ToUpper(text)
	var result strings.Builder

	// Braille representations spell out the text
	result.WriteString("⠤⠤⠤ Message in Braille ⠤⠤⠤\n")

	for _, ch := range text {
		braille, ok := brailleFont[ch]
		if !ok {
			braille = "⠀⠀" // Blank Braille character for unknown
		}
		result.WriteString(braille)
		result.WriteString(" ")
	}

	result.WriteString("\n⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤\n")

	return result.String()
}

// brailleFont maps characters to Braille patterns.
// Based on standard English Braille Grade 1.
var brailleFont = map[rune]string{
	'A': "⠁", 'B': "⠃", 'C': "⠉", 'D': "⠙", 'E': "⠑",
	'F': "⠋", 'G': "⠛", 'H': "⠓", 'I': "⠊", 'J': "⠚",
	'K': "⠅", 'L': "⠇", 'M': "⠍", 'N': "⠝", 'O': "⠕",
	'P': "⠏", 'Q': "⠟", 'R': "⠗", 'S': "⠎", 'T': "⠞",
	'U': "⠥", 'V': "⠧", 'W': "⠺", 'X': "⠭", 'Y': "⠽",
	'Z': "⠵", ' ': "⠀",
}
