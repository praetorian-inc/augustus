package probes

import (
	"bufio"
	"bytes"
	"strings"
)

// LoadLines parses embedded byte data (one entry per line) into a string slice.
// It trims whitespace from each line and skips empty lines. This is suitable
// for loading prompt lists from embedded text files where each line is a prompt.
//
// This replaces the duplicated loadPrompts() pattern found across multiple
// probe packages (donotanswer, realtoxicityprompts, etc.).
func LoadLines(data []byte) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// SplitLines splits string data by newlines, trims whitespace, and skips empty
// lines. This is the string-input variant of LoadLines, suitable for data
// embedded as string rather than []byte.
//
// This replaces the duplicated parseSuffixes() pattern found in gcg and suffix
// packages.
func SplitLines(data string) []string {
	raw := strings.Split(data, "\n")
	lines := make([]string, 0, len(raw))

	for _, line := range raw {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			lines = append(lines, trimmed)
		}
	}

	return lines
}

// SplitLinesSkipComments splits string data by newlines, trims whitespace,
// skips empty lines, and skips lines beginning with "#". This is suitable for
// embedded data files that use "#" as a comment prefix.
//
// This replaces the duplicated parseLines() / parseLinesFromData() pattern
// found in poetry and phrasing packages.
func SplitLinesSkipComments(data string) []string {
	raw := strings.Split(data, "\n")
	lines := make([]string, 0, len(raw))

	for _, line := range raw {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			lines = append(lines, trimmed)
		}
	}

	return lines
}
