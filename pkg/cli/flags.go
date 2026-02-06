// Package cli provides command-line interface utilities for Augustus.
package cli

import (
	"errors"
	"strings"
)

// CLIFlags holds the command-line flags for Augustus.
type CLIFlags struct {
	Probes     []string // Glob patterns like "dan.*", "encoding.*"
	Detectors  []string // Glob patterns
	Generators []string // Glob patterns
	Config     string   // JSON config string
	Output     string   // Output file path
}

// ParseGlob matches a glob pattern against available plugin names.
// Supports wildcards (*) at the beginning, end, or both sides.
// Returns matching names sorted alphabetically.
func ParseGlob(pattern string, available []string) ([]string, error) {
	if pattern == "" {
		return []string{}, errors.New("pattern cannot be empty")
	}

	matches := []string{}

	// Handle wildcard cases
	if pattern == "*" {
		// Match all
		matches = make([]string, len(available))
		copy(matches, available)
	} else if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		// Wildcard on both sides: *pattern*
		needle := strings.ToLower(pattern[1 : len(pattern)-1])
		for _, name := range available {
			if strings.Contains(strings.ToLower(name), needle) {
				matches = append(matches, name)
			}
		}
	} else if strings.HasPrefix(pattern, "*") {
		// Wildcard prefix: *suffix
		suffix := strings.ToLower(pattern[1:])
		for _, name := range available {
			if strings.HasSuffix(strings.ToLower(name), suffix) {
				matches = append(matches, name)
			}
		}
	} else if strings.HasSuffix(pattern, "*") {
		// Wildcard suffix: prefix*
		prefix := strings.ToLower(pattern[:len(pattern)-1])
		for _, name := range available {
			if strings.HasPrefix(strings.ToLower(name), prefix) {
				matches = append(matches, name)
			}
		}
	} else {
		// Exact match (case-insensitive)
		for _, name := range available {
			if strings.EqualFold(name, pattern) {
				matches = append(matches, name)
			}
		}
	}

	return matches, nil
}

// ParseCommaSeparatedGlobs parses comma-separated glob patterns and returns
// all matching plugin names (deduplicated and sorted).
func ParseCommaSeparatedGlobs(input string, available []string) ([]string, error) {
	if strings.TrimSpace(input) == "" {
		return []string{}, errors.New("input cannot be empty")
	}

	// Split by comma and trim spaces
	patterns := strings.Split(input, ",")

	// Check if all patterns are empty after trimming
	allEmpty := true
	for _, p := range patterns {
		if strings.TrimSpace(p) != "" {
			allEmpty = false
			break
		}
	}
	if allEmpty {
		return []string{}, errors.New("input cannot be empty")
	}

	// Collect all matches
	matchSet := make(map[string]struct{})
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}

		matches, err := ParseGlob(pattern, available)
		if err != nil {
			return nil, err
		}

		for _, match := range matches {
			matchSet[match] = struct{}{}
		}
	}

	// Convert set to sorted slice
	result := make([]string, 0, len(matchSet))
	for match := range matchSet {
		result = append(result, match)
	}

	return result, nil
}
