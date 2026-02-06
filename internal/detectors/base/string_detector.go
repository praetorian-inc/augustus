// Package base provides base detector implementations including StringDetector.
package base

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("base.StringDetector", NewStringDetector)
}

// StringDetector detects if outputs contain any of a list of substrings.
// It supports different match types: "str" (substring), "word" (word boundary),
// and "startswith" (prefix match).
type StringDetector struct {
	substrings    []string
	matchType     string // "str", "word", "startswith"
	caseSensitive bool
}

// NewStringDetector creates a new StringDetector from config.
// Required config:
//   - substrings: []string - list of substrings to search for
//
// Optional config:
//   - matchtype: string - "str" (default), "word", or "startswith"
//   - case_sensitive: bool - false (default)
func NewStringDetector(cfg registry.Config) (detectors.Detector, error) {
	// Parse substrings (required)
	substrings, err := parseSubstrings(cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid substrings config: %w", err)
	}

	// Parse matchtype (default: "str")
	matchType := "str"
	if mt, ok := cfg["matchtype"]; ok {
		if s, ok := mt.(string); ok {
			matchType = s
		}
	}

	// Parse case_sensitive (default: false)
	caseSensitive := false
	if cs, ok := cfg["case_sensitive"]; ok {
		if b, ok := cs.(bool); ok {
			caseSensitive = b
		}
	}

	return &StringDetector{
		substrings:    substrings,
		matchType:     matchType,
		caseSensitive: caseSensitive,
	}, nil
}

// parseSubstrings extracts the substrings from config.
// Supports []string and []any (where elements are strings).
func parseSubstrings(cfg registry.Config) ([]string, error) {
	raw, ok := cfg["substrings"]
	if !ok {
		return nil, fmt.Errorf("substrings required")
	}

	switch v := raw.(type) {
	case []string:
		return v, nil
	case []any:
		result := make([]string, len(v))
		for i, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("substring at index %d is not a string", i)
			}
			result[i] = s
		}
		return result, nil
	default:
		return nil, fmt.Errorf("substrings must be a slice of strings, got %T", raw)
	}
}

// Detect analyzes each output for substring matches.
// Returns 1.0 if any substring matches, 0.0 otherwise.
func (d *StringDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	scores := make([]float64, len(a.Outputs))

	for i, output := range a.Outputs {
		match, err := d.matchesAny(output)
		if err != nil {
			return nil, err
		}
		if match {
			scores[i] = 1.0
		} else {
			scores[i] = 0.0
		}
	}

	return scores, nil
}

// matchesAny checks if the output matches any of the substrings.
func (d *StringDetector) matchesAny(output string) (bool, error) {
	for _, s := range d.substrings {
		match, err := d.matches(s, output)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}

// matches checks if a single substring matches the output.
func (d *StringDetector) matches(substring, output string) (bool, error) {
	// Apply case sensitivity
	if !d.caseSensitive {
		substring = strings.ToLower(substring)
		output = strings.ToLower(output)
	}

	switch d.matchType {
	case "str":
		return strings.Contains(output, substring), nil
	case "word":
		// Word boundary match using regex
		pattern := `\b` + regexp.QuoteMeta(substring) + `\b`
		matched, err := regexp.MatchString(pattern, output)
		if err != nil {
			return false, fmt.Errorf("regex match error: %w", err)
		}
		return matched, nil
	case "startswith":
		return strings.HasPrefix(output, substring), nil
	default:
		return false, fmt.Errorf("unknown matchtype: %s", d.matchType)
	}
}

// NewSubstringDetector is a convenience constructor that creates a WrappedDetector
// backed by a StringDetector with the given substrings. It uses the default match
// type ("str" / substring) and case-insensitive matching. Use functional options
// to override: WithMatchType, WithCaseSensitive.
//
// This eliminates the common boilerplate of:
//
//	baseDetector, err := base.NewStringDetector(registry.Config{"substrings": substrings})
//	if err != nil { return nil, err }
//	return base.NewWrappedDetector(baseDetector, name, description), nil
func NewSubstringDetector(name, description string, substrings []string, opts ...StringDetectorOption) (*WrappedDetector, error) {
	cfg := DefaultStringDetectorConfig()
	cfg.Substrings = substrings
	cfg = ApplyStringDetectorOptions(cfg, opts...)

	detector := &StringDetector{
		substrings:    cfg.Substrings,
		matchType:     cfg.MatchType,
		caseSensitive: cfg.CaseSensitive,
	}

	return NewWrappedDetector(detector, name, description), nil
}

// Name returns the detector's fully qualified name.
func (d *StringDetector) Name() string {
	return "base.StringDetector"
}

// Description returns a human-readable description.
func (d *StringDetector) Description() string {
	return "Detects if outputs contain any of a list of substrings"
}
