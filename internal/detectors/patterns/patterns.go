// Package patterns provides regex and semantic pattern matching detectors.
package patterns

import (
	"context"
	"fmt"
	"regexp"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("patterns.Patterns", NewPatterns)
}

// MatchMode determines how multiple patterns are combined.
type MatchMode int

const (
	// ModeAny returns the highest severity if any pattern matches.
	ModeAny MatchMode = iota
	// ModeAll requires all patterns to match to score positively.
	ModeAll
	// ModeWeighted returns the average severity of all matching patterns.
	ModeWeighted
)

// Pattern represents a single detection pattern.
type Pattern struct {
	// Name is a descriptive identifier for the pattern.
	Name string
	// Regex is the compiled regular expression to match against outputs.
	Regex *regexp.Regexp
	// Semantic is an optional semantic description for future enhancements.
	Semantic string
	// Severity is the score assigned when this pattern matches (0.0-1.0).
	Severity float64
}

// PatternsDetector detects outputs matching configured regex patterns.
type PatternsDetector struct {
	patterns  []Pattern
	mode      MatchMode
	threshold float64
}

// NewPatterns creates a new patterns detector from configuration.
//
// Configuration format:
//   {
//     "patterns": [
//       {
//         "name": "password_leak",
//         "regex": "password\\s*[:=]",
//         "severity": 1.0,
//         "semantic": "Optional semantic description"
//       }
//     ],
//     "mode": "any",  // "any", "all", or "weighted"
//     "threshold": 0.5
//   }
func NewPatterns(cfg registry.Config) (detectors.Detector, error) {
	d := &PatternsDetector{
		patterns:  []Pattern{},
		mode:      ModeAny,
		threshold: 0.5,
	}

	// Parse patterns
	if patternsRaw, ok := cfg["patterns"]; ok {
		patternList, ok := patternsRaw.([]map[string]any)
		if !ok {
			// Try type assertion for []any and convert
			if patternListIface, ok := patternsRaw.([]any); ok {
				patternList = make([]map[string]any, len(patternListIface))
				for i, p := range patternListIface {
					if pm, ok := p.(map[string]any); ok {
						patternList[i] = pm
					} else {
						return nil, fmt.Errorf("pattern at index %d is not a map", i)
					}
				}
			} else {
				return nil, fmt.Errorf("patterns must be an array of maps")
			}
		}

		for i, patternCfg := range patternList {
			name, _ := patternCfg["name"].(string)
			if name == "" {
				name = fmt.Sprintf("pattern_%d", i)
			}

			regexStr, ok := patternCfg["regex"].(string)
			if !ok {
				return nil, fmt.Errorf("pattern %q missing required 'regex' field", name)
			}

			regex, err := regexp.Compile(regexStr)
			if err != nil {
				return nil, fmt.Errorf("pattern %q has invalid regex: %w", name, err)
			}

			severity := 1.0
			if sev, ok := patternCfg["severity"].(float64); ok {
				severity = sev
			}

			semantic, _ := patternCfg["semantic"].(string)

			d.patterns = append(d.patterns, Pattern{
				Name:     name,
				Regex:    regex,
				Semantic: semantic,
				Severity: severity,
			})
		}
	}

	// Parse mode
	if modeStr, ok := cfg["mode"].(string); ok {
		switch modeStr {
		case "any":
			d.mode = ModeAny
		case "all":
			d.mode = ModeAll
		case "weighted":
			d.mode = ModeWeighted
		default:
			return nil, fmt.Errorf("invalid mode: %q (must be 'any', 'all', or 'weighted')", modeStr)
		}
	}

	// Parse threshold
	if threshold, ok := cfg["threshold"].(float64); ok {
		d.threshold = threshold
	}

	return d, nil
}

// Detect analyzes attempt outputs for pattern matches and returns scores.
func (d *PatternsDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	scores := make([]float64, len(a.Outputs))

	for i, output := range a.Outputs {
		scores[i] = d.scoreOutput(output)
	}

	return scores, nil
}

// scoreOutput calculates the score for a single output based on pattern matches.
func (d *PatternsDetector) scoreOutput(output string) float64 {
	if len(d.patterns) == 0 {
		return 0.0
	}

	switch d.mode {
	case ModeAny:
		return d.scoreAnyMode(output)
	case ModeAll:
		return d.scoreAllMode(output)
	case ModeWeighted:
		return d.scoreWeightedMode(output)
	default:
		return 0.0
	}
}

// scoreAnyMode returns the highest severity if any pattern matches.
func (d *PatternsDetector) scoreAnyMode(output string) float64 {
	maxSeverity := 0.0

	for _, pattern := range d.patterns {
		if pattern.Regex.MatchString(output) {
			if pattern.Severity > maxSeverity {
				maxSeverity = pattern.Severity
			}
		}
	}

	return maxSeverity
}

// scoreAllMode requires all patterns to match to score positively.
func (d *PatternsDetector) scoreAllMode(output string) float64 {
	if len(d.patterns) == 0 {
		return 0.0
	}

	// Check if all patterns match
	for _, pattern := range d.patterns {
		if !pattern.Regex.MatchString(output) {
			return 0.0
		}
	}

	// All patterns matched - return highest severity
	maxSeverity := 0.0
	for _, pattern := range d.patterns {
		if pattern.Severity > maxSeverity {
			maxSeverity = pattern.Severity
		}
	}

	return maxSeverity
}

// scoreWeightedMode returns the average severity of all matching patterns.
func (d *PatternsDetector) scoreWeightedMode(output string) float64 {
	var totalSeverity float64
	matchCount := 0

	for _, pattern := range d.patterns {
		if pattern.Regex.MatchString(output) {
			totalSeverity += pattern.Severity
			matchCount++
		}
	}

	if matchCount == 0 {
		return 0.0
	}

	return totalSeverity / float64(matchCount)
}

// Name returns the detector's fully qualified name.
func (d *PatternsDetector) Name() string {
	return "patterns.Patterns"
}

// Description returns a human-readable description.
func (d *PatternsDetector) Description() string {
	return "Regex and semantic pattern matching for custom detection"
}
