package base

import (
	"context"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// MatchMode specifies how trigger strings are matched against outputs.
type MatchMode int

const (
	// MatchContains checks if the output contains the trigger as a substring.
	MatchContains MatchMode = iota
	// MatchStartsWith checks if the output starts with the trigger (after trimming whitespace).
	MatchStartsWith
)

// TriggerMatchDetector is a shared base detector that checks if LLM outputs
// contain trigger strings stored in attempt metadata.
//
// It encapsulates the common pattern used by many detectors:
//  1. Extract triggers from attempt.Metadata["triggers"]
//  2. For each output, check if any trigger matches
//  3. Return 1.0 for match, 0.0 for no match
//
// Supports two match modes: contains (substring) and starts-with (prefix).
// Case-insensitive matching is the default.
//
// Domain detectors embed this type and provide their own Name/Description.
type TriggerMatchDetector struct {
	CaseSensitive bool
	Mode          MatchMode
	DetName       string
	Desc          string

	// ZeroOnNoTriggers controls behavior when no triggers are present in metadata.
	// If true, returns a zero-valued score slice matching the output count.
	// If false (default), returns an empty slice.
	ZeroOnNoTriggers bool
}

// NewTriggerMatchDetector creates a TriggerMatchDetector with the given match mode
// and name/description. The case_sensitive setting is read from config (default: false).
func NewTriggerMatchDetector(cfg registry.Config, mode MatchMode, name, description string) *TriggerMatchDetector {
	return &TriggerMatchDetector{
		CaseSensitive: registry.GetBool(cfg, "case_sensitive", false),
		Mode:          mode,
		DetName:       name,
		Desc:          description,
	}
}

// Detect analyzes each output for trigger matches from attempt metadata.
// Returns 1.0 if any trigger matches, 0.0 otherwise.
// Returns empty slice if no triggers are present in metadata.
func (d *TriggerMatchDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	triggers, err := ExtractTriggers(a)
	if err != nil {
		return nil, err
	}
	if len(triggers) == 0 {
		if d.ZeroOnNoTriggers {
			return make([]float64, len(a.Outputs)), nil
		}
		return []float64{}, nil
	}

	scores := make([]float64, len(a.Outputs))
	for i, output := range a.Outputs {
		if d.matchesAny(output, triggers) {
			scores[i] = 1.0
		}
	}

	return scores, nil
}

// matchesAny checks if the output matches any of the triggers.
func (d *TriggerMatchDetector) matchesAny(output string, triggers []string) bool {
	// For starts-with mode, trim leading whitespace (matches Python behavior).
	if d.Mode == MatchStartsWith {
		output = strings.TrimSpace(output)
	}

	for _, trigger := range triggers {
		if d.matches(output, trigger) {
			return true
		}
	}
	return false
}

// matches checks if a single trigger matches the output.
func (d *TriggerMatchDetector) matches(output, trigger string) bool {
	if !d.CaseSensitive {
		output = strings.ToLower(output)
		trigger = strings.ToLower(trigger)
	}

	switch d.Mode {
	case MatchStartsWith:
		return strings.HasPrefix(output, trigger)
	default: // MatchContains
		return strings.Contains(output, trigger)
	}
}

// Name returns the detector's fully qualified name.
func (d *TriggerMatchDetector) Name() string {
	return d.DetName
}

// Description returns a human-readable description.
func (d *TriggerMatchDetector) Description() string {
	return d.Desc
}
