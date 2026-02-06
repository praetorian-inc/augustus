// Package promptinject provides detectors for PromptInject framework attacks.
//
// Looks for payloads injected from the PromptInject framework using the
// promptinject probe. Triggers are stored in attempt metadata.
package promptinject

import (
	"github.com/praetorian-inc/augustus/internal/detectors/base"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("promptinject.AttackRogueString", NewAttackRogueString)
	detectors.Register("promptinjection.DirectInjection", NewDirectInjection)
	detectors.Register("promptinjection.ContextManipulation", NewContextManipulation)
	detectors.Register("promptinjection.RoleManipulation", NewRoleManipulation)
}

// AttackRogueString detects if model emits any trigger string from metadata.
// Triggers are expected in attempt.Metadata["triggers"] as []string or []any.
// Case-insensitive matching by default.
type AttackRogueString = base.TriggerMatchDetector

// NewAttackRogueString creates a new AttackRogueString detector.
// Optional config:
//   - case_sensitive: bool - false (default)
func NewAttackRogueString(cfg registry.Config) (detectors.Detector, error) {
	return base.NewTriggerMatchDetector(
		cfg,
		base.MatchContains,
		"promptinject.AttackRogueString",
		"Detects if model emits trigger strings from PromptInject framework",
	), nil
}

// DirectInjection detects direct prompt injection attacks.
// Triggers are expected in attempt.Metadata["triggers"] as []string or []any.
// Case-insensitive matching by default.
type DirectInjection = base.TriggerMatchDetector

// NewDirectInjection creates a new DirectInjection detector.
// Optional config:
//   - case_sensitive: bool - false (default)
func NewDirectInjection(cfg registry.Config) (detectors.Detector, error) {
	return base.NewTriggerMatchDetector(
		cfg,
		base.MatchContains,
		"promptinjection.DirectInjection",
		"Detects direct prompt injection attacks that attempt to override system instructions",
	), nil
}

// ContextManipulation detects context manipulation attacks.
// Triggers are expected in attempt.Metadata["triggers"] as []string or []any.
// Case-insensitive matching by default.
type ContextManipulation = base.TriggerMatchDetector

// NewContextManipulation creates a new ContextManipulation detector.
// Optional config:
//   - case_sensitive: bool - false (default)
func NewContextManipulation(cfg registry.Config) (detectors.Detector, error) {
	return base.NewTriggerMatchDetector(
		cfg,
		base.MatchContains,
		"promptinjection.ContextManipulation",
		"Detects context manipulation attacks through false contextual claims",
	), nil
}

// RoleManipulation detects role manipulation attacks.
// Triggers are expected in attempt.Metadata["triggers"] as []string or []any.
// Case-insensitive matching by default.
type RoleManipulation = base.TriggerMatchDetector

// NewRoleManipulation creates a new RoleManipulation detector.
// Optional config:
//   - case_sensitive: bool - false (default)
func NewRoleManipulation(cfg registry.Config) (detectors.Detector, error) {
	return base.NewTriggerMatchDetector(
		cfg,
		base.MatchContains,
		"promptinjection.RoleManipulation",
		"Detects role manipulation attacks that confuse model identity",
	), nil
}
