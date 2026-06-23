package attempt

// Metadata key constants used across probes, buffs, and detectors.
// Using these constants prevents silent breakage from key typos.
const (
	MetadataKeySystemPrompt = "system_prompt"
	MetadataKeyTriggers     = "triggers"
	MetadataKeyFlipMode     = "flip_mode"
	MetadataKeyVariant      = "variant"
	MetadataKeyToolCalls    = "tool_calls"
	// MetadataKeyGoal carries the probe's objective so goal-conditioned
	// detectors (e.g. agent.ToolLeakJudge) can read it from the attempt. The
	// multi-turn / PAIR-TAP attack engines already write this key; surfacing it
	// for single-turn template probes lets judge detectors work in chat-mode.
	MetadataKeyGoal = "goal"
)
