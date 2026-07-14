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

	// MetadataKeyInjectionCanaries holds the []string of canary markers a
	// toolsec injection probe expects to see in a tool's output if the tool
	// evaluated the injected payload. Read by the toolsec.Injection detector.
	MetadataKeyInjectionCanaries = "toolsec.injection_canaries"

	// MetadataKeySSRFCallback (bool) records whether the toolsec.SSRF probe's
	// out-of-band collector received a callback for this attempt's canary URL —
	// proof of server-side request forgery, including the blind case.
	MetadataKeySSRFCallback = "toolsec.ssrf_callback"
	// MetadataKeySSRFReflected (bool) records whether the tool's response
	// contained the collector's body marker (non-blind SSRF: the tool fetched
	// the URL and returned its content).
	MetadataKeySSRFReflected = "toolsec.ssrf_reflected"
	// MetadataKeySSRFOOBURL (string) is the canary URL injected for this attempt.
	MetadataKeySSRFOOBURL = "toolsec.ssrf_oob_url"

	// MetadataKeyBOLAID (string) is the victim object identifier the toolsec.BOLA
	// probe called a getter with under the attacker's identity.
	MetadataKeyBOLAID = "toolsec.bola.id"
	// MetadataKeyBOLAVictimIdentity (string) labels the identity that owns the
	// object the attacker attempted to read.
	MetadataKeyBOLAVictimIdentity = "toolsec.bola.victim_identity"
	// MetadataKeyBOLAPositiveControl (string) is the attacker's OWN-object response
	// for the same getter — a served baseline the toolsec.BOLA detector's judge uses
	// to calibrate what "served" looks like on this server. Absent when the attacker
	// owns no object for that getter.
	MetadataKeyBOLAPositiveControl = "toolsec.bola.positive_control"
	// MetadataKeyBOLANegativeControl (string) is the attacker's response for a
	// well-formed but NONEXISTENT id on the same getter — a denied/not-found baseline.
	// The detector uses it deterministically (stage-1 prune) and passes it to the
	// judge (stage 2) to calibrate what "denied/empty" looks like on this server.
	MetadataKeyBOLANegativeControl = "toolsec.bola.negative_control"
	// MetadataKeyBOLANegativeControlError (string) records why the negative-control
	// call failed, when it did. The probe stamps this instead of the denial baseline
	// so a transient failure on the nonexistent-id call is visible (never a silent
	// missing baseline) without failing the whole attempt.
	MetadataKeyBOLANegativeControlError = "toolsec.bola.negative_control_error"
	// MetadataKeyBOLANonexistentID (string) is the well-formed-nonexistent id the
	// probe substituted for the negative control. The detector masks BOTH this id
	// and the target id when comparing the two responses in the stage-1 prune, so a
	// not-found echoing the (different) id still collapses to the same shape. Keeping
	// it in metadata means the detector never re-derives it and stays id-format
	// agnostic.
	MetadataKeyBOLANonexistentID = "toolsec.bola.nonexistent_id"
)
