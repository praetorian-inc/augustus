package attempt

// Metadata key constants used across probes, buffs, and detectors.
// Using these constants prevents silent breakage from key typos.
const (
	MetadataKeySystemPrompt = "system_prompt"
	MetadataKeyTriggers     = "triggers"
	MetadataKeyFlipMode     = "flip_mode"
	MetadataKeyVariant      = "variant"
	MetadataKeyToolCalls    = "tool_calls"

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
)
