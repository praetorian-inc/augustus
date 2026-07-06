package attempt

// Well-known Metadata keys used to carry probe context through to detectors.
//
// Probes attach these to an Attempt via the Metadata map so a detector can
// score against the exact payload the probe used, instead of relying on a
// separately-maintained global list that can silently drift out of sync.
const (
	// MetaMultimodalCanary holds the exact canary phrase a multimodal probe
	// embedded in its image (e.g. "PINEAPPLE SUNSET 7319"). The multimodal
	// Canary detector reads this so the probe remains the single source of
	// truth for its payload.
	MetaMultimodalCanary = "multimodal_canary"

	// MetaMultimodalCovert records whether the probe's channel is covert
	// (steganography, invisible/low-contrast text, metadata, tiny-font,
	// scaling) versus a visible channel (plainly rendered text). The Canary
	// detector uses this to decide whether the canary's mere presence is the
	// finding (covert) or merely informational (visible). (Consumed by a
	// later change; defined here alongside the canary key.)
	MetaMultimodalCovert = "multimodal_covert"
)
