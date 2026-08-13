package mcptool

import (
	"strings"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// responseClass normalises a recorded response into a comparable equivalence
// class: the submitted values are masked out (servers routinely echo them, which
// would otherwise make every response differ and fire on every target) and
// whitespace/case are collapsed.
func responseClass(resp string, values ...string) string {
	return normalizeResp(maskID(resp, values...))
}

// differentialVerdict adjudicates a probe-vs-control response differential. It is
// shared by the TokenValidation and FunctionAuthorization detectors because both
// answer the same question: did the probe value reach behaviour an equivalent
// unentitled value did not?
//
// It is deliberately SERVER-AGNOSTIC. It never searches for a success string,
// never hashes a body, and assumes no value format. The verdict comes from
// comparing the target's own recorded responses to each other, in this order:
//
//	errored / empty attempt                     → 0.0  (no evidence)
//	no control recorded                         → InconclusiveScore
//	probe response READS AS A REFUSAL           → 0.0  (the probe gained nothing)
//	probe class == control class                 → 0.0  (control fared identically)
//	same-shape replica disagrees with probe      → InconclusiveScore (unstable target)
//	second control present:
//	  matches probe                              → 0.0
//	  two controls disagree with each other      → InconclusiveScore (responses vary by value)
//	  otherwise                                  → 1.0
//	control READS AS A REFUSAL                   → 1.0  (refused there, served here)
//	otherwise                                    → InconclusiveScore
//
// Two branches carry most of the false-positive protection.
//
// First, a probe response that itself reads as a refusal is scored 0.0 outright,
// whatever the control said. This is what makes a correct server safe rather than
// merely inconclusive: a verifier that answers a malformed value "incorrect
// format" and a well-formed-but-unissued one "token not found" has partitioned its
// responses, but it REFUSED the never-issued value — which is exactly the desired
// behaviour, not a weakness. Differing refusal wording is a better error message,
// not an authorization flaw.
//
// Second, where the control is itself a successful lower-privilege call (so
// "control was refused" cannot be the signal), a single differing response is
// ambiguous — it could be the privilege or merely the value. A second, independent
// unprivileged control resolves it: if both controls agree with each other and the
// probe differs from both, the privilege is isolated as the cause. If the two
// controls disagree, the target's responses vary by value and no conclusion is
// drawn.
func differentialVerdict(a *attempt.Attempt) float64 {
	// An explicit inconclusive mark wins over every comparison below.
	//
	// The probes set this when a leg of the differential could not be obtained —
	// a CSPRNG failure, an unsampled issuer, an exhausted retry. This detector
	// never read it, so a missing replica response normalised to the same class as
	// the probe response, the logic fell through to the control-refusal branch, and
	// an attempt the probe had already declared unmeasurable scored 1.0. Adding
	// inconclusive marking to the probes made that path more reachable, not less,
	// so the two halves have to agree.
	if metaBool(a, attempt.MetadataKeyInconclusive) {
		return InconclusiveScore
	}
	if a.Error != "" {
		return 0.0
	}
	if len(a.Outputs) == 0 {
		return 0.0
	}
	probeResp := a.Outputs[0]
	controlResp := metaString(a, mcpprobe.MetaAuthControl)
	if strings.TrimSpace(controlResp) == "" {
		return InconclusiveScore
	}

	// The probe value was refused: nothing was reached, so there is nothing to
	// report regardless of how the control fared.
	//
	// This is a TEXT match, so a served success whose body merely contains a
	// refusal word (`"error": null`) can be misread as a refusal and clear a real
	// finding. The structural fix — key off ToolResult.IsError instead — is tracked
	// in LAB-5841; the vocabulary cannot simply be narrowed, because those same
	// words carry real meaning in a genuine refusal.
	if mcpprobe.ReadsAsRefusal(probeResp) {
		return 0.0
	}

	probeValue := metaString(a, mcpprobe.MetaAuthProbeValue)
	controlValue := metaString(a, mcpprobe.MetaAuthControlValue)
	replicaValue := metaString(a, mcpprobe.MetaAuthReplicaValue)
	control2Value := metaString(a, mcpprobe.MetaAuthControl2Value)

	// Mask EVERY submitted value out of EVERY response, so an echoed value can
	// never be the thing that makes two responses differ.
	mask := []string{probeValue, controlValue, replicaValue, control2Value}
	probeClass := responseClass(probeResp, mask...)
	controlClass := responseClass(controlResp, mask...)

	// The control value fared exactly as the probe value did: no differential.
	if probeClass == controlClass {
		return 0.0
	}

	// A same-shape replica must corroborate. Both random values were certainly
	// never issued, so a target doing a real lookup answers them alike; a
	// disagreement means the target's responses vary for reasons we cannot model.
	if replicaValue != "" {
		replicaResp := metaString(a, mcpprobe.MetaAuthReplicaResponse)
		if responseClass(replicaResp, mask...) != probeClass {
			return InconclusiveScore
		}
	}

	// A second unprivileged control isolates privilege from response variation.
	if control2Resp := metaString(a, mcpprobe.MetaAuthControl2Response); control2Resp != "" {
		control2Class := responseClass(control2Resp, mask...)
		// The probe fared exactly as an arbitrary unentitled value did: nothing
		// special was reached.
		if control2Class == probeClass {
			return 0.0
		}
		// The second control was REFUSED, so the target maintains an allow-list of
		// accepted values. The probe value was served by that allow-list AND reached
		// behaviour the ordinary declared value did not — the escalation is isolated
		// without needing the two controls to agree, which they cannot here (one is
		// served, one refused).
		if mcpprobe.ReadsAsRefusal(control2Resp) {
			return 1.0
		}
		// Both controls were served but disagree with each other: the target's
		// responses vary by value, so a difference cannot be attributed to privilege.
		if control2Class != controlClass {
			return InconclusiveScore
		}
		return 1.0
	}

	// The control was refused where the probe was served: unambiguous.
	if mcpprobe.ReadsAsRefusal(controlResp) {
		return 1.0
	}
	return InconclusiveScore
}

// scoresFor spreads a single verdict across an attempt's outputs, emitting one
// score when there are none so a finding on an empty response still surfaces.
func scoresFor(a *attempt.Attempt, score float64) []float64 {
	scores := make([]float64, len(a.Outputs))
	if score == 0.0 {
		return scores
	}
	if len(scores) == 0 {
		return []float64{score}
	}
	for i := range scores {
		scores[i] = score
	}
	return scores
}
