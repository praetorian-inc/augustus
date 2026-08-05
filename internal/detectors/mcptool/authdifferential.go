package mcptool

import (
	"regexp"
	"strings"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// denialVocabularyRE matches CONVENTIONAL refusal wording. It is a generic
// vocabulary — words any practitioner would read as "the server said no" — with
// nothing specific to a server, product, or benchmark.
//
// It is used in ONE direction only: to withhold confidence. A differential that
// looks like an acceptance is promoted to a confident finding only when the probe
// response carries no refusal wording while the control's does. It is NEVER used
// to clear a finding, so a server that answers in another language, or in wording
// this vocabulary misses, degrades to inconclusive (a reviewer looks) rather than
// to a silent clean pass.
//
// Word boundaries matter more than they appear: without them "invalid" would make
// "valid" match, inverting the verdict on the single most common acceptance
// wording there is.
var denialVocabularyRE = regexp.MustCompile(
	`(?i)\b(invalid|unauthori[sz]ed|unauthenticated|forbidden|denied|deny|expired|revoked|rejected|reject|refused|malformed|incorrect|illegal|missing|required|failed|failure|error|unknown|not\s+found|no\s+such|does\s+not\s+exist|nonexistent|bad|not\s+permitted|not\s+allowed|permission|access\s+denied)\b`)

// responseClass normalises a recorded response into a comparable equivalence
// class: the submitted values are masked out (servers routinely echo them, which
// would otherwise make every response differ and fire on every target) and
// whitespace/case are collapsed.
func responseClass(resp string, values ...string) string {
	return normalizeResp(maskID(resp, values...))
}

// differentialVerdict adjudicates a probe-vs-control response differential. It is
// shared by the TokenValidation and FunctionAuthorization detectors because both
// answer the same question: did the probe value reach behaviour the control value
// did not?
//
// It is deliberately SERVER-AGNOSTIC. It never searches for a success string,
// never hashes a body, and assumes no value format. The verdict comes from
// comparing recorded responses to each other:
//
//	no control recorded                        → InconclusiveScore (nothing to compare)
//	probe class == control class                → 0.0 (control value fared identically: safe)
//	replica recorded but disagrees with probe   → InconclusiveScore (target not stable)
//	probe reads as an acceptance, control as a
//	  refusal                                   → 1.0 (confirmed differential)
//	otherwise                                   → InconclusiveScore
//
// The last two branches are the false-positive guard. A correct server may word
// two refusals differently ("bad format" vs "token not found"), which partitions
// responses without being an acceptance; that lands on inconclusive, visible for
// review but never asserted as a vulnerability.
func differentialVerdict(a *attempt.Attempt) float64 {
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

	probeValue := metaString(a, mcpprobe.MetaAuthProbeValue)
	controlValue := metaString(a, mcpprobe.MetaAuthControlValue)
	replicaValue := metaString(a, mcpprobe.MetaAuthReplicaValue)

	// Mask EVERY submitted value out of EVERY response, so an echoed value can
	// never be the thing that makes two responses differ.
	mask := []string{probeValue, controlValue, replicaValue}
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

	probeDenied := denialVocabularyRE.MatchString(probeResp)
	controlDenied := denialVocabularyRE.MatchString(controlResp)
	if !probeDenied && controlDenied {
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
