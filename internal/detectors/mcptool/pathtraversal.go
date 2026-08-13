package mcptool

import (
	"context"
	"regexp"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("mcptool.PathTraversal", NewPathTraversalDetector)
}

// PathTraversalDetector flags a tool output that contains a file-content
// signature the probe expected to see if the traversal payload resolved to the
// target file. The signature (e.g. "root:x:0:0:", "[extensions]") never appears
// in the payload text, so a tool that merely echoes its argument cannot trigger
// a false positive — mirroring the mcptool.Injection design.
type PathTraversalDetector struct{}

// NewPathTraversalDetector constructs the detector.
func NewPathTraversalDetector(_ registry.Config) (detectors.Detector, error) {
	return &PathTraversalDetector{}, nil
}

func (d *PathTraversalDetector) Name() string { return "mcptool.PathTraversal" }

func (d *PathTraversalDetector) Description() string {
	return "Flags tool outputs containing a well-known system-file signature (e.g. /etc/passwd or win.ini) that only a real filesystem read could have produced"
}

// writeSuccessRE matches phrases a tool typically produces when it has
// actually WRITTEN a file (not merely echoed the path). Detection for
// write payloads requires one of these in the same response as the
// canary — echo alone ("read /tmp/proof-<canary>", "processing
// /tmp/proof-<canary>") is not evidence a file was created.
var writeSuccessRE = regexp.MustCompile(`(?i)\b(wrote|written|saved|created|stored|updated|uploaded|success|successfully|ok|done|complete)\b`)

// Detect scoring:
//
//	read payload  + signature present                    → 1.0
//	write payload + canary + !IsError + success-verb    → InconclusiveScore
//	write payload + canary + IsError                    → 0.0
//	write payload + canary + !IsError but no success    → 0.0
//	no signature / no match                             → 0.0
//
// Read vs write score asymmetry is deliberate. A read that leaks the
// literal contents of /etc/passwd (`root:x:0:0:` etc.) is
// proof-by-content-signature: nothing but reading the file could have
// produced that string. A write that echoes the canary path back with
// success wording is proof-by-server-claim only — a tool that includes
// "wrote" in its response text without ever touching the filesystem
// produces the same signal. The probe cannot verify the file exists
// (no side-channel filesystem access), so we surface the write finding
// as inconclusive (0.5) rather than a confirmed vulnerability.
// Independent verification (a read-back via another tool, or manual
// filesystem inspection) is left to the reviewer. Fixes CodeRabbit
// finding #1 on PR #234.
func (d *PathTraversalDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	scores := make([]float64, len(a.Outputs))
	sigs := pathTraversalSignaturesFrom(a)
	if len(sigs) == 0 {
		return scores, nil
	}
	isWrite := metaBool(a, attempt.MetadataKeyPathTraversalIsWrite)
	toolErrored := metaBool(a, attempt.MetadataKeyPathTraversalToolIsError)
	if isWrite && toolErrored {
		return scores, nil
	}
	// A prefix-append attempt that defeated the tool's own path guard is a
	// finding even with no file content, and the probe has already done the
	// paired comparison that proves it (see markGuardBypass). Scored
	// inconclusive rather than confirmed: the guard is demonstrably bypassable,
	// but on this host the escaped path resolved to nothing, so arbitrary read
	// is proven reachable rather than proven. Strictly below a content hit, and
	// never inferred from the error text alone.
	guardBypassed := metaBool(a, attempt.MetadataKeyPathTraversalGuardBypass)
	for i, out := range a.Outputs {
		matched := false
		for _, s := range sigs {
			if s != "" && strings.Contains(out, s) {
				matched = true
				break
			}
		}
		if !matched {
			if guardBypassed {
				scores[i] = InconclusiveScore
			}
			continue
		}
		if isWrite && !writeSuccessRE.MatchString(out) {
			continue // canary present but no success verb — echo, not proof
		}
		if isWrite {
			scores[i] = InconclusiveScore
		} else {
			scores[i] = 1.0
		}
	}
	return scores, nil
}

// pathTraversalSignaturesFrom reads the expected file signatures from attempt
// metadata, tolerating both []string and the []any that survives a JSON
// round-trip.
func pathTraversalSignaturesFrom(a *attempt.Attempt) []string {
	raw, ok := a.GetMetadata(attempt.MetadataKeyPathTraversalSignatures)
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
