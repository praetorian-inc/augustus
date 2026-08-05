package mcptool

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// att builds a completed attempt carrying one output, the shape callOne produces.
func att(output string) *attempt.Attempt {
	a := attempt.New("payload")
	a.AddOutput(output)
	a.Complete()
	return a
}

func bypassed(a *attempt.Attempt) bool {
	v, ok := a.GetMetadata(attempt.MetadataKeyPathTraversalGuardBypass)
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

func TestMarkGuardBypass(t *testing.T) {
	// The real DVMCP challenge 2 responses. The bare payload is refused on the
	// tool's own authorization grounds; the prefixed one gets past the guard and
	// fails at the filesystem layer instead. That change is the finding.
	guardRefusal := "Error: Access to '../../../../../../etc/passwd' is not allowed. Only files in /tmp/safe/ are accessible."
	fsError := "Error reading file: [Errno 2] No such file or directory: '/tmp/safe/../../../../../../etc/passwd'"

	t.Run("refusal then filesystem error is a bypass", func(t *testing.T) {
		prefixed := att(fsError)
		markGuardBypass(prefixed, att(guardRefusal))
		if !bypassed(prefixed) {
			t.Error("guard bypass not recorded")
		}
		// The reviewer needs both halves of the differential, not just the verdict.
		if v, ok := prefixed.GetMetadata(attempt.MetadataKeyPathTraversalBaselineResponse); !ok || v != guardRefusal {
			t.Errorf("baseline response metadata = %v, want the refusal text", v)
		}
	})

	// False-positive guards. A filesystem error on its own is the ordinary result
	// of asking for a file that is not there — it is only evidence when paired
	// with a baseline the guard actively refused.
	t.Run("filesystem error alone is not a bypass", func(t *testing.T) {
		prefixed := att(fsError)
		markGuardBypass(prefixed, att(fsError))
		if bypassed(prefixed) {
			t.Error("recorded a bypass with no authorization refusal in the baseline")
		}
	})

	t.Run("still refused after prefixing is not a bypass", func(t *testing.T) {
		prefixed := att(guardRefusal)
		markGuardBypass(prefixed, att(guardRefusal))
		if bypassed(prefixed) {
			t.Error("recorded a bypass when the guard refused both payloads")
		}
	})

	t.Run("permission denied is not treated as a filesystem error", func(t *testing.T) {
		// "Permission denied" is ambiguous between the authorization layer and
		// the filesystem layer, so it must not satisfy the filesystem half.
		prefixed := att("Error reading file: [Errno 13] Permission denied: '/tmp/safe/../../etc/shadow'")
		markGuardBypass(prefixed, att(guardRefusal))
		if bypassed(prefixed) {
			t.Error("permission-denied counted as a filesystem-layer error")
		}
	})

	t.Run("nil and empty inputs are safe", func(t *testing.T) {
		prefixed := att(fsError)
		markGuardBypass(prefixed, nil)
		markGuardBypass(nil, att(guardRefusal))
		markGuardBypass(prefixed, att(""))
		if bypassed(prefixed) {
			t.Error("recorded a bypass from a missing or empty baseline")
		}
	})
}
