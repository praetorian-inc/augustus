package mcpconfig

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// TestRiskInfo_Populated verifies the mcpconfig probe exposes a complete
// RiskDescriber write-up. RiskInfo returns a literal, so a zero-value struct
// suffices — no construction needed.
func TestRiskInfo_Populated(t *testing.T) {
	for _, p := range []probes.Prober{
		&CredentialExposure{},
	} {
		rd, ok := p.(types.RiskDescriber)
		if !ok {
			t.Errorf("%s does not implement types.RiskDescriber", p.Name())
			continue
		}
		info := rd.RiskInfo()
		if info.Description == "" || info.Impact == "" || info.Recommendation == "" ||
			info.References == "" || info.Taxonomies == "" || info.CVSSVector == "" ||
			info.Verification == "" {
			t.Errorf("%s RiskInfo has empty field(s): %+v", p.Name(), info)
		}
		if !strings.HasPrefix(info.CVSSVector, "CVSS:4.0/") {
			t.Errorf("%s CVSSVector is not a CVSS v4.0 vector: %q", p.Name(), info.CVSSVector)
		}
		// Verification is static prose consumers render and append to: it must
		// carry no template tokens (SSTI contract) and no angle-bracket
		// placeholders (which break Guard evidence rendering).
		if strings.Contains(info.Verification, "{{") ||
			strings.Contains(info.Verification, "<") || strings.Contains(info.Verification, ">") {
			t.Errorf("%s Verification must be static (no template tokens or angle brackets): %q", p.Name(), info.Verification)
		}
	}
}
