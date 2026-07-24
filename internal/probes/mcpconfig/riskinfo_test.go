package mcpconfig

import (
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
			info.References == "" || info.Taxonomies == "" || info.CVSSVector == "" {
			t.Errorf("%s RiskInfo has empty field(s): %+v", p.Name(), info)
		}
	}
}
