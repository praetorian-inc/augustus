package mcptool

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// TestRiskInfo_Populated verifies every mcptool probe exposes a complete
// RiskDescriber write-up (the finding definition Guard renders). RiskInfo returns
// a literal, so zero-value structs are sufficient — no construction needed.
func TestRiskInfo_Populated(t *testing.T) {
	for _, p := range []probes.Prober{
		&Injection{}, &SSRF{}, &BOLA{}, &PathTraversal{}, &ResponseLeak{},
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
