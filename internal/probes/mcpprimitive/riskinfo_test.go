package mcpprimitive

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// TestRiskInfo_Populated verifies every mcpprimitive probe exposes a complete
// RiskDescriber write-up (the finding definition Guard renders). RiskInfo returns a
// literal, so zero-value structs are sufficient — no construction needed.
func TestRiskInfo_Populated(t *testing.T) {
	for _, p := range []probes.Prober{
		&ResourceInjection{}, &PromptTemplateInjection{},
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

// TestProbeMetadata_Populated checks the introspection surface every probe in this
// package is expected to expose, including a primary detector that actually names a
// detector this package ships.
func TestProbeMetadata_Populated(t *testing.T) {
	for _, p := range []probes.Prober{
		&ResourceInjection{}, &PromptTemplateInjection{},
	} {
		md, ok := p.(types.ProbeMetadata)
		if !ok {
			t.Errorf("%s does not implement types.ProbeMetadata", p.Name())
			continue
		}
		if md.Description() == "" || md.Goal() == "" {
			t.Errorf("%s has an empty Description or Goal", p.Name())
		}
		if got := md.GetPrimaryDetector(); got != "mcpprimitive.Injection" {
			t.Errorf("%s primary detector = %q, want mcpprimitive.Injection", p.Name(), got)
		}

		sd, ok := p.(types.ProbeSecondaryDetectors)
		if !ok {
			t.Errorf("%s does not declare secondary detectors", p.Name())
			continue
		}
		secondaries := sd.GetSecondaryDetectors()
		if len(secondaries) != 1 || secondaries[0].Name != "mcpprimitive.ContentInjection" {
			t.Errorf("%s secondary detectors = %+v, want mcpprimitive.ContentInjection", p.Name(), secondaries)
		}
	}
}

// TestGetPrompts_NonEmpty guards the report-introspection surface: both probes must
// describe the payload shapes they send.
func TestGetPrompts_NonEmpty(t *testing.T) {
	res := &ResourceInjection{}
	if len(res.GetPrompts()) == 0 {
		t.Error("ResourceInjection.GetPrompts() is empty")
	}
	// PromptTemplateInjection renders its canary payloads, so it needs a constructed probe.
	p := newPromptProbe(t, nil)
	if len(p.GetPrompts()) == 0 {
		t.Error("PromptTemplateInjection.GetPrompts() is empty")
	}
}
