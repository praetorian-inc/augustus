package mcpprimitive

import (
	"slices"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// TestRiskInfo_Populated verifies every mcpprimitive probe exposes a complete
// RiskDescriber write-up (the finding definition Guard renders). RiskInfo returns a
// literal, so zero-value structs are sufficient — no construction needed.
func TestRiskInfo_Populated(t *testing.T) {
	for _, p := range allProbes() {
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

// allProbes lists every probe this package ships, so package-wide contracts
// (RiskInfo, metadata) cannot silently skip a newly added probe. RiskInfo and the
// metadata methods return literals, so zero-value structs are sufficient.
func allProbes() []probes.Prober {
	return []probes.Prober{&ResourceInjection{}, &PromptTemplateInjection{}, &ContentLeak{}}
}

// TestProbeMetadata_Populated checks the introspection surface every probe in this
// package is expected to expose. The detector expectations are per probe: the two
// injection probes score a sink with mcpprimitive.Injection and additionally scan
// served content, whereas ContentLeak scores credential exposure with the shared
// mcpsecrets.Credential detector and needs no secondary.
func TestProbeMetadata_Populated(t *testing.T) {
	wantPrimary := map[string]string{
		"mcpprimitive.ResourceInjection":       "mcpprimitive.Injection",
		"mcpprimitive.PromptTemplateInjection": "mcpprimitive.Injection",
		"mcpprimitive.ContentLeak":             "mcpsecrets.Credential",
	}
	wantSecondary := map[string][]string{
		"mcpprimitive.ResourceInjection":       {"mcpprimitive.ContentInjection"},
		"mcpprimitive.PromptTemplateInjection": {"mcpprimitive.ContentInjection"},
		"mcpprimitive.ContentLeak":             nil,
	}

	for _, p := range allProbes() {
		md, ok := p.(types.ProbeMetadata)
		if !ok {
			t.Errorf("%s does not implement types.ProbeMetadata", p.Name())
			continue
		}
		if md.Description() == "" || md.Goal() == "" {
			t.Errorf("%s has an empty Description or Goal", p.Name())
		}
		want, known := wantPrimary[p.Name()]
		if !known {
			t.Errorf("%s is not covered by this test's detector expectations", p.Name())
			continue
		}
		if got := md.GetPrimaryDetector(); got != want {
			t.Errorf("%s primary detector = %q, want %q", p.Name(), got, want)
		}

		var got []string
		if sd, ok := p.(types.ProbeSecondaryDetectors); ok {
			for _, s := range sd.GetSecondaryDetectors() {
				got = append(got, s.Name)
			}
		}
		if !slices.Equal(got, wantSecondary[p.Name()]) {
			t.Errorf("%s secondary detectors = %v, want %v", p.Name(), got, wantSecondary[p.Name()])
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
