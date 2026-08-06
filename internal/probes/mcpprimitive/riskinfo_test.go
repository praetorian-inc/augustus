package mcpprimitive

import (
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/types"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// TestRiskInfo_Populated verifies every mcpprimitive probe exposes a complete
// RiskDescriber write-up (the finding definition Guard renders). RiskInfo returns a
// literal, so zero-value structs are sufficient — no construction needed.
func TestRiskInfo_Populated(t *testing.T) {
	for _, p := range allProbes(t) {
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

// allProbes returns every probe this package ships, so package-wide contracts
// (RiskInfo, metadata) cannot silently skip a newly added probe.
//
// Derived from the registry rather than hand-listed. A hand-written list only
// enforces the contract if the author who adds a probe also remembers to extend
// the list — which is exactly the omission these tests exist to catch. Building
// from probes.Registry means registering in init() is sufficient.
func allProbes(t *testing.T) []probes.Prober {
	t.Helper()
	names := probes.Registry.List()
	sort.Strings(names)
	var out []probes.Prober
	for _, name := range names {
		if !strings.HasPrefix(name, "mcpprimitive.") {
			continue
		}
		p, err := probes.Registry.Create(name, registry.Config{})
		if err != nil {
			t.Fatalf("construct %s: %v", name, err)
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		t.Fatal("no mcpprimitive probes found in the registry; the contract tests would pass vacuously")
	}
	return out
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

	for _, p := range allProbes(t) {
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
