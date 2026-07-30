package mcpprimitive

import (
	"context"
	"fmt"
	"strings"
	"testing"

	_ "github.com/praetorian-inc/augustus/internal/detectors/mcpprimitive"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func newResourceProbe(t *testing.T, cfg registry.Config) *ResourceInjection {
	t.Helper()
	if cfg == nil {
		cfg = registry.Config{}
	}
	// Keep the callback grace period short: the simulated sinks fetch
	// synchronously, so there is nothing to wait for.
	if _, ok := cfg["oob_wait_seconds"]; !ok {
		cfg["oob_wait_seconds"] = 0
	}
	p, err := NewResourceInjection(cfg)
	if err != nil {
		t.Fatalf("NewResourceInjection: %v", err)
	}
	return p.(*ResourceInjection)
}

// scoreAll runs the real primary detector over every attempt and reports the
// highest score seen, so tests assert the verdict the scanner would actually
// produce rather than a stub's.
func scoreAll(t *testing.T, attempts []*attempt.Attempt) float64 {
	t.Helper()
	det, err := detectors.Create("mcpprimitive.Injection", registry.Config{})
	if err != nil {
		t.Fatalf("detectors.Create: %v", err)
	}
	top := 0.0
	for _, a := range attempts {
		scores, err := det.Detect(context.Background(), a)
		if err != nil {
			t.Fatalf("Detect: %v", err)
		}
		for _, s := range scores {
			if s > top {
				top = s
			}
		}
	}
	return top
}

// TestResourceInjection_TraversalConfirmedBySignature: a server that resolves a
// traversal URI onto the real filesystem returns /etc/passwd content, and the
// file-content signature confirms it.
func TestResourceInjection_TraversalConfirmedBySignature(t *testing.T) {
	target := &mockTarget{
		read: func(uri string) (types.MCPResourceResult, error) {
			if strings.Contains(uri, "etc/passwd") || strings.Contains(uri, "etc%2fpasswd") {
				return types.MCPResourceResult{URI: uri, Text: passwdBody, MIMEType: "text/plain", Blocks: 1}, nil
			}
			return types.MCPResourceResult{}, fmt.Errorf("resource not found: %s", uri)
		},
	}

	attempts, err := newResourceProbe(t, nil).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("Probe produced no attempts")
	}
	if got := scoreAll(t, attempts); got != 1.0 {
		t.Errorf("top score = %v, want 1.0 (traversal should be confirmed by the passwd signature)", got)
	}
}

// TestResourceInjection_ConfinedServerScoresZero is the false-positive control: a
// server that refuses every URI it does not serve must produce no finding, and the
// refusal reason must be preserved so a reviewer can see it was asked.
func TestResourceInjection_ConfinedServerScoresZero(t *testing.T) {
	target := &mockTarget{
		read: func(uri string) (types.MCPResourceResult, error) {
			return types.MCPResourceResult{}, fmt.Errorf("access denied for %s", uri)
		},
	}

	attempts, err := newResourceProbe(t, nil).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("Probe produced no attempts")
	}
	if got := scoreAll(t, attempts); got != 0.0 {
		t.Errorf("top score = %v, want 0.0 for a properly confined server", got)
	}
	if reason := metaString(t, attempts[0], attempt.MetadataKeyPrimitiveCallError); reason == "" {
		t.Error("refusal reason was not recorded; a denial must stay visible in the report")
	}
	for _, a := range attempts {
		if a.Status == attempt.StatusError {
			t.Errorf("attempt %q left in error status; a server refusal is a non-finding, not a probe failure", a.Prompt)
		}
	}
}

// TestResourceInjection_EchoServerScoresZero is the second false-positive control:
// a server that echoes the requested URI back in the body must not score. This is
// the failure mode signature-based detection exists to defeat.
func TestResourceInjection_EchoServerScoresZero(t *testing.T) {
	target := &mockTarget{
		read: func(uri string) (types.MCPResourceResult, error) {
			return types.MCPResourceResult{URI: uri, Text: "you requested: " + uri, Blocks: 1}, nil
		},
	}

	attempts, err := newResourceProbe(t, nil).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := scoreAll(t, attempts); got != 0.0 {
		t.Errorf("top score = %v, want 0.0; echoing the URI is not proof of a read", got)
	}
}

// TestResourceInjection_SSRFCallback: a server that resolves an http URI as a
// network location triggers the out-of-band collector, proving SSRF via
// resources/read even though no file was read.
func TestResourceInjection_SSRFCallback(t *testing.T) {
	target := &mockTarget{
		read: func(uri string) (types.MCPResourceResult, error) {
			if strings.HasPrefix(uri, "http://") {
				// Blind shape: the server fetches but returns nothing useful.
				fetchURL(uri)
				return types.MCPResourceResult{URI: uri, Text: "", Blocks: 0}, nil
			}
			return types.MCPResourceResult{}, fmt.Errorf("unsupported scheme: %s", uri)
		},
	}

	attempts, err := newResourceProbe(t, nil).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	sawCallback := false
	for _, a := range attempts {
		if metaString(t, a, attempt.MetadataKeyPrimitiveClass) != classSSRF {
			continue
		}
		if metaBool(a, attempt.MetadataKeyPrimitiveOOBCallback) {
			sawCallback = true
		}
	}
	if !sawCallback {
		t.Error("no out-of-band callback recorded; the SSRF payload should have been fetched")
	}
	if got := scoreAll(t, attempts); got != 1.0 {
		t.Errorf("top score = %v, want 1.0 (blind SSRF is proven by the callback alone)", got)
	}
}

// TestResourceInjection_DerivesFromAdvertisedURI verifies the probe builds
// prefix-preserving payloads from the catalog, which is what defeats a server that
// validates only the leading directory of the URI.
func TestResourceInjection_DerivesFromAdvertisedURI(t *testing.T) {
	target := &mockTarget{
		inv: &types.MCPInventory{
			Resources: []types.MCPResource{{URI: "file:///data/notes.txt", Name: "notes"}},
		},
	}

	if _, err := newResourceProbe(t, nil).Probe(context.Background(), target); err != nil {
		t.Fatalf("Probe: %v", err)
	}

	want := "file:///data/../../../../../../etc/passwd"
	found := false
	for _, uri := range target.readURIs {
		if uri == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("probe never requested %q; requested URIs = %v", want, target.readURIs)
	}
}

// TestResourceInjection_ExpandsResourceTemplate verifies a template parameter is
// treated as the sink it is.
func TestResourceInjection_ExpandsResourceTemplate(t *testing.T) {
	target := &mockTarget{
		inv: &types.MCPInventory{
			ResourceTemplates: []types.MCPResourceTemplate{{URITemplate: "file:///docs/{path}", Name: "docs"}},
		},
	}

	if _, err := newResourceProbe(t, nil).Probe(context.Background(), target); err != nil {
		t.Fatalf("Probe: %v", err)
	}

	sawTraversal, sawCanary := false, false
	for _, uri := range target.readURIs {
		if !strings.HasPrefix(uri, "file:///docs/") {
			continue
		}
		if strings.Contains(uri, "etc/passwd") {
			sawTraversal = true
		}
		if strings.Contains(uri, "/oob/") {
			sawCanary = true
		}
	}
	if !sawTraversal {
		t.Errorf("template parameter never carried a traversal payload; requested = %v", target.readURIs)
	}
	if !sawCanary {
		t.Errorf("template parameter never carried an out-of-band canary; requested = %v", target.readURIs)
	}
}

// TestResourceInjection_BaselineWithoutCatalog is the regression guard for the
// capability-gating trap: a target with no reconnaissance at all must still be
// probed, because "no resources advertised" is not evidence that resources/read is
// unreachable.
func TestResourceInjection_BaselineWithoutCatalog(t *testing.T) {
	target := &readerOnlyTarget{
		read: func(uri string) (types.MCPResourceResult, error) {
			return types.MCPResourceResult{}, fmt.Errorf("not found: %s", uri)
		},
	}

	attempts, err := newResourceProbe(t, nil).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("probe produced no attempts without a catalog; the baseline set must always be sent")
	}
	found := false
	for _, uri := range target.readURIs {
		if uri == "file:///etc/passwd" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("baseline payload was not sent; requested URIs = %v", target.readURIs)
	}
}

// TestResourceInjection_InventoryErrorIsNotFatal: the catalog only enriches the
// payload set, so a failed enumeration degrades to baseline rather than aborting.
func TestResourceInjection_InventoryErrorIsNotFatal(t *testing.T) {
	target := &mockTarget{
		invErr: fmt.Errorf("resources/list exploded"),
		read: func(uri string) (types.MCPResourceResult, error) {
			return types.MCPResourceResult{}, fmt.Errorf("not found: %s", uri)
		},
	}

	attempts, err := newResourceProbe(t, nil).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe should degrade to baseline payloads, got error: %v", err)
	}
	if len(attempts) == 0 {
		t.Error("no attempts after an inventory failure; baseline payloads must still be sent")
	}
}

// TestResourceInjection_RequiresPrimitiveReader: an unsupported target must fail
// loud rather than return a clean-looking empty result, which would read as "no
// injection sinks found".
func TestResourceInjection_RequiresPrimitiveReader(t *testing.T) {
	_, err := newResourceProbe(t, nil).Probe(context.Background(), plainTarget{})
	if err == nil {
		t.Fatal("Probe on a non-primitive target returned nil error; it must fail loud")
	}
	if !strings.Contains(err.Error(), "cannot read MCP primitives") {
		t.Errorf("error should explain the missing capability, got %v", err)
	}
}

// TestResourceInjection_RespectsMaxTargets bounds catalog-derived work and says so.
func TestResourceInjection_RespectsMaxTargets(t *testing.T) {
	inv := &types.MCPInventory{}
	for i := range 10 {
		inv.Resources = append(inv.Resources, types.MCPResource{URI: fmt.Sprintf("file:///d%d/f.txt", i)})
	}
	target := &mockTarget{inv: inv}

	p := newResourceProbe(t, registry.Config{"resource_max_targets": 2})
	if _, err := p.Probe(context.Background(), target); err != nil {
		t.Fatalf("Probe: %v", err)
	}

	// Only the first two advertised resources should contribute derived payloads.
	for i := 2; i < 10; i++ {
		prefix := fmt.Sprintf("file:///d%d/", i)
		for _, uri := range target.readURIs {
			if strings.HasPrefix(uri, prefix) {
				t.Errorf("resource %d was derived from despite the cap of 2: %q", i, uri)
			}
		}
	}
}
