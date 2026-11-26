package mcptransport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// --- test helpers ---

func newMetadataInjectionProbe(t *testing.T, cfg registry.Config) *MetadataInjection {
	t.Helper()
	p, err := NewMetadataInjection(cfg)
	if err != nil {
		t.Fatalf("NewMetadataInjection: %v", err)
	}
	return p.(*MetadataInjection)
}

// toolsListResponse builds a JSON-RPC response body with the given tool names.
func toolsListResponse(tools ...string) []byte {
	type tool struct {
		Name string `json:"name"`
	}
	type result struct {
		Tools []tool `json:"tools"`
	}
	ts := make([]tool, len(tools))
	for i, name := range tools {
		ts[i] = tool{Name: name}
	}
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result":  result{Tools: ts},
	}
	b, _ := json.Marshal(resp)
	return b
}

// uniformToolServer returns the same tools regardless of _meta content (safe).
func uniformToolServer(t *testing.T, tools ...string) *httptest.Server {
	t.Helper()
	body := toolsListResponse(tools...)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
}

// identityGatingServer returns extra tools when clientInfo.name is "claude-desktop".
func identityGatingServer(t *testing.T) *httptest.Server {
	t.Helper()
	baseTools := toolsListResponse("read_file", "list_dir")
	extraTools := toolsListResponse("read_file", "list_dir", "admin_panel", "execute_code")

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params struct {
				Meta map[string]json.RawMessage `json:"_meta"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(baseTools)
			return
		}
		if raw, ok := req.Params.Meta["io.modelcontextprotocol/clientInfo"]; ok {
			var ci struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(raw, &ci) == nil && ci.Name == "claude-desktop" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(extraTools)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(baseTools)
	}))
}

// versionGatingServer returns extra tools when protocolVersion is "2024-11-05".
func versionGatingServer(t *testing.T) *httptest.Server {
	t.Helper()
	baseTools := toolsListResponse("read_file", "list_dir")
	legacyTools := toolsListResponse("read_file", "list_dir", "legacy_admin")

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params struct {
				Meta map[string]json.RawMessage `json:"_meta"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(baseTools)
			return
		}
		if raw, ok := req.Params.Meta["io.modelcontextprotocol/protocolVersion"]; ok {
			var version string
			if json.Unmarshal(raw, &version) == nil && version == "2024-11-05" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(legacyTools)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(baseTools)
	}))
}

// --- registration test ---

func TestMetadataInjection_Registration(t *testing.T) {
	p := newMetadataInjectionProbe(t, registry.Config{})
	if p.Name() != "mcptransport.MetadataInjection" {
		t.Errorf("Name() = %q, want mcptransport.MetadataInjection", p.Name())
	}
	if p.GetPrimaryDetector() != "mcptransport.MetadataInjection" {
		t.Errorf("GetPrimaryDetector() = %q, want mcptransport.MetadataInjection", p.GetPrimaryDetector())
	}
}

// --- skip test ---

func TestMetadataInjection_SkipsWithoutEndpoint(t *testing.T) {
	p := newMetadataInjectionProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), plainGen{})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if attempts != nil {
		t.Errorf("expected nil attempts with no endpoint, got %d", len(attempts))
	}
}

// --- safe server test ---

func TestMetadataInjection_UniformServer_NoDifferential(t *testing.T) {
	srv := uniformToolServer(t, "read_file", "list_dir", "search")
	defer srv.Close()

	p := newMetadataInjectionProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	// Should have baseline + all variants.
	if len(attempts) < 2 {
		t.Fatalf("expected at least 2 attempts (baseline + variants), got %d", len(attempts))
	}

	// No variant should show a differential.
	for _, a := range attempts {
		class, _ := a.GetMetadata(attempt.MetadataKeyMetadataInjectionClass)
		classStr, _ := class.(string)
		if classStr == "baseline" {
			continue
		}
		if metaBool(a, attempt.MetadataKeyMetadataInjectionDifferential) {
			t.Errorf("variant %q unexpectedly shows a differential on a uniform server", a.Prompt)
		}
	}

	// No findings via detector.
	findings := countFindings(attempts)
	if findings != 0 {
		t.Errorf("uniform server should produce 0 findings, got %d", findings)
	}
}

// --- vulnerable server tests ---

func TestMetadataInjection_IdentityGating_Differential(t *testing.T) {
	srv := identityGatingServer(t)
	defer srv.Close()

	p := newMetadataInjectionProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	// The claude-desktop variant should show a differential.
	found := false
	for _, a := range attempts {
		if strings.Contains(a.Prompt, "claude-desktop") {
			if !metaBool(a, attempt.MetadataKeyMetadataInjectionDifferential) {
				t.Errorf("claude-desktop variant should show a differential")
			}
			found = true
			// Verify tool counts differ.
			baseCount, _ := a.GetMetadata(attempt.MetadataKeyMetadataInjectionBaselineTools)
			varCount, _ := a.GetMetadata(attempt.MetadataKeyMetadataInjectionVariantTools)
			if baseCount == varCount {
				t.Errorf("tool counts should differ: baseline=%v variant=%v", baseCount, varCount)
			}
		}
	}
	if !found {
		t.Fatal("expected a claude-desktop variant attempt")
	}

	// Should have at least one finding.
	if findings := countFindings(attempts); findings == 0 {
		t.Errorf("identity-gating server should produce at least 1 finding")
	}
}

func TestMetadataInjection_VersionGating_Differential(t *testing.T) {
	srv := versionGatingServer(t)
	defer srv.Close()

	p := newMetadataInjectionProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	// The protocol-version-downgrade variant should show a differential.
	found := false
	for _, a := range attempts {
		class, _ := a.GetMetadata(attempt.MetadataKeyMetadataInjectionClass)
		classStr, _ := class.(string)
		if classStr == "protocol-version-downgrade" {
			if !metaBool(a, attempt.MetadataKeyMetadataInjectionDifferential) {
				t.Errorf("protocol-version-downgrade should show a differential")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("expected a protocol-version-downgrade variant attempt")
	}
}

// --- error server test ---

func TestMetadataInjection_ErrorServer_Inconclusive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := newMetadataInjectionProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	// Only baseline should be returned, with an error.
	if len(attempts) != 1 {
		t.Errorf("expected 1 attempt (failed baseline), got %d", len(attempts))
	}
	if attempts[0].Status != attempt.StatusError {
		t.Errorf("baseline should be errored, got status %q", attempts[0].Status)
	}
}

// --- endpoint resolution test ---

func TestMetadataInjection_ResolvesEndpointFromGenerator(t *testing.T) {
	srv := uniformToolServer(t, "tool1")
	defer srv.Close()

	p := newMetadataInjectionProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Errorf("expected attempts when generator supplies endpoint via MCPEndpoint")
	}
}

// --- detector scoring helpers ---

// metadataInjectionDetectorStub reimplements the detection check locally.
type metadataInjectionDetectorStub struct{}

func (metadataInjectionDetectorStub) detect(a *attempt.Attempt) []float64 {
	scores := make([]float64, len(a.Outputs))
	raw, _ := a.GetMetadata(attempt.MetadataKeyMetadataInjectionClass)
	class, _ := raw.(string)
	if class == "baseline" {
		return scores
	}
	if a.Status == attempt.StatusError {
		for i := range scores {
			scores[i] = 0.5
		}
		if len(scores) == 0 {
			return []float64{0.5}
		}
		return scores
	}
	if !metaBoolStub(a, attempt.MetadataKeyMetadataInjectionDifferential) {
		return scores
	}
	if len(scores) == 0 {
		return []float64{1.0}
	}
	for i := range scores {
		scores[i] = 1.0
	}
	return scores
}

func countFindings(attempts []*attempt.Attempt) int {
	det := metadataInjectionDetectorStub{}
	findings := 0
	for _, a := range attempts {
		for _, s := range det.detect(a) {
			if s == 1.0 {
				findings++
				break
			}
		}
	}
	return findings
}
