package mcptransport

import (
	"context"
	"encoding/json"
	"fmt"
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

// paginatedToolsListResponse builds a JSON-RPC response with a nextCursor.
func paginatedToolsListResponse(tools ...string) []byte {
	type tool struct {
		Name string `json:"name"`
	}
	type result struct {
		Tools      []tool `json:"tools"`
		NextCursor string `json:"nextCursor"`
	}
	ts := make([]tool, len(tools))
	for i, name := range tools {
		ts[i] = tool{Name: name}
	}
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result":  result{Tools: ts, NextCursor: "page2"},
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

// sseUniformToolServer returns the same tools as an SSE-framed response.
func sseUniformToolServer(t *testing.T, tools ...string) *httptest.Server {
	t.Helper()
	body := toolsListResponse(tools...)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(body))
	}))
}

// refusingVariantServer returns tools for the baseline, HTTP 403 for variants
// that contain a spoofed client identity.
func refusingVariantServer(t *testing.T) *httptest.Server {
	t.Helper()
	baseTools := toolsListResponse("read_file", "list_dir")
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
			if json.Unmarshal(raw, &ci) == nil && ci.Name != "augustus-scan" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(baseTools)
	}))
}

// paginatedToolServer returns a paginated response with nextCursor.
func paginatedToolServer(t *testing.T) *httptest.Server {
	t.Helper()
	body := paginatedToolsListResponse("read_file", "list_dir")
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

	if len(attempts) < 2 {
		t.Fatalf("expected at least 2 attempts (baseline + variants), got %d", len(attempts))
	}

	for _, a := range attempts {
		class, _ := a.GetMetadata(attempt.MetadataKeyMetadataInjectionClass)
		classStr, _ := class.(string)
		if classStr == "baseline" {
			continue
		}
		if metaBoolStub(a, attempt.MetadataKeyMetadataInjectionDifferential) {
			t.Errorf("variant %q unexpectedly shows a differential on a uniform server", a.Prompt)
		}
	}

	if findings := countFindings(attempts); findings != 0 {
		t.Errorf("uniform server should produce 0 findings, got %d", findings)
	}
}

// --- SSE server test ---

func TestMetadataInjection_SSEServer_NoDifferential(t *testing.T) {
	srv := sseUniformToolServer(t, "read_file", "list_dir")
	defer srv.Close()

	p := newMetadataInjectionProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	if len(attempts) < 2 {
		t.Fatalf("expected at least 2 attempts (baseline + variants), got %d", len(attempts))
	}

	for _, a := range attempts {
		if a.Status == attempt.StatusError {
			t.Errorf("attempt %q should not error on SSE-framed response", a.Prompt)
		}
	}
}

// --- paginated server test ---

func TestMetadataInjection_PaginatedServer_BaselineErrors(t *testing.T) {
	srv := paginatedToolServer(t)
	defer srv.Close()

	p := newMetadataInjectionProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	if len(attempts) != 1 {
		t.Fatalf("expected 1 attempt (failed baseline), got %d", len(attempts))
	}
	if attempts[0].Status != attempt.StatusError {
		t.Errorf("paginated baseline should be errored, got status %q", attempts[0].Status)
	}
}

// --- refusal test ---

func TestMetadataInjection_RefusingServer_NonDifferential(t *testing.T) {
	srv := refusingVariantServer(t)
	defer srv.Close()

	p := newMetadataInjectionProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	if len(attempts) < 2 {
		t.Fatalf("expected at least 2 attempts, got %d", len(attempts))
	}

	for _, a := range attempts {
		if a.Status == attempt.StatusError {
			t.Errorf("refused variant %q should not be StatusError", a.Prompt)
		}
		if metaBoolStub(a, attempt.MetadataKeyMetadataInjectionDifferential) {
			t.Errorf("refused variant %q should not show differential", a.Prompt)
		}
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

	found := false
	for _, a := range attempts {
		if strings.Contains(a.Prompt, "claude-desktop") {
			if !metaBoolStub(a, attempt.MetadataKeyMetadataInjectionDifferential) {
				t.Errorf("claude-desktop variant should show a differential")
			}
			found = true
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

	found := false
	for _, a := range attempts {
		class, _ := a.GetMetadata(attempt.MetadataKeyMetadataInjectionClass)
		classStr, _ := class.(string)
		if classStr == "protocol-version-downgrade" {
			if !metaBoolStub(a, attempt.MetadataKeyMetadataInjectionDifferential) {
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

// --- MCP protocol headers test ---

func TestMetadataInjection_SendsMCPHeaders(t *testing.T) {
	var capturedHeaders http.Header
	var once bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !once {
			capturedHeaders = r.Header.Clone()
			once = true
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(toolsListResponse("tool1"))
	}))
	defer srv.Close()

	p := newMetadataInjectionProbe(t, registry.Config{"endpoint": srv.URL})
	_, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	if v := capturedHeaders.Get("mcp-protocol-version"); v != "2026-07-28" {
		t.Errorf("mcp-protocol-version = %q, want 2026-07-28", v)
	}
	if v := capturedHeaders.Get("mcp-method"); v != "tools/list" {
		t.Errorf("mcp-method = %q, want tools/list", v)
	}
}

// --- detector scoring helpers ---

// countFindings uses the real detector scoring logic to count findings.
func countFindings(attempts []*attempt.Attempt) int {
	findings := 0
	for _, a := range attempts {
		scores, _ := detectMetadataDifferential(a)
		for _, s := range scores {
			if s == 1.0 {
				findings++
				break
			}
		}
	}
	return findings
}

// detectMetadataDifferential is imported from the detector package
// indirectly: since probe tests are in the same process, we call the
// shared scoring logic directly. This function is defined in
// internal/detectors/mcptransport/metadatainjection.go but since we
// can't import that package (cyclic), we reimplement the identical logic.
// The detector tests in internal/detectors/mcptransport/ validate the
// real function directly.
func detectMetadataDifferential(a *attempt.Attempt) ([]float64, error) {
	class, _ := stringMetaStub(a, attempt.MetadataKeyMetadataInjectionClass)
	differential := metaBoolStub(a, attempt.MetadataKeyMetadataInjectionDifferential)

	scores := make([]float64, len(a.Outputs))

	if a.Status == attempt.StatusError {
		score := 0.5
		if len(scores) == 0 {
			return []float64{score}, nil
		}
		for i := range scores {
			scores[i] = score
		}
		return scores, nil
	}

	if class == "baseline" {
		return scores, nil
	}

	var score float64
	switch {
	case differential:
		score = 1.0
	default:
		return scores, nil
	}

	if len(scores) == 0 {
		return []float64{score}, nil
	}
	for i := range scores {
		scores[i] = score
	}
	return scores, nil
}

func stringMetaStub(a *attempt.Attempt, key string) (string, bool) {
	raw, ok := a.GetMetadata(key)
	if !ok {
		return "", false
	}
	s, ok := raw.(string)
	return s, ok
}
