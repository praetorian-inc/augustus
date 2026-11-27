package mcptransport

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	detmcptransport "github.com/praetorian-inc/augustus/internal/detectors/mcptransport"
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

	if findings := countReviewFindings(attempts); findings == 0 {
		t.Errorf("version-gating server should produce at least 1 review-level finding")
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

// --- refused baseline test ---

func TestMetadataInjection_RefusedBaseline_IsInconclusive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	p := newMetadataInjectionProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	if len(attempts) != 1 {
		t.Fatalf("expected 1 attempt (refused baseline), got %d", len(attempts))
	}
	a := attempts[0]
	if a.Status != attempt.StatusComplete {
		t.Errorf("refused baseline should be StatusComplete (inconclusive), got %q", a.Status)
	}
	if inc, ok := a.Metadata[attempt.MetadataKeyInconclusive].(bool); !ok || !inc {
		t.Errorf("refused baseline should be marked inconclusive")
	}
	if _, ok := a.Metadata[attempt.MetadataKeyInconclusiveReason].(string); !ok {
		t.Errorf("refused baseline should have an inconclusive reason")
	}
}

// --- large SSE response test ---

func TestMetadataInjection_LargeSSEResponse(t *testing.T) {
	largeSchema := strings.Repeat("x", 100*1024) // 100 KiB > default 64 KiB scanner limit
	body := toolsListResponse("read_file", "list_dir")
	// Inject a large inputSchema to bloat the JSON past 64 KiB.
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	result := envelope["result"].(map[string]any)
	tools := result["tools"].([]any)
	tools[0].(map[string]any)["inputSchema"] = map[string]string{"description": largeSchema}
	bigBody, _ := json.Marshal(envelope)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(bigBody))
	}))
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
			t.Errorf("large SSE attempt %q should not error (scanner buffer should handle >64 KiB)", a.Prompt)
		}
	}
}

// --- legacy SSE transport skip test ---

func TestMetadataInjection_SkipsLegacySSETransport(t *testing.T) {
	srv := uniformToolServer(t, "read_file")
	defer srv.Close()

	p := newMetadataInjectionProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "sse"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if attempts != nil {
		t.Errorf("expected nil attempts for legacy SSE transport, got %d", len(attempts))
	}
}

// headerMismatchServer returns extra tools when mcp-method header is resources/list.
func headerMismatchServer(t *testing.T) *httptest.Server {
	t.Helper()
	baseTools := toolsListResponse("read_file", "list_dir")
	routedTools := toolsListResponse("read_file", "list_dir", "resources_read", "resources_list")
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("mcp-method") == "resources/list" {
			_, _ = w.Write(routedTools)
			return
		}
		_, _ = w.Write(baseTools)
	}))
}

// --- header-mismatch server test ---

func TestMetadataInjection_HeaderMismatch_Differential(t *testing.T) {
	srv := headerMismatchServer(t)
	defer srv.Close()

	p := newMetadataInjectionProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	found := false
	for _, a := range attempts {
		if strings.Contains(a.Prompt, "mcp-method: resources/list") {
			if !metaBoolStub(a, attempt.MetadataKeyMetadataInjectionDifferential) {
				t.Errorf("header-mismatch mcp-method variant should show a differential")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("expected a header-mismatch mcp-method variant attempt")
	}

	if findings := countFindings(attempts); findings == 0 {
		t.Errorf("header-mismatch server should produce at least 1 finding")
	}
}

// --- rate-limited variant test ---

func TestMetadataInjection_RateLimitedVariant_Inconclusive(t *testing.T) {
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		// First request = baseline, last request = stability-check baseline
		// Everything in between gets rate limited
		if requestCount <= 1 || requestCount >= 9 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(toolsListResponse("read_file", "list_dir"))
			return
		}
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	p := newMetadataInjectionProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	for _, a := range attempts {
		class, _ := a.GetMetadata(attempt.MetadataKeyMetadataInjectionClass)
		classStr, _ := class.(string)
		if classStr == "baseline" {
			continue
		}
		if a.Status == attempt.StatusError {
			t.Errorf("rate-limited variant %q should NOT be StatusError", a.Prompt)
		}
	}
}

// --- unstable catalog test ---

func TestMetadataInjection_UnstableCatalog_Inconclusive(t *testing.T) {
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		if requestCount == 1 {
			_, _ = w.Write(toolsListResponse("read_file", "list_dir"))
		} else {
			_, _ = w.Write(toolsListResponse("read_file", "list_dir", "new_tool"))
		}
	}))
	defer srv.Close()

	p := newMetadataInjectionProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	// All variants should be inconclusive because catalog is unstable
	for _, a := range attempts {
		class, _ := a.GetMetadata(attempt.MetadataKeyMetadataInjectionClass)
		classStr, _ := class.(string)
		if classStr == "baseline" {
			continue
		}
		if !metaBoolStub(a, attempt.MetadataKeyInconclusive) {
			t.Errorf("variant %q should be marked inconclusive when catalog is unstable", a.Prompt)
		}
	}

	if findings := countFindings(attempts); findings != 0 {
		t.Errorf("unstable catalog should produce 0 findings, got %d", findings)
	}
}

// --- multi-event SSE test ---

func TestMetadataInjection_MultiEventSSE(t *testing.T) {
	body := toolsListResponse("read_file", "list_dir")
	notification := `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"abc","progress":50}}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", notification)
		_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(body))
	}))
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
			t.Errorf("multi-event SSE attempt %q should not error", a.Prompt)
		}
	}
}

// --- detector scoring helpers ---

func countFindings(attempts []*attempt.Attempt) int {
	det, _ := detmcptransport.NewMetadataInjectionDetector(registry.Config{})
	findings := 0
	for _, a := range attempts {
		scores, _ := det.Detect(context.Background(), a)
		for _, s := range scores {
			if s == 1.0 {
				findings++
				break
			}
		}
	}
	return findings
}

func countReviewFindings(attempts []*attempt.Attempt) int {
	det, _ := detmcptransport.NewMetadataInjectionDetector(registry.Config{})
	findings := 0
	for _, a := range attempts {
		scores, _ := det.Detect(context.Background(), a)
		for _, s := range scores {
			if s >= 0.5 {
				findings++
				break
			}
		}
	}
	return findings
}
