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

func newCapabilityEscalationProbe(t *testing.T, cfg registry.Config) *CapabilityEscalation {
	t.Helper()
	p, err := NewCapabilityEscalation(cfg)
	if err != nil {
		t.Fatalf("NewCapabilityEscalation: %v", err)
	}
	return p.(*CapabilityEscalation)
}

// capabilityGatingServer returns extra tools when elicitation is declared.
func capabilityGatingServer(t *testing.T) *httptest.Server {
	t.Helper()
	baseTools := toolsListResponse("read_file", "list_dir")
	elicitTools := toolsListResponse("read_file", "list_dir", "collect_user_data", "request_approval")

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
		if raw, ok := req.Params.Meta["io.modelcontextprotocol/clientCapabilities"]; ok {
			var caps map[string]any
			if json.Unmarshal(raw, &caps) == nil {
				if _, hasElicit := caps["elicitation"]; hasElicit {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(elicitTools)
					return
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(baseTools)
	}))
}

// bogusCapabilityGatingServer returns extra tools for bogus admin/debug extensions.
func bogusCapabilityGatingServer(t *testing.T) *httptest.Server {
	t.Helper()
	baseTools := toolsListResponse("read_file")
	adminTools := toolsListResponse("read_file", "admin_panel", "debug_inspect")

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
		if raw, ok := req.Params.Meta["io.modelcontextprotocol/clientCapabilities"]; ok {
			var caps map[string]json.RawMessage
			if json.Unmarshal(raw, &caps) == nil {
				if extsRaw, hasExts := caps["extensions"]; hasExts {
					var exts map[string]any
					if json.Unmarshal(extsRaw, &exts) == nil {
						if _, hasAdmin := exts["io.modelcontextprotocol/admin"]; hasAdmin {
							w.Header().Set("Content-Type", "application/json")
							_, _ = w.Write(adminTools)
							return
						}
					}
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(baseTools)
	}))
}

// jsonRPCErrorServer returns a JSON-RPC error envelope for non-baseline requests.
func jsonRPCErrorServer(t *testing.T) *httptest.Server {
	t.Helper()
	baseTools := toolsListResponse("read_file")
	errorResp := []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"unsupported capabilities"}}`)

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
		if raw, ok := req.Params.Meta["io.modelcontextprotocol/clientCapabilities"]; ok {
			var caps map[string]any
			if json.Unmarshal(raw, &caps) == nil && len(caps) > 0 {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(errorResp)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(baseTools)
	}))
}

// --- registration test ---

func TestCapabilityEscalation_Registration(t *testing.T) {
	p := newCapabilityEscalationProbe(t, registry.Config{})
	if p.Name() != "mcptransport.CapabilityEscalation" {
		t.Errorf("Name() = %q, want mcptransport.CapabilityEscalation", p.Name())
	}
	if p.GetPrimaryDetector() != "mcptransport.CapabilityEscalation" {
		t.Errorf("GetPrimaryDetector() = %q, want mcptransport.CapabilityEscalation", p.GetPrimaryDetector())
	}
}

// --- skip test ---

func TestCapabilityEscalation_SkipsWithoutEndpoint(t *testing.T) {
	p := newCapabilityEscalationProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), plainGen{})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if attempts != nil {
		t.Errorf("expected nil attempts with no endpoint, got %d", len(attempts))
	}
}

// --- safe server test ---

func TestCapabilityEscalation_UniformServer_NoDifferential(t *testing.T) {
	srv := uniformToolServer(t, "read_file", "list_dir")
	defer srv.Close()

	p := newCapabilityEscalationProbe(t, registry.Config{"endpoint": srv.URL})
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

// --- vulnerable server tests ---

func TestCapabilityEscalation_ElicitationGating_Differential(t *testing.T) {
	srv := capabilityGatingServer(t)
	defer srv.Close()

	p := newCapabilityEscalationProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	found := false
	for _, a := range attempts {
		if strings.Contains(a.Prompt, "elicitation") {
			if !metaBoolStub(a, attempt.MetadataKeyMetadataInjectionDifferential) {
				t.Errorf("elicitation variant should show a differential")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("expected an elicitation variant attempt")
	}

	for _, a := range attempts {
		if strings.Contains(a.Prompt, "all capabilities") {
			if !metaBoolStub(a, attempt.MetadataKeyMetadataInjectionDifferential) {
				t.Errorf("all-capabilities variant should show a differential (includes elicitation)")
			}
		}
	}

	if findings := countFindings(attempts); findings == 0 {
		t.Errorf("capability-gating server should produce at least 1 finding")
	}
}

func TestCapabilityEscalation_BogusCapability_Differential(t *testing.T) {
	srv := bogusCapabilityGatingServer(t)
	defer srv.Close()

	p := newCapabilityEscalationProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	found := false
	for _, a := range attempts {
		if strings.Contains(a.Prompt, "bogus") {
			if !metaBoolStub(a, attempt.MetadataKeyMetadataInjectionDifferential) {
				t.Errorf("bogus capability variant should show a differential")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("expected a bogus capability variant attempt")
	}
}

// --- refusal test ---

func TestCapabilityEscalation_JSONRPCRefusal_NonDifferential(t *testing.T) {
	srv := jsonRPCErrorServer(t)
	defer srv.Close()

	p := newCapabilityEscalationProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	if len(attempts) < 2 {
		t.Fatalf("expected at least 2 attempts, got %d", len(attempts))
	}

	for _, a := range attempts {
		if a.Status == attempt.StatusError {
			t.Errorf("JSON-RPC refusal %q should not be StatusError", a.Prompt)
		}
		if metaBoolStub(a, attempt.MetadataKeyMetadataInjectionDifferential) {
			t.Errorf("JSON-RPC refusal %q should not show differential", a.Prompt)
		}
	}
}

// --- error server test ---

func TestCapabilityEscalation_ErrorServer_OnlyBaseline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := newCapabilityEscalationProbe(t, registry.Config{"endpoint": srv.URL})
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

func TestCapabilityEscalation_ResolvesEndpointFromGenerator(t *testing.T) {
	srv := uniformToolServer(t, "tool1")
	defer srv.Close()

	p := newCapabilityEscalationProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Errorf("expected attempts when generator supplies endpoint via MCPEndpoint")
	}
}
