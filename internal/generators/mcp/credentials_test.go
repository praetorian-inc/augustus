package mcp

import (
	"reflect"
	"testing"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// credentialHeaders constructs a generator from cfg and returns what it reports
// as its configured credential headers. The assertion is against the interface
// the probes actually consume, so this test fails if the generator ever drifts
// out of the contract the unauthenticated-access differential depends on.
func credentialHeaders(t *testing.T, cfg registry.Config) []string {
	t.Helper()
	g := newGen(t, cfg)
	rep, ok := g.(mcpprobe.CredentialReporter)
	if !ok {
		t.Fatalf("%T does not implement mcpprobe.CredentialReporter", g)
	}
	return rep.ConfiguredCredentialHeaders()
}

// TestConfiguredCredentialHeaders_NoneConfigured: with no headers at all the
// generator must report no credentials. This is the precondition that makes an
// unauthenticated-access probe SKIP rather than fire — without it, "the
// anonymous session worked" is trivially true and worthless.
func TestConfiguredCredentialHeaders_NoneConfigured(t *testing.T) {
	got := credentialHeaders(t, registry.Config{"endpoint": "http://127.0.0.1:1/mcp"})
	if len(got) != 0 {
		t.Errorf("ConfiguredCredentialHeaders() = %v, want none", got)
	}
}

// TestConfiguredCredentialHeaders_ReportsCredentialBearingNames: a configured
// Authorization header is credential material and must be reported BY NAME.
func TestConfiguredCredentialHeaders_ReportsCredentialBearingNames(t *testing.T) {
	got := credentialHeaders(t, registry.Config{
		"endpoint": "http://127.0.0.1:1/mcp",
		"headers":  map[string]any{"Authorization": "Bearer abc123"},
	})
	if want := []string{"Authorization"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ConfiguredCredentialHeaders() = %v, want %v", got, want)
	}
}

// TestConfiguredCredentialHeaders_NeverReturnsValues: the report is a NAME set.
// Returning values would put operator secrets into attempt metadata and report
// output, so no returned element may contain the secret.
func TestConfiguredCredentialHeaders_NeverReturnsValues(t *testing.T) {
	const secret = "sup3rs3cr3t-value"
	got := credentialHeaders(t, registry.Config{
		"endpoint": "http://127.0.0.1:1/mcp",
		"headers":  map[string]any{"X-Api-Key": secret},
	})
	for _, name := range got {
		if name == secret || len(name) > 64 {
			t.Errorf("ConfiguredCredentialHeaders() leaked a value: %q", name)
		}
	}
	if want := []string{"X-Api-Key"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ConfiguredCredentialHeaders() = %v, want %v", got, want)
	}
}

// TestConfiguredCredentialHeaders_IgnoresNonCredentialHeaders: a configured
// tracing/content header is not an auth boundary. Counting it would make the
// probe treat every header-configured scan as credentialed and fire on open
// servers the operator never gave credentials for.
func TestConfiguredCredentialHeaders_IgnoresNonCredentialHeaders(t *testing.T) {
	got := credentialHeaders(t, registry.Config{
		"endpoint": "http://127.0.0.1:1/mcp",
		"headers": map[string]any{
			"X-Trace-Id":   "abc",
			"Accept":       "application/json",
			"User-Agent":   "augustus",
			"X-Request-Id": "1",
		},
	})
	if len(got) != 0 {
		t.Errorf("ConfiguredCredentialHeaders() = %v, want none (no credential-bearing names)", got)
	}
}

// TestConfiguredCredentialHeaders_UnresolvedKeyPlaceholderIsNotACredential: a
// header template of "Bearer $KEY" with NO api_key configured reaches the target
// as the literal "$KEY" — the operator intended an auth boundary but supplied no
// secret. Counting it would let a forgotten api_key turn an open server into a
// VULN verdict on a boundary that was never actually established.
func TestConfiguredCredentialHeaders_UnresolvedKeyPlaceholderIsNotACredential(t *testing.T) {
	got := credentialHeaders(t, registry.Config{
		"endpoint": "http://127.0.0.1:1/mcp",
		"headers":  map[string]any{"Authorization": "Bearer $KEY"},
	})
	if len(got) != 0 {
		t.Errorf("ConfiguredCredentialHeaders() = %v, want none ($KEY unresolved: no api_key configured)", got)
	}
}

// TestConfiguredCredentialHeaders_ResolvedKeyPlaceholderIsACredential: the same
// template WITH an api_key does establish a boundary.
func TestConfiguredCredentialHeaders_ResolvedKeyPlaceholderIsACredential(t *testing.T) {
	got := credentialHeaders(t, registry.Config{
		"endpoint": "http://127.0.0.1:1/mcp",
		"api_key":  "s3cret",
		"headers":  map[string]any{"Authorization": "Bearer $KEY"},
	})
	if want := []string{"Authorization"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ConfiguredCredentialHeaders() = %v, want %v", got, want)
	}
}

// TestConfiguredCredentialHeaders_HookVarPlaceholderCounts: a hook-supplied
// credential ("Authorization: Bearer $TOKEN") is resolved per request from hook
// vars, which are not in scope when a probe asks. Assume it will resolve —
// otherwise every hook-authenticated scan would silently skip the probe.
func TestConfiguredCredentialHeaders_HookVarPlaceholderCounts(t *testing.T) {
	got := credentialHeaders(t, registry.Config{
		"endpoint": "http://127.0.0.1:1/mcp",
		"headers":  map[string]any{"Authorization": "Bearer $TOKEN"},
	})
	if want := []string{"Authorization"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ConfiguredCredentialHeaders() = %v, want %v", got, want)
	}
}

// TestConfiguredCredentialHeaders_EmptyValueIsNotACredential: a header
// configured with an empty value establishes nothing.
func TestConfiguredCredentialHeaders_EmptyValueIsNotACredential(t *testing.T) {
	got := credentialHeaders(t, registry.Config{
		"endpoint": "http://127.0.0.1:1/mcp",
		"headers":  map[string]any{"Authorization": "   "},
	})
	if len(got) != 0 {
		t.Errorf("ConfiguredCredentialHeaders() = %v, want none (empty value)", got)
	}
}

// TestConfiguredCredentialHeaders_Sorted: the report is deterministic so
// attempt metadata and report output don't churn between runs (Go map iteration
// order is randomised).
func TestConfiguredCredentialHeaders_Sorted(t *testing.T) {
	got := credentialHeaders(t, registry.Config{
		"endpoint": "http://127.0.0.1:1/mcp",
		"headers": map[string]any{
			"X-Session-Id":  "s",
			"Authorization": "Bearer a",
			"Cookie":        "c=1",
		},
	})
	want := []string{"Authorization", "Cookie", "X-Session-Id"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ConfiguredCredentialHeaders() = %v, want %v (sorted)", got, want)
	}
}

// TestCredentialHeaderName_ConventionalNames documents the conventional
// credential-header vocabulary directly. The set is deliberately generic — a
// name any pentester would recognise as carrying caller credentials — and
// contains nothing specific to a particular server or product.
func TestCredentialHeaderName_ConventionalNames(t *testing.T) {
	credential := []string{
		"Authorization", "authorization", "Proxy-Authorization", "Cookie",
		"X-Api-Key", "X-API-KEY", "Api-Key", "X-Auth-Token", "X-Session-Id",
		"X-Access-Token", "X-Secret", "X-Credential", "X-Password", "X-JWT",
		"X-Subscription-Key",
	}
	for _, name := range credential {
		if !isCredentialHeaderName(name) {
			t.Errorf("isCredentialHeaderName(%q) = false, want true", name)
		}
	}
	notCredential := []string{
		"Accept", "Content-Type", "User-Agent", "X-Trace-Id", "X-Request-Id",
		"Origin", "Referer", "X-Forwarded-For", "Accept-Encoding", "X-Tenant",
	}
	for _, name := range notCredential {
		if isCredentialHeaderName(name) {
			t.Errorf("isCredentialHeaderName(%q) = true, want false", name)
		}
	}
}
