package mcptransport

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// credentialURLs are endpoint values that url.Parse rejects while the raw
// string carries userinfo. Both forms leak through url.Parse's own error: the
// *url.Error quotes the whole input, and a password with no '@' after it is
// parsed as the port, so the inner error quotes the password as well
// (`invalid port ":s3cret"`).
var credentialURLs = []struct {
	name string
	url  string
}{
	{"userinfo with bad port", "http://user:s3cret@host:bad"},
	{"password parsed as port", "http://user:s3cret"},
}

// assertRedactedParseError checks that err is the fixed malformed-URL error and
// carries no part of the credential.
func assertRedactedParseError(t *testing.T, err error, wantMsg string) {
	t.Helper()
	require.Error(t, err)
	assert.Contains(t, err.Error(), wantMsg)
	assert.NotContains(t, err.Error(), "s3cret")
	assert.NotContains(t, err.Error(), "user:")
}

// TestProbe_MalformedEndpointErrorOmitsCredentials: each probe that parses the
// target endpoint must reject a malformed URL without echoing it, because the
// endpoint can embed user:password.
func TestProbe_MalformedEndpointErrorOmitsCredentials(t *testing.T) {
	probes := []struct {
		name    string
		wantMsg string
		probe   func(t *testing.T, endpoint string) error
	}{
		{
			name:    "SSESessionHijack",
			wantMsg: "mcptransport.SSESessionHijack: invalid endpoint (malformed URL)",
			probe: func(t *testing.T, endpoint string) error {
				p := newSSESessionProbe(t, registry.Config{})
				_, err := p.Probe(context.Background(), endpointGen{url: endpoint, transport: "sse"})
				return err
			},
		},
		{
			name:    "UnauthenticatedAccess",
			wantMsg: "mcptransport.UnauthenticatedAccess: invalid endpoint (malformed URL)",
			probe: func(t *testing.T, endpoint string) error {
				p := newUnauthProbe(t, registry.Config{})
				_, err := p.Probe(context.Background(), authzGen{endpoint: endpoint, transport: "http"})
				return err
			},
		},
		{
			name:    "OriginValidation",
			wantMsg: "mcptransport.OriginValidation: invalid endpoint (malformed URL)",
			probe: func(t *testing.T, endpoint string) error {
				p := newOriginValidationProbe(t, registry.Config{})
				_, err := p.Probe(context.Background(), endpointGen{url: endpoint, transport: "http"})
				return err
			},
		},
	}
	// The generator stubs must expose the endpoint the way production
	// generators do, or Probe returns before reaching the parse.
	var _ types.MCPEndpoint = endpointGen{}
	var _ types.MCPEndpoint = authzGen{}

	for _, pr := range probes {
		for _, in := range credentialURLs {
			t.Run(pr.name+"/"+in.name, func(t *testing.T) {
				assertRedactedParseError(t, pr.probe(t, in.url), pr.wantMsg)
			})
		}
	}
}

// TestResolvePostURL_MalformedInputErrorOmitsCredentials: the SSE POST URL is
// built from the configured base and the server-supplied endpoint path; a parse
// failure on either must not echo the value.
func TestResolvePostURL_MalformedInputErrorOmitsCredentials(t *testing.T) {
	const validBase = "http://127.0.0.1:9003/sse"
	tests := []struct {
		name         string
		base         string
		endpointPath string
		wantMsg      string
	}{
		{"base: userinfo with bad port", "http://user:s3cret@host:bad", "/messages/", "invalid base URL (malformed URL)"},
		{"base: password parsed as port", "http://user:s3cret", "/messages/", "invalid base URL (malformed URL)"},
		{"path: password parsed as port", validBase, "http://user:s3cret", "invalid endpoint path (malformed URL)"},
		{"path: invalid escape before secret", validBase, "/messages/%zz?session_id=user:s3cret", "invalid endpoint path (malformed URL)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolvePostURL(tt.base, tt.endpointPath)
			assert.Empty(t, got)
			assertRedactedParseError(t, err, tt.wantMsg)
		})
	}
}
