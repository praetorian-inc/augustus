package mcptransport

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// captureSlog routes the default logger into a buffer for the rest of the test.
// Tests using it must not call t.Parallel: the default logger is process-wide.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

// assertNoUserinfo checks that out names the host but carries no part of the
// endpoint's userinfo.
func assertNoUserinfo(t *testing.T, out, host string) {
	t.Helper()
	assert.Contains(t, out, host)
	assert.NotContains(t, out, "ghp_tok")
	assert.NotContains(t, out, "s3cret")
}

// TestProbe_SkipLogsOmitEndpointUserinfo: a probe that skips a target logs the
// endpoint; a token carried as userinfo must not reach the log.
func TestProbe_SkipLogsOmitEndpointUserinfo(t *testing.T) {
	tests := []struct {
		name    string
		wantLog string
		host    string
		run     func(t *testing.T) error
	}{
		{
			name:    "UnauthenticatedAccess non-HTTP skip",
			wantLog: "UnauthenticatedAccess: skipping non-HTTP transport",
			host:    "mcp.example.test",
			run: func(t *testing.T) error {
				_, err := newUnauthProbe(t, registry.Config{}).Probe(context.Background(),
					authzGen{endpoint: "ws://ghp_tok:s3cret@mcp.example.test/", transport: "http", credHeaders: []string{"Authorization"}})
				return err
			},
		},
		{
			name:    "UnauthenticatedAccess no credential reporter skip",
			wantLog: "target cannot report whether credentials were configured",
			host:    "mcp.example.test",
			run: func(t *testing.T) error {
				_, err := newUnauthProbe(t, registry.Config{}).Probe(context.Background(),
					endpointGen{url: "http://ghp_tok:s3cret@mcp.example.test/mcp", transport: "http"})
				return err
			},
		},
		{
			name:    "OriginValidation non-HTTP skip",
			wantLog: "OriginValidation: skipping non-HTTP transport",
			host:    "mcp.example.test",
			run: func(t *testing.T) error {
				_, err := newOriginValidationProbe(t, registry.Config{}).Probe(context.Background(),
					endpointGen{url: "ws://ghp_tok:s3cret@mcp.example.test/", transport: "http"})
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := captureSlog(t)
			require.NoError(t, tt.run(t))
			out := buf.String()
			require.Contains(t, out, tt.wantLog, "the skip must have been logged")
			assertNoUserinfo(t, out, tt.host)
		})
	}
}

// TestOriginValidation_FailedRequestErrorsOmitEndpointUserinfo: against an
// unreachable endpoint every variant and the preflight record net/http's error;
// neither those attempt errors nor the log may carry the endpoint's userinfo.
func TestOriginValidation_FailedRequestErrorsOmitEndpointUserinfo(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	tests := []struct{ name, endpoint string }{
		{"user and password", fmt.Sprintf("http://ghp_tok:s3cret@127.0.0.1:%d/mcp", port)},
		{"bare-username token", fmt.Sprintf("http://ghp_tok@127.0.0.1:%d/mcp", port)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := captureSlog(t)
			attempts, err := newOriginValidationProbe(t, registry.Config{}).Probe(context.Background(),
				endpointGen{url: tt.endpoint, transport: "http"})
			require.NoError(t, err)
			require.NotEmpty(t, attempts)

			var errText bytes.Buffer
			for _, a := range attempts {
				fmt.Fprintln(&errText, a.Error)
			}
			require.Contains(t, errText.String(), "connection refused", "the requests must have failed at connect")
			assertNoUserinfo(t, errText.String()+buf.String(), "127.0.0.1")
		})
	}
}

// TestRenderSweepEvidence_OmitsEndpointUserinfo: the sweep evidence becomes the
// aggregated attempt's output, which lands in scan reports; it must name the
// host without the endpoint's userinfo.
func TestRenderSweepEvidence_OmitsEndpointUserinfo(t *testing.T) {
	for _, endpoint := range []string{
		"http://ghp_tok:s3cret@mcp.example.test/mcp",
		"http://ghp_tok@mcp.example.test/mcp",
	} {
		t.Run(endpoint, func(t *testing.T) {
			accepted := []variantResult{{class: classSweep, origin: "http://evil.test", accepted: true, result: "HTTP 200"}}
			out := renderSweepEvidence(endpoint, "http", accepted, nil, nil, corsPresent, true)
			require.Contains(t, out, "MCP Origin/Host validation sweep against")
			assertNoUserinfo(t, out, "mcp.example.test")
		})
	}
}

// TestRenderSweepEvidence_OmitsQueryToken: a token carried as a query value
// must not reach the sweep evidence either.
func TestRenderSweepEvidence_OmitsQueryToken(t *testing.T) {
	accepted := []variantResult{{class: classSweep, origin: "http://evil.test", accepted: true, result: "HTTP 200"}}
	out := renderSweepEvidence("https://mcp.example.test/mcp?access_token=s3cret", "http", accepted, nil, nil, corsPresent, true)
	require.Contains(t, out, "MCP Origin/Host validation sweep against")
	assert.Contains(t, out, "mcp.example.test")
	assert.Contains(t, out, "access_token")
	assert.NotContains(t, out, "s3cret")
}

// TestRedactSessionID_RedactsEveryQueryValue: a POST URL can carry a token in a
// parameter other than session_id; that value must go too.
func TestRedactSessionID_RedactsEveryQueryValue(t *testing.T) {
	got := redactSessionID("http://127.0.0.1:1/messages?session_id=abc&token=s3cret")
	assert.NotContains(t, got, "s3cret")
	assert.NotContains(t, got, "abc")
	u, err := url.Parse(got)
	require.NoError(t, err)
	assert.Equal(t, "<redacted>", u.Query().Get("session_id"))
	assert.Equal(t, "<redacted>", u.Query().Get("token"))
}

// TestRedactSessionID_DropsUserinfo: the POST URL inherits the base URL's
// userinfo, so the redacted form must drop it along with the session id.
func TestRedactSessionID_DropsUserinfo(t *testing.T) {
	for _, in := range []string{
		"http://ghp_tok:s3cret@127.0.0.1:1/messages?session_id=abc",
		"http://ghp_tok@127.0.0.1:1/messages?session_id=abc",
	} {
		t.Run(in, func(t *testing.T) {
			got := redactSessionID(in)
			assertNoUserinfo(t, got, "127.0.0.1:1")
			u, err := url.Parse(got)
			require.NoError(t, err)
			assert.Nil(t, u.User)
			assert.Equal(t, "<redacted>", u.Query().Get("session_id"))
			assert.NotContains(t, got, "abc")
		})
	}
}

// TestSSESession_BaselineOmitsEndpointUserinfo: against a server whose endpoint
// event is a same-host relative path, the baseline attempt's post_url output
// and endpoint metadata must not carry the configured endpoint's userinfo.
func TestSSESession_BaselineOmitsEndpointUserinfo(t *testing.T) {
	srv := newSSETestServer(t, func(int) string { return "9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d" }, func(string) bool { return false })
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	for _, userinfo := range []string{"ghp_tok:s3cret@", "ghp_tok@"} {
		t.Run(userinfo, func(t *testing.T) {
			endpoint := "http://" + userinfo + host + "/sse"
			p := newSSESessionProbe(t, registry.Config{"endpoint": endpoint})
			attempts, err := p.Probe(context.Background(), endpointGen{url: endpoint, transport: "sse"})
			require.NoError(t, err)

			var baseline *attempt.Attempt
			for _, a := range attempts {
				if class, _ := a.Metadata[attempt.MetadataKeySSESessionClass].(string); class == string(sseClassBaseline) {
					baseline = a
				}
			}
			require.NotNil(t, baseline, "the probe must have recorded a baseline handshake")
			require.Empty(t, baseline.Error)

			meta, ok := baseline.Metadata[attempt.MetadataKeySSESessionEndpoint].(string)
			require.True(t, ok, "the baseline must record the POST endpoint")
			assertNoUserinfo(t, meta, host)

			out := strings.Join(baseline.Outputs, "\n")
			require.Contains(t, out, "post_url=")
			assertNoUserinfo(t, out, host)
		})
	}
}

// TestSSESession_BaselineOmitsEndpointQueryToken: a base endpoint carrying a
// query token must not leak it into any attempt's outputs or endpoint metadata.
func TestSSESession_BaselineOmitsEndpointQueryToken(t *testing.T) {
	srv := newSSETestServer(t, func(int) string { return "9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d" }, func(string) bool { return false })
	defer srv.Close()

	endpoint := srv.URL + "/sse?access_token=s3cret"
	p := newSSESessionProbe(t, registry.Config{"endpoint": endpoint})
	attempts, err := p.Probe(context.Background(), endpointGen{url: endpoint, transport: "sse"})
	require.NoError(t, err)

	var baseline *attempt.Attempt
	for _, a := range attempts {
		if class, _ := a.Metadata[attempt.MetadataKeySSESessionClass].(string); class == string(sseClassBaseline) {
			baseline = a
		}
		assert.NotContains(t, strings.Join(a.Outputs, "\n"), "s3cret")
		if meta, ok := a.Metadata[attempt.MetadataKeySSESessionEndpoint].(string); ok {
			assert.NotContains(t, meta, "s3cret")
		}
	}
	require.NotNil(t, baseline, "the server must have accepted the tokened endpoint")
	require.Empty(t, baseline.Error)
}
