package mcp

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// closedLoopbackPort returns a loopback port with nothing listening on it.
func closedLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

// TestGenerate_ConnectFailureOmitsEndpointUserinfo: an endpoint can carry a
// token as userinfo; the connect-failure error names the target and wraps
// net/http's error, and neither may echo the token.
func TestGenerate_ConnectFailureOmitsEndpointUserinfo(t *testing.T) {
	port := closedLoopbackPort(t)
	tests := []struct {
		name      string
		transport string
		endpoint  string
	}{
		{"http, user and password", "http", fmt.Sprintf("http://ghp_tok:s3cret@127.0.0.1:%d/mcp", port)},
		{"http, bare-username token", "http", fmt.Sprintf("http://ghp_tok@127.0.0.1:%d/mcp", port)},
		{"sse, user and password", "sse", fmt.Sprintf("http://ghp_tok:s3cret@127.0.0.1:%d/sse", port)},
		{"auto, user and password", "auto", fmt.Sprintf("http://ghp_tok:s3cret@127.0.0.1:%d/mcp", port)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newGen(t, registry.Config{
				"transport": tt.transport, "endpoint": tt.endpoint, "tool_name": "echo", "arg_name": "query",
				"request_timeout": 2,
			})
			conv := attempt.NewConversation()
			conv.AddPrompt("hi")

			_, err := g.Generate(context.Background(), conv, 1)

			require.Error(t, err)
			msg := err.Error()
			assert.Contains(t, msg, fmt.Sprintf("127.0.0.1:%d", port))
			assert.Contains(t, msg, "connection refused")
			assert.NotContains(t, msg, "ghp_tok")
			assert.NotContains(t, msg, "s3cret")
		})
	}
}

// TestHTTPClient_InsecureSkipVerifyWarningOmitsEndpointUserinfo: the
// insecure_skip_verify warning logs the endpoint; its userinfo must not reach
// the log. Not parallel: it swaps the process-wide default logger.
func TestHTTPClient_InsecureSkipVerifyWarningOmitsEndpointUserinfo(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	g := newGen(t, registry.Config{
		"transport": "http", "endpoint": "https://ghp_tok:s3cret@mcp.example.test/mcp",
		"tool_name": "echo", "arg_name": "query", "insecure_skip_verify": true,
	})
	_ = g.(*MCP).httpClient()

	out := buf.String()
	require.Contains(t, out, "TLS certificate verification disabled")
	assert.Contains(t, out, "mcp.example.test")
	assert.NotContains(t, out, "ghp_tok")
	assert.NotContains(t, out, "s3cret")
}
