package mcpprobe

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConnectAnonymous_MalformedEndpointErrorOmitsCredentials: url.Parse's
// error quotes its whole input, and a password with no '@' after it is parsed
// as the port, so echoing either would leak user:password from the endpoint.
func TestConnectAnonymous_MalformedEndpointErrorOmitsCredentials(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
	}{
		{"userinfo with bad port", "http://user:s3cret@host:bad"},
		{"password parsed as port", "http://user:s3cret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess, err := ConnectAnonymous(context.Background(), stubEndpoint{endpoint: tt.endpoint, transport: "http"}, time.Second)
			assert.Nil(t, sess)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "mcpprobe: invalid endpoint (malformed URL)")
			assert.NotContains(t, err.Error(), "s3cret")
			assert.NotContains(t, err.Error(), "user:")
		})
	}
}

// TestConnectAnonymous_ErrorsOmitEndpointUserinfo: a well-formed endpoint can
// still embed a token as userinfo; neither the non-HTTP rejection nor the
// failed-connect error (including each joined transport error) may echo it.
func TestConnectAnonymous_ErrorsOmitEndpointUserinfo(t *testing.T) {
	tests := []struct {
		name      string
		endpoint  string
		transport string
		wantMsg   string
		wantHost  string
	}{
		{
			name:     "non-HTTP scheme",
			endpoint: "ws://ghp_tok:s3cret@host/",
			wantMsg:  "is not HTTP-based",
			wantHost: "ws://host/",
		},
		{
			name:     "failed connect, both transports",
			endpoint: fmt.Sprintf("http://ghp_tok:s3cret@127.0.0.1:%d/mcp", closedPort(t)),
			wantMsg:  "anonymous connect to",
			wantHost: "127.0.0.1",
		},
		{
			name:     "failed connect, bare-username token",
			endpoint: fmt.Sprintf("http://ghp_tok@127.0.0.1:%d/mcp", closedPort(t)),
			wantMsg:  "anonymous connect to",
			wantHost: "127.0.0.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess, err := ConnectAnonymous(context.Background(), stubEndpoint{endpoint: tt.endpoint, transport: tt.transport}, 2*time.Second)
			assert.Nil(t, sess)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantMsg)
			assert.Contains(t, err.Error(), tt.wantHost)
			assert.NotContains(t, err.Error(), "ghp_tok")
			assert.NotContains(t, err.Error(), "s3cret")
		})
	}
}
