package mcpprobe

import (
	"context"
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
