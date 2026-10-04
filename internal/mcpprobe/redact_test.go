package mcpprobe

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactEndpoint(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"user and password", "http://ghp_tok:s3cret@host:8080/mcp", "http://host:8080/mcp"},
		// A bare username is often a token; url.URL.Redacted would keep it.
		{"bare-username token", "https://ghp_tok@host/mcp", "https://host/mcp"},
		{"no userinfo is unchanged", "http://host:8080/mcp", "http://host:8080/mcp"},
		{"query string preserved", "http://ghp_tok:s3cret@host/mcp?session=1&x=y", "http://host/mcp?session=1&x=y"},
		{"non-HTTP scheme", "ws://ghp_tok:s3cret@host/", "ws://host/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactEndpoint(tt.in)
			assert.Equal(t, tt.want, got)
			assert.NotContains(t, got, "ghp_tok")
			assert.NotContains(t, got, "s3cret")
		})
	}
}

// TestRedactEndpoint_MalformedEchoesNothing: url.Parse's error quotes its whole
// input, so a malformed endpoint must map to a fixed string.
func TestRedactEndpoint_MalformedEchoesNothing(t *testing.T) {
	for _, in := range []string{"http://ghp_tok:s3cret@host:bad", "http://ghp_tok:s3cret"} {
		t.Run(in, func(t *testing.T) {
			assert.Equal(t, "(malformed URL)", RedactEndpoint(in))
		})
	}
}

// closedPort returns a loopback port with nothing listening on it.
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

// realURLError performs a GET that fails to connect, returning net/http's own
// *url.Error for rawURL.
func realURLError(t *testing.T, rawURL string) error {
	t.Helper()
	resp, err := (&http.Client{}).Get(rawURL)
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err)
	var ue *url.Error
	require.ErrorAs(t, err, &ue)
	return err
}

func TestRedactURLError_PassThrough(t *testing.T) {
	assert.NoError(t, RedactURLError(nil))

	plain := errors.New("plain failure ghp_tok")
	assert.Same(t, plain, RedactURLError(plain), "an error with no *url.Error must be returned unchanged")
}

func TestRedactURLError_RemovesUserinfo(t *testing.T) {
	port := closedPort(t)
	sentinel := errors.New("sentinel")

	tests := []struct {
		name string
		err  func(t *testing.T) error
	}{
		{"http.Client user:password", func(t *testing.T) error {
			return realURLError(t, fmt.Sprintf("http://ghp_tok:pw@127.0.0.1:%d/x", port))
		}},
		{"http.Client bare-username token", func(t *testing.T) error {
			return realURLError(t, fmt.Sprintf("http://ghp_tok@127.0.0.1:%d/x", port))
		}},
		{"wrapped http.Client error", func(t *testing.T) error {
			return fmt.Errorf("outer: %w", realURLError(t, fmt.Sprintf("http://ghp_tok:pw@127.0.0.1:%d/x", port)))
		}},
		// A *url.Error carrying the raw URL, wrapped by a layer that formats
		// net/http's stripPassword form ("user:***@") of the same URL.
		{"raw URL with stripPassword form in the message", func(t *testing.T) error {
			ue := &url.Error{Op: "Post", URL: "http://ghp_tok:pw@127.0.0.1/x", Err: sentinel}
			return fmt.Errorf("POST http://ghp_tok:***@127.0.0.1/x: %w", ue)
		}},
		// url.URL.Redacted's form ("user:xxxxx@") of the same URL.
		{"raw URL with Redacted form in the message", func(t *testing.T) error {
			ue := &url.Error{Op: "Post", URL: "http://ghp_tok:pw@127.0.0.1/x", Err: sentinel}
			return fmt.Errorf("POST http://ghp_tok:xxxxx@127.0.0.1/x: %w", ue)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := tt.err(t)
			got := RedactURLError(orig)
			require.Error(t, got)
			msg := got.Error()
			assert.NotContains(t, msg, "ghp_tok")
			assert.NotContains(t, msg, "pw@")
			assert.NotContains(t, msg, ":pw")
			assert.Contains(t, msg, "127.0.0.1")

			var ue *url.Error
			require.ErrorAs(t, got, &ue, "the *url.Error must stay reachable")
			assert.ErrorIs(t, got, orig)
		})
	}
}

// TestRedactURLError_PreservesWrappedSentinel: errors.Is must see a sentinel
// inside the *url.Error after redaction.
func TestRedactURLError_PreservesWrappedSentinel(t *testing.T) {
	sentinel := errors.New("sentinel")
	ue := &url.Error{Op: "Get", URL: "http://ghp_tok@127.0.0.1/x", Err: sentinel}

	got := RedactURLError(fmt.Errorf("wrap: %w", ue))

	assert.ErrorIs(t, got, sentinel)
	var gotUE *url.Error
	require.ErrorAs(t, got, &gotUE)
	assert.Same(t, ue, gotUE)
	assert.NotContains(t, got.Error(), "ghp_tok")
	assert.Contains(t, got.Error(), "sentinel")
}
