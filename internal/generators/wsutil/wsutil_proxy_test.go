package wsutil

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xwebsocket "golang.org/x/net/websocket"
)

// echoHandler is a WebSocket server that replies "echo:<msg>" to one frame.
func echoHandler(ws *xwebsocket.Conn) {
	var msg string
	if xwebsocket.Message.Receive(ws, &msg) != nil {
		return
	}
	_ = xwebsocket.Message.Send(ws, "echo:"+msg)
}

func toWS(httpURL string) string { return "ws" + strings.TrimPrefix(httpURL, "http") }

// startFakeProxy launches an HTTP CONNECT proxy on a random port. When reject is
// empty it answers 200 and tunnels raw bytes to the requested target; otherwise
// it returns the given status line and closes. Returns the proxy's host:port.
func startFakeProxy(t *testing.T, reject string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveProxyConn(c, reject)
		}
	}()
	return ln.Addr().String()
}

func serveProxyConn(c net.Conn, reject string) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)

	reqLine, err := br.ReadString('\n') // "CONNECT host:port HTTP/1.1\r\n"
	if err != nil {
		return
	}
	for { // drain the rest of the header block
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	if reject != "" {
		_, _ = io.WriteString(c, "HTTP/1.1 "+reject+"\r\n\r\n")
		return
	}

	fields := strings.Fields(reqLine)
	if len(fields) < 2 {
		return
	}
	backend, err := net.Dial("tcp", fields[1])
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer func() { _ = backend.Close() }()

	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	// Bridge both directions. Reading the client side via br forwards any bytes
	// buffered past the CONNECT header block.
	go func() { _, _ = io.Copy(backend, br) }()
	_, _ = io.Copy(c, backend)
}

func TestDialViaProxy_WS(t *testing.T) {
	backend := httptest.NewServer(xwebsocket.Handler(echoHandler))
	t.Cleanup(backend.Close)

	wsCfg, err := BuildHandshakeConfig(toWS(backend.URL), "http://origin", nil, nil, false)
	require.NoError(t, err)
	proxyURL, _ := url.Parse("http://" + startFakeProxy(t, ""))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialViaProxy(ctx, wsCfg, proxyURL)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	require.NoError(t, xwebsocket.Message.Send(conn, "hi"))
	var got string
	require.NoError(t, xwebsocket.Message.Receive(conn, &got))
	assert.Equal(t, "echo:hi", got)
}

func TestDialViaProxy_WSS_TLSOverTunnel(t *testing.T) {
	backend := httptest.NewTLSServer(xwebsocket.Handler(echoHandler))
	t.Cleanup(backend.Close)

	// wss target with verification disabled (httptest uses a self-signed cert).
	wsCfg, err := BuildHandshakeConfig(toWS(backend.URL), "https://origin", nil, nil, true)
	require.NoError(t, err)
	proxyURL, _ := url.Parse("http://" + startFakeProxy(t, ""))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialViaProxy(ctx, wsCfg, proxyURL)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	require.NoError(t, xwebsocket.Message.Send(conn, "secure"))
	var got string
	require.NoError(t, xwebsocket.Message.Receive(conn, &got))
	assert.Equal(t, "echo:secure", got)
}

func TestDialViaProxy_Rejected(t *testing.T) {
	for _, status := range []string{"407 Proxy Authentication Required", "502 Bad Gateway"} {
		t.Run(status, func(t *testing.T) {
			wsCfg, err := BuildHandshakeConfig("ws://unused.example/ws", "http://origin", nil, nil, false)
			require.NoError(t, err)
			proxyURL, _ := url.Parse("http://" + startFakeProxy(t, status))

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err = DialViaProxy(ctx, wsCfg, proxyURL)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "CONNECT failed")
		})
	}
}

func TestEnvProxyFor(t *testing.T) {
	// Explicit proxy always wins.
	explicit, _ := url.Parse("http://explicit:8080")
	got, err := EnvProxyFor("wss://target/ws", explicit)
	require.NoError(t, err)
	assert.Equal(t, explicit, got)

	// wss maps to HTTPS_PROXY.
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("NO_PROXY", "")
	t.Setenv("HTTPS_PROXY", "http://burp:8080")
	got, err = EnvProxyFor("wss://target/ws", nil)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "burp:8080", got.Host)

	// ws maps to HTTP_PROXY.
	t.Setenv("HTTP_PROXY", "http://plain:8080")
	got, err = EnvProxyFor("ws://target/ws", nil)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "plain:8080", got.Host)

	// NO_PROXY yields a direct dial (nil).
	t.Setenv("NO_PROXY", "target")
	got, err = EnvProxyFor("wss://target/ws", nil)
	require.NoError(t, err)
	assert.Nil(t, got)
}
