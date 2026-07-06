package websocket

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xwebsocket "golang.org/x/net/websocket"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// wsURL rewrites an httptest http(s) URL to its ws(s) equivalent.
func wsURL(httpURL string) string {
	return "ws" + strings.TrimPrefix(httpURL, "http")
}

// newServer starts an httptest WebSocket server driven by handler.
func newServer(t *testing.T, handler xwebsocket.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func convWith(prompt string) *attempt.Conversation {
	conv := attempt.NewConversation()
	conv.AddPrompt(prompt)
	return conv
}

func newGen(t *testing.T, cfg registry.Config) *Websocket {
	t.Helper()
	g, err := NewWebsocket(cfg)
	require.NoError(t, err)
	return g.(*Websocket)
}

func TestNameAndDescription(t *testing.T) {
	g := newGen(t, registry.Config{"uri": "ws://x/ws"})
	assert.Equal(t, "websocket.Websocket", g.Name())
	assert.NotEmpty(t, g.Description())
}

func TestNew_RejectsNonWSScheme(t *testing.T) {
	_, err := NewWebsocket(registry.Config{"uri": "http://example.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scheme")
}

func TestGenerate_SingleEcho(t *testing.T) {
	srv := newServer(t, func(ws *xwebsocket.Conn) {
		var msg string
		if err := xwebsocket.Message.Receive(ws, &msg); err != nil {
			return
		}
		_ = xwebsocket.Message.Send(ws, "echo:"+msg)
	})

	g := newGen(t, registry.Config{"uri": wsURL(srv.URL)})
	resp, err := g.Generate(context.Background(), convWith("hello"), 1)
	require.NoError(t, err)
	require.Len(t, resp, 1)
	assert.Equal(t, "echo:hello", resp[0].Content)
	assert.Equal(t, attempt.RoleAssistant, resp[0].Role)
}

func TestGenerate_MultipleCompletions(t *testing.T) {
	srv := newServer(t, func(ws *xwebsocket.Conn) {
		var msg string
		if err := xwebsocket.Message.Receive(ws, &msg); err != nil {
			return
		}
		_ = xwebsocket.Message.Send(ws, "ok")
	})

	g := newGen(t, registry.Config{"uri": wsURL(srv.URL)})
	resp, err := g.Generate(context.Background(), convWith("hi"), 3)
	require.NoError(t, err)
	require.Len(t, resp, 3)
	for _, r := range resp {
		assert.Equal(t, "ok", r.Content)
	}
}

func TestGenerate_JSONFieldExtraction(t *testing.T) {
	srv := newServer(t, func(ws *xwebsocket.Conn) {
		var msg string
		_ = xwebsocket.Message.Receive(ws, &msg)
		_ = xwebsocket.Message.Send(ws, `{"data":{"text":"extracted"}}`)
	})

	g := newGen(t, registry.Config{
		"uri":           wsURL(srv.URL),
		"response_json": true,
		"response_path": "$.data.text",
	})
	resp, err := g.Generate(context.Background(), convWith("hi"), 1)
	require.NoError(t, err)
	assert.Equal(t, "extracted", resp[0].Content)
}

func TestGenerate_UntilClose(t *testing.T) {
	srv := newServer(t, func(ws *xwebsocket.Conn) {
		var msg string
		_ = xwebsocket.Message.Receive(ws, &msg)
		for _, chunk := range []string{"a", "b", "c"} {
			_ = xwebsocket.Message.Send(ws, chunk)
		}
		// returning closes the connection, terminating the stream
	})

	g := newGen(t, registry.Config{"uri": wsURL(srv.URL), "read_mode": ReadModeUntilClose})
	resp, err := g.Generate(context.Background(), convWith("hi"), 1)
	require.NoError(t, err)
	assert.Equal(t, "abc", resp[0].Content)
}

func TestGenerate_UntilMarker_DoneMarker(t *testing.T) {
	srv := newServer(t, func(ws *xwebsocket.Conn) {
		var msg string
		_ = xwebsocket.Message.Receive(ws, &msg)
		for _, chunk := range []string{"one ", "two ", "three", "[DONE]"} {
			_ = xwebsocket.Message.Send(ws, chunk)
		}
		// Hold the connection open briefly so the client must rely on the
		// marker (not connection close) to stop reading.
		time.Sleep(50 * time.Millisecond)
	})

	g := newGen(t, registry.Config{
		"uri":         wsURL(srv.URL),
		"read_mode":   ReadModeUntilMarker,
		"done_marker": "[DONE]",
	})
	resp, err := g.Generate(context.Background(), convWith("hi"), 1)
	require.NoError(t, err)
	assert.Equal(t, "one two three", resp[0].Content)
}

func TestGenerate_UntilMarker_DoneField(t *testing.T) {
	srv := newServer(t, func(ws *xwebsocket.Conn) {
		var msg string
		_ = xwebsocket.Message.Receive(ws, &msg)
		_ = xwebsocket.Message.Send(ws, `{"type":"chunk","text":"part1"}`)
		_ = xwebsocket.Message.Send(ws, `{"type":"chunk","text":"part2"}`)
		_ = xwebsocket.Message.Send(ws, `{"type":"end"}`)
		time.Sleep(50 * time.Millisecond)
	})

	g := newGen(t, registry.Config{
		"uri":           wsURL(srv.URL),
		"read_mode":     ReadModeUntilMarker,
		"done_field":    "type",
		"done_value":    "end",
		"response_json": true,
		"response_path": "text",
	})
	resp, err := g.Generate(context.Background(), convWith("hi"), 1)
	require.NoError(t, err)
	assert.Equal(t, "part1part2", resp[0].Content)
}

func TestGenerate_TemplateSubstitution(t *testing.T) {
	var received string
	srv := newServer(t, func(ws *xwebsocket.Conn) {
		_ = xwebsocket.Message.Receive(ws, &received)
		_ = xwebsocket.Message.Send(ws, "ok")
	})

	g := newGen(t, registry.Config{
		"uri":          wsURL(srv.URL),
		"req_template": `{"key":"$KEY","msg":"$INPUT_JSON"}`,
		"api_key":      "secret",
	})
	_, err := g.Generate(context.Background(), convWith(`he said "hi"`), 1)
	require.NoError(t, err)
	assert.JSONEq(t, `{"key":"secret","msg":"he said \"hi\""}`, received)
}

func TestGenerate_RawInputNotEscaped(t *testing.T) {
	var received string
	srv := newServer(t, func(ws *xwebsocket.Conn) {
		_ = xwebsocket.Message.Receive(ws, &received)
		_ = xwebsocket.Message.Send(ws, "ok")
	})

	g := newGen(t, registry.Config{"uri": wsURL(srv.URL)}) // default template "$INPUT"
	_, err := g.Generate(context.Background(), convWith("line1\nline2"), 1)
	require.NoError(t, err)
	assert.Equal(t, "line1\nline2", received) // raw, not JSON-escaped
}

func TestGenerate_HookVarSubstitution(t *testing.T) {
	var received string
	srv := newServer(t, func(ws *xwebsocket.Conn) {
		_ = xwebsocket.Message.Receive(ws, &received)
		_ = xwebsocket.Message.Send(ws, "ok")
	})

	g := newGen(t, registry.Config{"uri": wsURL(srv.URL), "req_template": "tok=$TOKEN"})
	ctx := types.WithHookVars(context.Background(), map[string]string{"TOKEN": "abc123"})
	_, err := g.Generate(ctx, convWith("ignored"), 1)
	require.NoError(t, err)
	assert.Equal(t, "tok=abc123", received)
}

func TestGenerate_HeadersSentInHandshake(t *testing.T) {
	var gotAuth string
	srv := newServer(t, func(ws *xwebsocket.Conn) {
		gotAuth = ws.Request().Header.Get("Authorization")
		var msg string
		_ = xwebsocket.Message.Receive(ws, &msg)
		_ = xwebsocket.Message.Send(ws, "ok")
	})

	g := newGen(t, registry.Config{
		"uri":     wsURL(srv.URL),
		"headers": map[string]any{"Authorization": "Bearer xyz"},
	})
	_, err := g.Generate(context.Background(), convWith("hi"), 1)
	require.NoError(t, err)
	assert.Equal(t, "Bearer xyz", gotAuth)
}

func TestGenerate_MessagesTemplate(t *testing.T) {
	var received string
	srv := newServer(t, func(ws *xwebsocket.Conn) {
		_ = xwebsocket.Message.Receive(ws, &received)
		_ = xwebsocket.Message.Send(ws, "ok")
	})

	g := newGen(t, registry.Config{"uri": wsURL(srv.URL), "req_template": `{"messages":$MESSAGES}`})
	_, err := g.Generate(context.Background(), convWith("hello"), 1)
	require.NoError(t, err)
	assert.JSONEq(t, `{"messages":[{"role":"user","content":"hello"}]}`, received)
}

func TestPersistent_ReusesConnection(t *testing.T) {
	var conns int32
	srv := newServer(t, func(ws *xwebsocket.Conn) {
		atomic.AddInt32(&conns, 1)
		for {
			var msg string
			if err := xwebsocket.Message.Receive(ws, &msg); err != nil {
				return
			}
			_ = xwebsocket.Message.Send(ws, "echo:"+msg)
		}
	})

	g := newGen(t, registry.Config{"uri": wsURL(srv.URL), "persistent": true})
	for i := 0; i < 3; i++ {
		resp, err := g.Generate(context.Background(), convWith("hi"), 1)
		require.NoError(t, err)
		assert.Equal(t, "echo:hi", resp[0].Content)
	}
	assert.Equal(t, int32(1), atomic.LoadInt32(&conns), "persistent should reuse one connection")

	g.ClearHistory()
	resp, err := g.Generate(context.Background(), convWith("hi"), 1)
	require.NoError(t, err)
	assert.Equal(t, "echo:hi", resp[0].Content)
	assert.Equal(t, int32(2), atomic.LoadInt32(&conns), "ClearHistory should force a redial")
}

// TestPersistent_ConcurrentGenerateNoCrosstalk fires many Generate calls at one
// persistent generator at once. The scanner shares a single generator instance
// across concurrent probe goroutines; the shared WS connection must be
// serialized, otherwise concurrent Send/Receive interleaves frames and a call
// receives another call's echo (and -race fires). Each call must get its own.
func TestPersistent_ConcurrentGenerateNoCrosstalk(t *testing.T) {
	srv := newServer(t, func(ws *xwebsocket.Conn) {
		for {
			var msg string
			if err := xwebsocket.Message.Receive(ws, &msg); err != nil {
				return
			}
			_ = xwebsocket.Message.Send(ws, "echo:"+msg)
		}
	})

	g := newGen(t, registry.Config{"uri": wsURL(srv.URL), "persistent": true})

	const n = 16
	var wg sync.WaitGroup
	got := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			in := fmt.Sprintf("msg-%d", i)
			resp, err := g.Generate(context.Background(), convWith(in), 1)
			if err != nil {
				errs[i] = err
				return
			}
			got[i] = resp[0].Content
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		require.NoError(t, errs[i])
		assert.Equal(t, fmt.Sprintf("echo:msg-%d", i), got[i],
			"each concurrent call must receive its own response (no frame cross-talk)")
	}
}

func TestPersistent_RedialsAfterServerClose(t *testing.T) {
	// Each connection answers exactly one request then closes, simulating a
	// server that idle-closes sessions. Persistent mode must transparently
	// redial on the stale socket so every Generate call still succeeds.
	var conns int32
	srv := newServer(t, func(ws *xwebsocket.Conn) {
		atomic.AddInt32(&conns, 1)
		var msg string
		if err := xwebsocket.Message.Receive(ws, &msg); err != nil {
			return
		}
		_ = xwebsocket.Message.Send(ws, "echo:"+msg)
		// returning closes the connection after one exchange
	})

	g := newGen(t, registry.Config{"uri": wsURL(srv.URL), "persistent": true})
	for i := 0; i < 3; i++ {
		resp, err := g.Generate(context.Background(), convWith("hi"), 1)
		require.NoError(t, err)
		assert.Equal(t, "echo:hi", resp[0].Content)
	}
	// 3 successful calls; first uses the initial dial, each subsequent call finds
	// the socket closed and redials once. More than 3 connections proves redial.
	assert.GreaterOrEqual(t, atomic.LoadInt32(&conns), int32(3))
}

func TestNonPersistent_DialsPerCall(t *testing.T) {
	var conns int32
	srv := newServer(t, func(ws *xwebsocket.Conn) {
		atomic.AddInt32(&conns, 1)
		var msg string
		_ = xwebsocket.Message.Receive(ws, &msg)
		_ = xwebsocket.Message.Send(ws, "ok")
	})

	g := newGen(t, registry.Config{"uri": wsURL(srv.URL)})
	for i := 0; i < 3; i++ {
		_, err := g.Generate(context.Background(), convWith("hi"), 1)
		require.NoError(t, err)
	}
	assert.Equal(t, int32(3), atomic.LoadInt32(&conns))
}

func TestGenerate_LastRawResponse(t *testing.T) {
	srv := newServer(t, func(ws *xwebsocket.Conn) {
		var msg string
		_ = xwebsocket.Message.Receive(ws, &msg)
		_ = xwebsocket.Message.Send(ws, `{"data":{"text":"x"}}`)
	})

	g := newGen(t, registry.Config{
		"uri":           wsURL(srv.URL),
		"response_json": true,
		"response_path": "$.data.text",
	})
	_, err := g.Generate(context.Background(), convWith("hi"), 1)
	require.NoError(t, err)
	assert.Equal(t, `{"data":{"text":"x"}}`, string(g.LastRawResponse()))
}

func TestGenerate_TLS_InsecureSkipVerify(t *testing.T) {
	srv := httptest.NewTLSServer(xwebsocket.Handler(func(ws *xwebsocket.Conn) {
		var msg string
		_ = xwebsocket.Message.Receive(ws, &msg)
		_ = xwebsocket.Message.Send(ws, "secure:"+msg)
	}))
	t.Cleanup(srv.Close)

	g := newGen(t, registry.Config{
		"uri":                  wsURL(srv.URL), // wss://
		"insecure_skip_verify": true,
	})
	resp, err := g.Generate(context.Background(), convWith("hi"), 1)
	require.NoError(t, err)
	assert.Equal(t, "secure:hi", resp[0].Content)
}

func TestGenerate_DialError(t *testing.T) {
	g := newGen(t, registry.Config{"uri": "ws://127.0.0.1:1/nope", "request_timeout": 2})
	_, err := g.Generate(context.Background(), convWith("hi"), 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dial")
}

func TestGenerate_ContextCancellation(t *testing.T) {
	srv := newServer(t, func(ws *xwebsocket.Conn) {
		var msg string
		_ = xwebsocket.Message.Receive(ws, &msg)
		time.Sleep(2 * time.Second) // never reply within the cancelled window
	})

	g := newGen(t, registry.Config{"uri": wsURL(srv.URL)})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := g.Generate(ctx, convWith("hi"), 1)
	require.Error(t, err)
	assert.Less(t, time.Since(start), time.Second, "cancellation should unblock the read promptly")
}

func TestGenerate_RequestTimeout_SingleRead(t *testing.T) {
	srv := newServer(t, func(ws *xwebsocket.Conn) {
		var msg string
		_ = xwebsocket.Message.Receive(ws, &msg)
		time.Sleep(2 * time.Second) // exceed request_timeout
	})

	g := newGen(t, registry.Config{"uri": wsURL(srv.URL), "request_timeout": 1})
	_, err := g.Generate(context.Background(), convWith("hi"), 1)
	require.Error(t, err)
}
