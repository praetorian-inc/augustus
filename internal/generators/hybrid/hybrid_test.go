package hybrid

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xwebsocket "golang.org/x/net/websocket"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// raiServer is an in-process stand-in for the Pylon/Rai exchange: an HTTP
// GraphQL endpoint (createConversation + updateConversation) plus a
// graphql-transport-ws subscription endpoint that streams the reply once the
// prompt arrives over HTTP. It exercises the full HTTP-in / WS-out hybrid.
type raiServer struct {
	srv *httptest.Server

	mu      sync.Mutex
	prompts map[string]chan string // conversationID -> prompt delivered via updateConversation

	gotUpdateBeforeSubscribe bool // set if updateConversation arrives with no waiting subscriber
}

func newRaiServer(t *testing.T) *raiServer {
	t.Helper()
	r := &raiServer{prompts: map[string]chan string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/graphql", r.handleGraphQL)
	mux.Handle("/subscriptions", xwebsocket.Handler(r.handleWS))
	r.srv = httptest.NewServer(mux)
	t.Cleanup(r.srv.Close)
	return r
}

func (r *raiServer) wsURL() string {
	return "ws" + strings.TrimPrefix(r.srv.URL, "http") + "/subscriptions"
}
func (r *raiServer) gqlURL() string { return r.srv.URL + "/graphql" }

func (r *raiServer) handleGraphQL(w http.ResponseWriter, req *http.Request) {
	var body struct {
		OperationName string `json:"operationName"`
		Variables     struct {
			Input struct {
				HouseholdID    string `json:"householdID"`
				ConversationID string `json:"conversationID"`
				Message        string `json:"message"`
			} `json:"input"`
		} `json:"variables"`
	}
	_ = json.NewDecoder(req.Body).Decode(&body)

	switch body.OperationName {
	case "create":
		convID := newUUID()
		r.mu.Lock()
		r.prompts[convID] = make(chan string, 1)
		r.mu.Unlock()
		writeJSON(w, map[string]any{"data": map[string]any{
			"createConversation": map[string]any{"conversation": map[string]any{"id": convID}},
		}})
	case "update":
		r.mu.Lock()
		ch, ok := r.prompts[body.Variables.Input.ConversationID]
		r.mu.Unlock()
		if !ok {
			r.mu.Lock()
			r.gotUpdateBeforeSubscribe = true
			r.mu.Unlock()
			http.Error(w, "no conversation", http.StatusInternalServerError)
			return
		}
		ch <- body.Variables.Input.Message
		writeJSON(w, map[string]any{"data": map[string]any{
			"updateConversation": map[string]any{"conversation": map[string]any{"id": body.Variables.Input.ConversationID}},
		}})
	default:
		http.Error(w, "unknown op", http.StatusBadRequest)
	}
}

func (r *raiServer) handleWS(ws *xwebsocket.Conn) {
	// 1. connection_init -> connection_ack
	var raw []byte
	if xwebsocket.Message.Receive(ws, &raw) != nil {
		return
	}
	_ = xwebsocket.Message.Send(ws, `{"type":"connection_ack"}`)

	// 2. subscribe -> capture id + conversationID
	if xwebsocket.Message.Receive(ws, &raw) != nil {
		return
	}
	var sub struct {
		ID      string `json:"id"`
		Payload struct {
			Variables struct {
				Input struct {
					ConversationID string `json:"conversationID"`
				} `json:"input"`
			} `json:"variables"`
		} `json:"payload"`
	}
	if json.Unmarshal(raw, &sub) != nil {
		return
	}

	r.mu.Lock()
	ch := r.prompts[sub.Payload.Variables.Input.ConversationID]
	r.mu.Unlock()
	if ch == nil {
		return
	}

	// 3. stream a reply for each prompt delivered via updateConversation.
	for prompt := range ch {
		r.stream(ws, sub.ID, prompt)
	}
}

// stream emits a protocol ping, two Message deltas, then the terminal
// CompleteSignal carrying the full answer — mirroring the captured frame order.
func (r *raiServer) stream(ws *xwebsocket.Conn, id, prompt string) {
	send := func(messageType, message string) bool {
		frame := map[string]any{
			"id": id, "type": "next",
			"payload": map[string]any{"data": map[string]any{"raiChat": map[string]any{
				"messageID": newUUID(), "messageType": messageType, "message": message,
			}}},
		}
		b, _ := json.Marshal(frame)
		return xwebsocket.Message.Send(ws, string(b)) == nil
	}
	_ = xwebsocket.Message.Send(ws, `{"type":"ping"}`)
	if !send("Message", "I'll check") {
		return
	}
	if !send("Message", " that for you") {
		return
	}
	send("CompleteSignal", "ANSWER:"+prompt)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func convWith(prompt string) *attempt.Conversation {
	conv := attempt.NewConversation()
	conv.AddPrompt(prompt)
	return conv
}

// pylonConfig builds the hybrid config that drives raiServer.
func pylonConfig(r *raiServer, persistent bool) registry.Config {
	return registry.Config{
		"api_key":         "test-jwt",
		"persistent":      persistent,
		"idle_timeout":    5,
		"request_timeout": 15,
		"vars":            map[string]any{"HOUSEHOLD_ID": "hh-1"},
		"steps": []any{
			map[string]any{
				"name": "create", "type": "http", "once": true,
				"url":     r.gqlURL() + "?m=create",
				"headers": map[string]any{"Authorization": "Bearer $KEY", "Content-Type": "application/json"},
				"body":    `{"operationName":"create","variables":{"input":{"householdID":"$HOUSEHOLD_ID"}}}`,
				"capture": map[string]any{"CONVERSATION_ID": "$.data.createConversation.conversation.id"},
			},
			map[string]any{
				"name": "connect", "type": "ws_connect", "once": true,
				"url": r.wsURL(), "subprotocol": "graphql-transport-ws", "origin": "http://test",
			},
			map[string]any{
				"name": "init", "type": "ws_send", "once": true,
				"frame": `{"type":"connection_init","payload":{"X-Caller":"member","X-Correlation-Id":"$CORRELATION_ID","authorization":"Bearer $KEY"}}`,
			},
			map[string]any{
				"name": "ack", "type": "ws_await", "once": true,
				"match_field": "$.type", "match_value": "connection_ack",
			},
			map[string]any{
				"name": "subscribe", "type": "ws_send", "once": true,
				"frame": `{"id":"$SUB_ID","type":"subscribe","payload":{"operationName":"AIChatContextConversation","variables":{"input":{"householdID":"$HOUSEHOLD_ID","conversationID":"$CONVERSATION_ID"}}}}`,
			},
			map[string]any{
				"name": "prompt", "type": "http",
				"url":     r.gqlURL() + "?m=update",
				"headers": map[string]any{"Authorization": "Bearer $KEY", "Content-Type": "application/json"},
				"body":    `{"operationName":"update","variables":{"input":{"householdID":"$HOUSEHOLD_ID","conversationID":"$CONVERSATION_ID","message":"$INPUT_JSON"}}}`,
			},
			map[string]any{
				"name": "answer", "type": "ws_stream", "answer": true,
				"response_field": "$.payload.data.raiChat.message",
				"complete_field": "$.payload.data.raiChat.messageType", "complete_value": "CompleteSignal",
			},
		},
	}
}

func TestHybrid_PylonFlow(t *testing.T) {
	r := newRaiServer(t)
	g, err := NewHybrid(pylonConfig(r, false))
	require.NoError(t, err)

	resp, err := g.Generate(context.Background(), convWith("How are my investments?"), 1)
	require.NoError(t, err)
	require.Len(t, resp, 1)
	// assembly=final: the CompleteSignal message wins, not the concatenated deltas.
	assert.Equal(t, "ANSWER:How are my investments?", resp[0].Content)
	assert.Equal(t, attempt.RoleAssistant, resp[0].Role)

	r.mu.Lock()
	defer r.mu.Unlock()
	assert.False(t, r.gotUpdateBeforeSubscribe, "updateConversation must arrive after subscribe")
}

func TestHybrid_PromptCarriesInput(t *testing.T) {
	r := newRaiServer(t)
	g, err := NewHybrid(pylonConfig(r, false))
	require.NoError(t, err)
	resp, err := g.Generate(context.Background(), convWith(`weird "quoted" prompt`), 1)
	require.NoError(t, err)
	assert.Equal(t, `ANSWER:weird "quoted" prompt`, resp[0].Content)
}

func TestHybrid_PersistentMultiTurn(t *testing.T) {
	r := newRaiServer(t)
	g, err := NewHybrid(pylonConfig(r, true))
	require.NoError(t, err)

	for _, p := range []string{"first", "second", "third"} {
		resp, err := g.Generate(context.Background(), convWith(p), 1)
		require.NoError(t, err)
		assert.Equal(t, "ANSWER:"+p, resp[0].Content)
	}
	// Persistent: only one conversation created (setup ran once).
	r.mu.Lock()
	assert.Len(t, r.prompts, 1)
	r.mu.Unlock()

	g.(*Hybrid).ClearHistory()
	resp, err := g.Generate(context.Background(), convWith("after-clear"), 1)
	require.NoError(t, err)
	assert.Equal(t, "ANSWER:after-clear", resp[0].Content)
	r.mu.Lock()
	assert.Len(t, r.prompts, 2, "ClearHistory should start a fresh conversation")
	r.mu.Unlock()
}

// TestHybrid_PersistentConcurrentGenerate fires many Generate calls at one
// persistent generator at once. The scanner shares a single generator instance
// across concurrent probe goroutines, so the shared WS session must be
// serialized — otherwise concurrent Send/Receive on one x/net/websocket conn
// interleaves frames and mis-attributes answers (and trips -race). Each call
// must get back exactly its own prompt's answer.
func TestHybrid_PersistentConcurrentGenerate(t *testing.T) {
	r := newRaiServer(t)
	g, err := NewHybrid(pylonConfig(r, true))
	require.NoError(t, err)

	const n = 8
	var wg sync.WaitGroup
	got := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := fmt.Sprintf("q-%d", i)
			resp, err := g.Generate(context.Background(), convWith(p), 1)
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
		assert.Equal(t, fmt.Sprintf("ANSWER:q-%d", i), got[i],
			"each concurrent call must receive its own answer (no frame cross-talk)")
	}
	r.mu.Lock()
	assert.Len(t, r.prompts, 1, "persistent: one conversation shared across all turns")
	r.mu.Unlock()
}

func TestHybrid_NonPersistentNewConversationPerCall(t *testing.T) {
	r := newRaiServer(t)
	g, err := NewHybrid(pylonConfig(r, false))
	require.NoError(t, err)
	for _, p := range []string{"a", "b"} {
		_, err := g.Generate(context.Background(), convWith(p), 1)
		require.NoError(t, err)
	}
	r.mu.Lock()
	assert.Len(t, r.prompts, 2, "non-persistent should create a conversation per call")
	r.mu.Unlock()
}

func TestHybrid_LastRawResponse(t *testing.T) {
	r := newRaiServer(t)
	g, err := NewHybrid(pylonConfig(r, false))
	require.NoError(t, err)
	_, err = g.Generate(context.Background(), convWith("x"), 1)
	require.NoError(t, err)
	assert.Contains(t, string(g.(*Hybrid).LastRawResponse()), "CompleteSignal")
}

// TestHybrid_PureHTTP proves the request+response can both be HTTP (the engine
// is not WS-only).
func TestHybrid_PureHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Variables struct {
				Input struct {
					Message string `json:"message"`
				} `json:"input"`
			} `json:"variables"`
		}
		_ = json.NewDecoder(req.Body).Decode(&body)
		writeJSON(w, map[string]any{"reply": "echo:" + body.Variables.Input.Message})
	}))
	t.Cleanup(srv.Close)

	g, err := NewHybrid(registry.Config{"steps": []any{
		map[string]any{
			"name": "ask", "type": "http", "answer": true,
			"url":            srv.URL,
			"body":           `{"variables":{"input":{"message":"$INPUT_JSON"}}}`,
			"response_field": "$.reply",
		},
	}})
	require.NoError(t, err)
	resp, err := g.Generate(context.Background(), convWith("hi"), 1)
	require.NoError(t, err)
	assert.Equal(t, "echo:hi", resp[0].Content)
}

// TestHybrid_HTTPFormFallback proves alternative request/response schemas: the
// first form hits an endpoint that 500s, the second succeeds.
func TestHybrid_HTTPFormFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasSuffix(req.URL.Path, "/v2") {
			http.Error(w, "gone", http.StatusInternalServerError)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(req.Body).Decode(&body)
		writeJSON(w, map[string]any{"legacy": map[string]any{"text": "ok-v1"}})
	}))
	t.Cleanup(srv.Close)

	g, err := NewHybrid(registry.Config{"steps": []any{
		map[string]any{
			"name": "ask", "type": "http", "answer": true,
			"response_field": []any{"$.modern.text", "$.legacy.text"},
			"forms": []any{
				map[string]any{"url": srv.URL + "/v2", "body": `{"v2":"$INPUT_JSON"}`},
				map[string]any{"url": srv.URL + "/v1", "body": `{"v1":"$INPUT_JSON"}`},
			},
		},
	}})
	require.NoError(t, err)
	resp, err := g.Generate(context.Background(), convWith("hi"), 1)
	require.NoError(t, err)
	assert.Equal(t, "ok-v1", resp[0].Content)
}

// TestHybrid_HTTPPollFormFallback proves http_poll honors fallback forms (like
// http does): the first poll form errors, the second succeeds.
func TestHybrid_HTTPPollFormFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/v2") {
			http.Error(w, "gone", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"status": "done", "result": "fallback-answer"})
	}))
	t.Cleanup(srv.Close)

	g, err := NewHybrid(registry.Config{"persistent": false, "steps": []any{
		map[string]any{
			"name": "wait", "type": "http_poll", "answer": true,
			"until_field": "$.status", "until_value": "done",
			"response_field": "$.result",
			"interval":       0.05, "max_attempts": 5,
			"forms": []any{
				map[string]any{"url": srv.URL + "/v2", "method": "GET"},
				map[string]any{"url": srv.URL + "/v1", "method": "GET"},
			},
		},
	}})
	require.NoError(t, err)
	resp, err := g.Generate(context.Background(), convWith("hi"), 1)
	require.NoError(t, err)
	assert.Equal(t, "fallback-answer", resp[0].Content)
}

// TestHybrid_PureWS proves the request+response can both be WebSocket.
func TestHybrid_PureWS(t *testing.T) {
	srv := httptest.NewServer(xwebsocket.Handler(func(ws *xwebsocket.Conn) {
		var msg string
		if xwebsocket.Message.Receive(ws, &msg) != nil {
			return
		}
		frame, _ := json.Marshal(map[string]any{"type": "next", "done": true, "text": "ws:" + msg})
		_ = xwebsocket.Message.Send(ws, string(frame))
	}))
	t.Cleanup(srv.Close)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	g, err := NewHybrid(registry.Config{"persistent": false, "idle_timeout": 5, "steps": []any{
		map[string]any{"name": "c", "type": "ws_connect", "url": wsURL, "origin": "http://test"},
		map[string]any{"name": "send", "type": "ws_send", "frame": "$INPUT"},
		map[string]any{
			"name": "answer", "type": "ws_stream", "answer": true,
			"response_field": "$.text", "complete_field": "$.done", "complete_value": "true",
		},
	}})
	require.NoError(t, err)
	resp, err := g.Generate(context.Background(), convWith("hello"), 1)
	require.NoError(t, err)
	assert.Equal(t, "ws:hello", resp[0].Content)
}

// TestHybrid_WSStreamCompleteBeforeTerminal proves assembly:final does not
// accept a protocol `complete` frame as the answer: a stream that completes
// before the configured terminal frame is an error, not a partial delta.
func TestHybrid_WSStreamCompleteBeforeTerminal(t *testing.T) {
	srv := httptest.NewServer(xwebsocket.Handler(func(ws *xwebsocket.Conn) {
		var msg string
		if xwebsocket.Message.Receive(ws, &msg) != nil {
			return
		}
		// A non-terminal delta, then a protocol complete with no terminal frame.
		delta, _ := json.Marshal(map[string]any{"type": "next", "done": false, "text": "partial"})
		_ = xwebsocket.Message.Send(ws, string(delta))
		_ = xwebsocket.Message.Send(ws, `{"type":"complete"}`)
	}))
	t.Cleanup(srv.Close)
	wsAddr := "ws" + strings.TrimPrefix(srv.URL, "http")

	g, err := NewHybrid(registry.Config{"persistent": false, "idle_timeout": 5, "steps": []any{
		map[string]any{"name": "c", "type": "ws_connect", "url": wsAddr, "origin": "http://test"},
		map[string]any{"name": "send", "type": "ws_send", "frame": "$INPUT"},
		map[string]any{
			"name": "answer", "type": "ws_stream", "answer": true,
			"response_field": "$.text", "complete_field": "$.done", "complete_value": "true",
		},
	}})
	require.NoError(t, err)
	_, err = g.Generate(context.Background(), convWith("hello"), 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "completed before terminal frame")
}

// TestHybrid_HTTPPoll_UntilField covers the async job shape: POST to endpoint A
// returns a job id; the answer is polled from endpoint B until status == done.
func TestHybrid_HTTPPoll_UntilField(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/send":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			writeJSON(w, map[string]any{"job_id": "job-1"})
		case strings.HasPrefix(r.URL.Path, "/jobs/"):
			if atomic.AddInt32(&attempts, 1) < 3 {
				writeJSON(w, map[string]any{"status": "pending"})
				return
			}
			writeJSON(w, map[string]any{"status": "done", "result": "polled-answer"})
		default:
			http.Error(w, "nope", http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	g, err := NewHybrid(registry.Config{"persistent": false, "steps": []any{
		map[string]any{
			"name": "send", "type": "http",
			"url": srv.URL + "/send", "body": `{"prompt":"$INPUT_JSON"}`,
			"capture": map[string]any{"JOB_ID": "$.job_id"},
		},
		map[string]any{
			"name": "wait", "type": "http_poll", "answer": true,
			"url": srv.URL + "/jobs/$JOB_ID", "method": "GET",
			"until_field": "$.status", "until_value": "done",
			"response_field": "$.result",
			"interval":       0.05, "max_attempts": 10,
		},
	}})
	require.NoError(t, err)

	resp, err := g.Generate(context.Background(), convWith("hi"), 1)
	require.NoError(t, err)
	assert.Equal(t, "polled-answer", resp[0].Content)
	assert.GreaterOrEqual(t, atomic.LoadInt32(&attempts), int32(3), "should have polled until done")
}

// TestHybrid_HTTPPoll_AnswerAppears covers readiness-by-presence: no status
// field, the poll stops once response_field becomes non-empty.
func TestHybrid_HTTPPoll_AnswerAppears(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) < 2 {
			writeJSON(w, map[string]any{}) // not ready: no result field
			return
		}
		writeJSON(w, map[string]any{"result": map[string]any{"text": "ready-now"}})
	}))
	t.Cleanup(srv.Close)

	g, err := NewHybrid(registry.Config{"persistent": false, "steps": []any{
		map[string]any{
			"name": "poll", "type": "http_poll", "answer": true,
			"url": srv.URL + "/result", "method": "GET",
			"response_field": "$.result.text",
			"interval":       0.05, "max_attempts": 10,
		},
	}})
	require.NoError(t, err)

	resp, err := g.Generate(context.Background(), convWith("hi"), 1)
	require.NoError(t, err)
	assert.Equal(t, "ready-now", resp[0].Content)
}

func TestHybrid_HTTPPoll_Exhausted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"status": "pending"}) // never ready
	}))
	t.Cleanup(srv.Close)

	g, err := NewHybrid(registry.Config{"persistent": false, "steps": []any{
		map[string]any{
			"name": "poll", "type": "http_poll", "answer": true,
			"url": srv.URL, "method": "GET",
			"until_field": "$.status", "until_value": "done",
			"response_field": "$.result",
			"interval":       0.02, "max_attempts": 3,
		},
	}})
	require.NoError(t, err)

	_, err = g.Generate(context.Background(), convWith("hi"), 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exhausted")
}

func TestHybridConfig_HTTPPollRequiresReadiness(t *testing.T) {
	_, err := HybridConfigFromMap(registry.Config{"steps": []any{
		map[string]any{"name": "p", "type": "http_poll", "answer": true, "url": "https://x", "method": "GET"},
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "readiness condition")
}

func TestHybrid_NameAndDescription(t *testing.T) {
	g, err := NewHybrid(registry.Config{"steps": minimalSteps()})
	require.NoError(t, err)
	assert.Equal(t, "hybrid.Hybrid", g.Name())
	assert.NotEmpty(t, g.Description())
}

// reconnectServer drives a hybrid in persistent + reuse_connection:false mode.
// The conversation is created once over HTTP, but the WS socket is rebuilt every
// turn. It counts HTTP conversation creations and WS handshakes so a test can
// prove the HTTP once-step ran once while the WS setup steps reran each turn. A
// fresh socket per turn means no lingering subscriber goroutine, so each turn is
// self-contained.
type reconnectServer struct {
	srv *httptest.Server

	mu            sync.Mutex
	conversations int
	handshakes    int
}

func newReconnectServer(t *testing.T) *reconnectServer {
	t.Helper()
	s := &reconnectServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		s.conversations++
		s.mu.Unlock()
		writeJSON(w, map[string]any{"data": map[string]any{
			"createConversation": map[string]any{"conversation": map[string]any{"id": newUUID()}},
		}})
	})
	mux.Handle("/subscriptions", xwebsocket.Handler(s.handleWS))
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

// handleWS handles exactly one turn per connection: an init frame (the WS setup
// step that must rerun on reconnect), then the prompt frame, then a streamed
// CompleteSignal answer.
func (s *reconnectServer) handleWS(ws *xwebsocket.Conn) {
	s.mu.Lock()
	s.handshakes++
	s.mu.Unlock()

	var raw []byte
	if xwebsocket.Message.Receive(ws, &raw) != nil { // init frame
		return
	}
	if xwebsocket.Message.Receive(ws, &raw) != nil { // prompt frame
		return
	}
	var pf struct {
		Prompt string `json:"prompt"`
	}
	if json.Unmarshal(raw, &pf) != nil {
		return
	}
	frame := map[string]any{"type": "next", "payload": map[string]any{
		"messageType": "CompleteSignal", "message": "ANSWER:" + pf.Prompt,
	}}
	b, _ := json.Marshal(frame)
	_ = xwebsocket.Message.Send(ws, string(b))
}

func reconnectConfig(s *reconnectServer) registry.Config {
	wsAddr := "ws" + strings.TrimPrefix(s.srv.URL, "http") + "/subscriptions"
	return registry.Config{
		"persistent":       true,
		"reuse_connection": false,
		"idle_timeout":     5,
		"request_timeout":  15,
		"steps": []any{
			map[string]any{
				"name": "create", "type": "http", "once": true,
				"url":     s.srv.URL + "/graphql",
				"headers": map[string]any{"Content-Type": "application/json"},
				"body":    `{"operationName":"create"}`,
				"capture": map[string]any{"CONVERSATION_ID": "$.data.createConversation.conversation.id"},
			},
			map[string]any{
				"name": "connect", "type": "ws_connect", "once": true,
				"url": wsAddr, "origin": "http://test",
			},
			map[string]any{
				"name": "init", "type": "ws_send", "once": true,
				"frame": `{"type":"connection_init","conversationID":"$CONVERSATION_ID"}`,
			},
			map[string]any{
				"name": "prompt", "type": "ws_send",
				"frame": `{"prompt":"$INPUT_JSON"}`,
			},
			map[string]any{
				"name": "answer", "type": "ws_stream", "answer": true,
				"response_field": "$.payload.message",
				"complete_field": "$.payload.messageType", "complete_value": "CompleteSignal",
			},
		},
	}
}

// TestHybrid_ReuseConnectionFalseReconnectsEachTurn is the regression for the
// reuse_connection:false lifecycle: HTTP captures persist (conversation created
// once) while the WS socket — and its once-marked setup steps — must be rebuilt
// every turn. Before the fix, once-steps were skipped on reuse and the next turn
// reached ws_stream with no open socket.
func TestHybrid_ReuseConnectionFalseReconnectsEachTurn(t *testing.T) {
	s := newReconnectServer(t)
	g, err := NewHybrid(reconnectConfig(s))
	require.NoError(t, err)

	prompts := []string{"alpha", "bravo", "charlie"}
	for _, p := range prompts {
		resp, err := g.Generate(context.Background(), convWith(p), 1)
		require.NoError(t, err)
		require.Len(t, resp, 1)
		assert.Equal(t, "ANSWER:"+p, resp[0].Content)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	assert.Equal(t, 1, s.conversations, "HTTP once-step must run only once (captures persist)")
	assert.Equal(t, len(prompts), s.handshakes, "WS must reconnect and re-run setup every turn")
}
