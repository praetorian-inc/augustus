package hooks

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// usageInnerGenerator is a test double that implements types.Generator AND
// types.UsageReporter via the embedded types.UsageCounter.
type usageInnerGenerator struct {
	mockGenerator
	types.UsageCounter
	tokensPerCall int64
}

func (u *usageInnerGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	u.AddTokens(u.tokensPerCall)
	return u.mockGenerator.Generate(ctx, conv, n)
}

// mockGenerator is a test double for types.Generator.
type mockGenerator struct {
	name       string
	lastCtx    context.Context
	responses  []attempt.Message
	err        error
	rawResp    []byte
	generateMu sync.Mutex
	callCount  int
}

func (m *mockGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	m.generateMu.Lock()
	defer m.generateMu.Unlock()
	m.lastCtx = ctx
	m.callCount++
	if m.err != nil {
		return nil, m.err
	}
	return m.responses, nil
}

func (m *mockGenerator) ClearHistory()           {}
func (m *mockGenerator) Name() string            { return m.name }
func (m *mockGenerator) Description() string     { return "mock generator" }
func (m *mockGenerator) LastRawResponse() []byte { return m.rawResp }

// mcpInnerGenerator implements types.Generator + types.ToolInvoker +
// types.MCPReconnaissance, recording the hook vars visible in each call's
// context so tests can assert that hook-provided credentials are threaded
// through the forwarded calls.
type mcpInnerGenerator struct {
	mockGenerator
	seenVars map[string]string
}

func (m *mcpInnerGenerator) ListTools(ctx context.Context) ([]map[string]any, error) {
	m.seenVars = types.HookVarsFromContext(ctx)
	return []map[string]any{{"name": "echo"}}, nil
}

func (m *mcpInnerGenerator) CallTool(ctx context.Context, _ string, _ map[string]any) (types.ToolResult, error) {
	m.seenVars = types.HookVarsFromContext(ctx)
	return types.ToolResult{Text: "ok"}, nil
}

func (m *mcpInnerGenerator) MCPInventory(ctx context.Context) (*types.MCPInventory, error) {
	m.seenVars = types.HookVarsFromContext(ctx)
	return &types.MCPInventory{ServerName: "fake"}, nil
}

// A hooked MCP generator must still satisfy ToolInvoker + MCPReconnaissance, and
// must thread the current hook vars into those forwarded calls so header/arg
// substitution (e.g. Authorization: Bearer $TOKEN) works on tool calls & recon.
func TestHookedGenerator_PreservesMCPCapabilities(t *testing.T) {
	inner := &mcpInnerGenerator{mockGenerator: mockGenerator{name: "mcp"}}
	h := NewHookedGenerator(inner, nil, map[string]string{"TOKEN": "secret"})

	ti, ok := h.(types.ToolInvoker)
	require.True(t, ok, "wrapped MCP generator must still be a ToolInvoker")
	rc, ok := h.(types.MCPReconnaissance)
	require.True(t, ok, "wrapped MCP generator must still be MCPReconnaissance")

	_, err := ti.ListTools(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "secret", inner.seenVars["TOKEN"], "ListTools must see hook vars")

	inner.seenVars = nil
	_, err = ti.CallTool(context.Background(), "echo", nil)
	require.NoError(t, err)
	assert.Equal(t, "secret", inner.seenVars["TOKEN"], "CallTool must see hook vars")

	inner.seenVars = nil
	_, err = rc.MCPInventory(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "secret", inner.seenVars["TOKEN"], "MCPInventory must see hook vars")
}

// A hooked PLAIN generator must NOT advertise MCP capabilities — otherwise the
// type-assert-and-skip pattern in toolsec/recon would falsely match and fail at
// runtime.
func TestHookedGenerator_PlainGeneratorHasNoMCPCapabilities(t *testing.T) {
	h := NewHookedGenerator(&mockGenerator{name: "plain"}, nil, nil)
	if _, ok := h.(types.ToolInvoker); ok {
		t.Error("plain generator must NOT be advertised as ToolInvoker")
	}
	if _, ok := h.(types.MCPReconnaissance); ok {
		t.Error("plain generator must NOT be advertised as MCPReconnaissance")
	}
}

func TestHookedGeneratorNoHooks(t *testing.T) {
	inner := &mockGenerator{
		name:      "test.Mock",
		responses: []attempt.Message{attempt.NewAssistantMessage("hello")},
	}

	hg := NewHookedGenerator(inner, nil, nil)
	conv := attempt.NewConversation()
	conv.AddPrompt("test prompt")
	msgs, err := hg.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 1 || msgs[0].Content != "hello" {
		t.Errorf("unexpected messages: %v", msgs)
	}
}

func TestHookedGeneratorInitialVars(t *testing.T) {
	inner := &mockGenerator{
		name:      "test.Mock",
		responses: []attempt.Message{attempt.NewAssistantMessage("hello")},
	}

	initialVars := map[string]string{"CONVERSATION_ID": "abc123"}
	hg := NewHookedGenerator(inner, nil, initialVars)

	conv := attempt.NewConversation()
	conv.AddPrompt("test prompt")
	_, err := hg.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that vars were injected into context
	vars := VarsFromContext(inner.lastCtx)
	if vars == nil {
		t.Fatal("expected vars in context")
	}
	if vars["CONVERSATION_ID"] != "abc123" {
		t.Errorf("CONVERSATION_ID: got %q, want %q", vars["CONVERSATION_ID"], "abc123")
	}
}

func TestHookedGeneratorPrepareHook(t *testing.T) {
	inner := &mockGenerator{
		name:      "test.Mock",
		responses: []attempt.Message{attempt.NewAssistantMessage("response1")},
		rawResp:   []byte(`{"messageId":"msg-001"}`),
	}

	prepare := &Hook{Command: `echo "PARENT_MESSAGE_ID=prepared-id"`}
	hg := NewHookedGenerator(inner, prepare, map[string]string{"CONVERSATION_ID": "conv-001"})

	conv := attempt.NewConversation()
	conv.AddPrompt("test prompt")
	_, err := hg.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that both initial and prepare vars are in context
	vars := VarsFromContext(inner.lastCtx)
	if vars == nil {
		t.Fatal("expected vars in context")
	}
	if vars["CONVERSATION_ID"] != "conv-001" {
		t.Errorf("CONVERSATION_ID: got %q, want %q", vars["CONVERSATION_ID"], "conv-001")
	}
	if vars["PARENT_MESSAGE_ID"] != "prepared-id" {
		t.Errorf("PARENT_MESSAGE_ID: got %q, want %q", vars["PARENT_MESSAGE_ID"], "prepared-id")
	}
}

func TestHookedGeneratorCapturesRawResponse(t *testing.T) {
	inner := &mockGenerator{
		name:      "test.Mock",
		responses: []attempt.Message{attempt.NewAssistantMessage("resp")},
		rawResp:   []byte(`{"messageId":"msg-first"}`),
	}

	// Prepare hook reads the last response from file and echoes it
	prepare := &Hook{Command: `if [ -n "$AUGUSTUS_LAST_RESPONSE_FILE" ]; then echo "LAST=$(cat $AUGUSTUS_LAST_RESPONSE_FILE)"; fi`}
	hg := NewHookedGenerator(inner, prepare, nil)

	conv := attempt.NewConversation()
	conv.AddPrompt("prompt1")

	// First call: no AUGUSTUS_LAST_RESPONSE_FILE yet
	_, err := hg.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("first generate: %v", err)
	}

	// Update raw response for second call
	inner.rawResp = []byte(`{"messageId":"msg-second"}`)

	// Second call: should have AUGUSTUS_LAST_RESPONSE_FILE from first call
	_, err = hg.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("second generate: %v", err)
	}

	vars := VarsFromContext(inner.lastCtx)
	if vars == nil {
		t.Fatal("expected vars in context")
	}
	// The LAST var should contain the raw response from the first call
	if vars["LAST"] != `{"messageId":"msg-first"}` {
		t.Errorf("LAST: got %q, want %q", vars["LAST"], `{"messageId":"msg-first"}`)
	}
}

func TestHookedGeneratorDelegatesName(t *testing.T) {
	inner := &mockGenerator{name: "rest.Rest"}
	hg := NewHookedGenerator(inner, nil, nil)
	if hg.Name() != "rest.Rest" {
		t.Errorf("Name: got %q, want %q", hg.Name(), "rest.Rest")
	}
	if hg.Description() != "mock generator" {
		t.Errorf("Description: got %q, want %q", hg.Description(), "mock generator")
	}
}

func TestHookedGeneratorProbeIndexIncrements(t *testing.T) {
	inner := &mockGenerator{
		name:      "test.Mock",
		responses: []attempt.Message{attempt.NewAssistantMessage("resp")},
	}

	// Prepare hook captures probe index
	prepare := &Hook{Command: `echo "INDEX=$AUGUSTUS_PROBE_INDEX"`}
	hg := NewHookedGenerator(inner, prepare, nil)
	conv := attempt.NewConversation()
	conv.AddPrompt("prompt")

	// Call 1: index 0
	_, _ = hg.Generate(context.Background(), conv, 1)
	vars1 := VarsFromContext(inner.lastCtx)
	if vars1["INDEX"] != "0" {
		t.Errorf("first call INDEX: got %q, want %q", vars1["INDEX"], "0")
	}

	// Call 2: index 1
	_, _ = hg.Generate(context.Background(), conv, 1)
	vars2 := VarsFromContext(inner.lastCtx)
	if vars2["INDEX"] != "1" {
		t.Errorf("second call INDEX: got %q, want %q", vars2["INDEX"], "1")
	}
}

func TestHookedGeneratorPrepareHookFailure(t *testing.T) {
	inner := &mockGenerator{
		name:      "test.Mock",
		responses: []attempt.Message{attempt.NewAssistantMessage("hello")},
	}

	prepare := &Hook{Command: "exit 1"}
	hg := NewHookedGenerator(inner, prepare, nil)

	conv := attempt.NewConversation()
	conv.AddPrompt("test prompt")

	_, err := hg.Generate(context.Background(), conv, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "prepare hook failed")

	// Verify mutex was properly released by making another call.
	// If mutex was NOT released, this would deadlock.
	done := make(chan struct{})
	go func() {
		_, _ = hg.Generate(context.Background(), conv, 1)
		close(done)
	}()
	select {
	case <-done:
		// Good -- mutex was released
	case <-time.After(2 * time.Second):
		t.Fatal("deadlock: mutex was not released after prepare hook failure")
	}
}

func TestHookedGeneratorInnerError(t *testing.T) {
	innerErr := fmt.Errorf("model API timeout")
	inner := &mockGenerator{
		name: "test.Mock",
		err:  innerErr,
	}

	hg := NewHookedGenerator(inner, nil, map[string]string{"FOO": "bar"})

	conv := attempt.NewConversation()
	conv.AddPrompt("test prompt")

	_, err := hg.Generate(context.Background(), conv, 1)
	require.Error(t, err)
	assert.Equal(t, innerErr, err)
}

func TestHookedGeneratorClearHistory(t *testing.T) {
	inner := &mockGenerator{name: "test.Mock"}
	hg := NewHookedGenerator(inner, nil, nil)
	// Should not panic; delegates to inner
	hg.ClearHistory()
}

func TestHookedGeneratorConcurrentSafety(t *testing.T) {
	inner := &mockGenerator{
		name:      "test.Mock",
		responses: []attempt.Message{attempt.NewAssistantMessage("concurrent-resp")},
	}

	prepare := &Hook{Command: `echo "INDEX=$AUGUSTUS_PROBE_INDEX"`}
	hg := NewHookedGenerator(inner, prepare, map[string]string{
		"CONVERSATION_ID": "conc-test",
	})

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)

	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			conv := attempt.NewConversation()
			conv.AddPrompt(fmt.Sprintf("prompt-%d", idx))
			msgs, err := hg.Generate(context.Background(), conv, 1)
			if err != nil {
				errs[idx] = err
				return
			}
			if len(msgs) != 1 {
				errs[idx] = fmt.Errorf("goroutine %d: got %d messages, want 1", idx, len(msgs))
				return
			}
			if msgs[0].Content != "concurrent-resp" {
				errs[idx] = fmt.Errorf("goroutine %d: got %q, want %q", idx, msgs[0].Content, "concurrent-resp")
			}
		}(i)
	}

	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}

	// Verify all goroutines ran by checking call count
	inner.generateMu.Lock()
	defer inner.generateMu.Unlock()
	assert.Equal(t, goroutines, inner.callCount, "all goroutines should have called Generate")
}

func TestHookedGeneratorPrepareReceivesCurrentVars(t *testing.T) {
	inner := &mockGenerator{
		name:      "test.Mock",
		responses: []attempt.Message{attempt.NewAssistantMessage("resp")},
	}

	// Prepare hook reads AUGUSTUS_VAR_CONVERSATION_ID and echoes it
	prepare := &Hook{Command: `echo "ECHOED=$AUGUSTUS_VAR_CONVERSATION_ID"`}
	hg := NewHookedGenerator(inner, prepare, map[string]string{
		"CONVERSATION_ID": "conv-999",
	})

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err := hg.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	vars := VarsFromContext(inner.lastCtx)
	require.NotNil(t, vars)
	assert.Equal(t, "conv-999", vars["ECHOED"])
}

// ─── Category (v): ClearHistory preserves UsageCounter ───────────────────────

// TestHookedGenerator_ClearHistory_PreservesUsage guards that ClearHistory
// on a HookedGenerator does not reset the inner generator's token counter.
func TestHookedGenerator_ClearHistory_PreservesUsage(t *testing.T) {
	inner := &usageInnerGenerator{
		mockGenerator: mockGenerator{
			name:      "test.UsageMock",
			responses: []attempt.Message{attempt.NewAssistantMessage("ok")},
		},
		tokensPerCall: 13,
	}

	hg := NewHookedGenerator(inner, nil, nil)
	ur, ok := hg.(types.UsageReporter)
	require.True(t, ok, "hooked generator must expose UsageReporter")
	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err := hg.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// inner has accumulated 13 tokens; forwarding must reflect it
	require.Equal(t, int64(13), ur.AccumulatedTokens(), "AccumulatedTokens must forward inner's total")

	hg.ClearHistory()

	require.Equal(t, int64(13), ur.AccumulatedTokens(),
		"ClearHistory must not reset the forwarded AccumulatedTokens")
}

// ─── Category (iv): Decorator forwarding ─────────────────────────────────────

// TestHookedGenerator_ForwardsUsage proves that HookedGenerator forwards
// AccumulatedTokens() to the inner generator when the inner implements
// types.UsageReporter. This guards correction (b): without the forward,
// scans run through a prepare hook would read 0 tokens.
func TestHookedGenerator_ForwardsUsage(t *testing.T) {
	const tokensPerCall = int64(7)
	inner := &usageInnerGenerator{
		mockGenerator: mockGenerator{
			name:      "test.UsageMock",
			responses: []attempt.Message{attempt.NewAssistantMessage("ok")},
		},
		tokensPerCall: tokensPerCall,
	}

	hg := NewHookedGenerator(inner, nil, nil)
	ur, ok := hg.(types.UsageReporter)
	require.True(t, ok, "hooked generator must expose UsageReporter")
	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	// First call
	_, err := hg.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	require.Equal(t, tokensPerCall, ur.AccumulatedTokens(),
		"after one Generate, wrapper must forward inner's accumulated tokens")

	// Second call
	_, err = hg.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	require.Equal(t, tokensPerCall*2, ur.AccumulatedTokens(),
		"after two Generate calls, wrapper must forward inner's cumulative total")
}

// TestHookedGenerator_InnerNoUsage_Zero ensures that when the inner generator
// does NOT implement UsageReporter, the wrapper returns 0 without panicking.
func TestHookedGenerator_InnerNoUsage_Zero(t *testing.T) {
	// mockGenerator does NOT embed types.UsageCounter → does not satisfy UsageReporter.
	inner := &mockGenerator{
		name:      "test.Plain",
		responses: []attempt.Message{attempt.NewAssistantMessage("ok")},
	}
	hg := NewHookedGenerator(inner, nil, nil)

	// The wrapper always satisfies UsageReporter (returns 0 for a non-reporting
	// inner) — unlike the MCP interfaces, a zero token count is a safe answer.
	ur, ok := hg.(types.UsageReporter)
	require.True(t, ok, "wrapper must always expose UsageReporter")

	assert.Equal(t, int64(0), ur.AccumulatedTokens(),
		"wrapper around non-UsageReporter inner must return 0 without panicking")
}
