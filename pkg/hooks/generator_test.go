package hooks

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func (m *mockGenerator) ClearHistory()          {}
func (m *mockGenerator) Name() string           { return m.name }
func (m *mockGenerator) Description() string    { return "mock generator" }
func (m *mockGenerator) LastRawResponse() []byte { return m.rawResp }

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
