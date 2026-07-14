package llm_test

import (
	"context"
	"errors"
	"testing"

	reconllm "github.com/praetorian-inc/augustus/internal/recon/llm"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/output"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// mockGen is a canned-response generator standing in for the navigator LLM.
type mockGen struct {
	content string
	err     error
}

func (m *mockGen) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	if m.err != nil {
		return nil, m.err
	}
	return []attempt.Message{attempt.NewAssistantMessage(m.content)}, nil
}
func (m *mockGen) ClearHistory()       {}
func (m *mockGen) Name() string        { return "mockGen" }
func (m *mockGen) Description() string { return "mock navigator" }

// lastNavCfg captures the config the navigator factory received, so tests can
// assert NewBase wires model / max_tokens correctly.
var lastNavCfg registry.Config

func init() {
	generators.Register("test.NavEcho", func(cfg registry.Config) (generators.Generator, error) {
		lastNavCfg = cfg
		return &mockGen{content: "ok"}, nil
	})
}

func TestNewBase_LazilyCreatesNavigatorWithDefaults(t *testing.T) {
	lastNavCfg = nil
	b, err := reconllm.NewBase(registry.Config{
		"navigator_generator_type": "test.NavEcho",
		"model":                    "m1",
	})
	if err != nil {
		t.Fatalf("NewBase error: %v", err)
	}
	// Lazy: nothing created until first use.
	if b.Navigator != nil || lastNavCfg != nil {
		t.Fatal("navigator must be created lazily, not at construction")
	}
	// First Ask builds it, wiring model + the high max_tokens default.
	if _, err := b.Ask(context.Background(), "", "go"); err != nil {
		t.Fatalf("Ask error: %v", err)
	}
	if lastNavCfg["max_tokens"] != 4096 {
		t.Errorf("max_tokens default = %v, want 4096", lastNavCfg["max_tokens"])
	}
	if lastNavCfg["model"] != "m1" {
		t.Errorf("model = %v, want m1", lastNavCfg["model"])
	}
}

func TestNewBase_FallsBackToJudgeGenerator(t *testing.T) {
	// With no explicit navigator type, the judge generator is used. Navigator is
	// created lazily, so prove the fallback by exercising Ask.
	b, err := reconllm.NewBase(registry.Config{"judge_generator_type": "test.NavEcho"})
	if err != nil {
		t.Fatalf("NewBase error: %v", err)
	}
	if got, err := b.Ask(context.Background(), "", "u"); err != nil || got != "ok" {
		t.Fatalf("expected navigator to fall back to judge generator; got=%q err=%v", got, err)
	}
}

// TestNewBase_NoLLMConfigDoesNotFail: the deterministic recon path must not
// require any LLM/model configuration. NewBase must succeed with an empty config
// and only attempt (and possibly fail) to build a navigator if Ask is called.
func TestNewBase_NoLLMConfigDoesNotFail(t *testing.T) {
	b, err := reconllm.NewBase(registry.Config{})
	if err != nil {
		t.Fatalf("NewBase with no LLM config must not fail, got: %v", err)
	}
	if b.Navigator != nil {
		t.Error("navigator should be created lazily, not at construction")
	}
}

func TestBase_Ask(t *testing.T) {
	b := &reconllm.Base{Navigator: &mockGen{content: "hello world"}}
	got, err := b.Ask(context.Background(), "sys", "user")
	if err != nil {
		t.Fatalf("Ask error: %v", err)
	}
	if got != "hello world" {
		t.Errorf("Ask = %q, want %q", got, "hello world")
	}
}

func TestBase_Ask_NoNavigator(t *testing.T) {
	b := &reconllm.Base{}
	if _, err := b.Ask(context.Background(), "", "u"); err == nil {
		t.Error("Ask with nil navigator should error")
	}
}

func TestBase_Ask_PropagatesError(t *testing.T) {
	b := &reconllm.Base{Navigator: &mockGen{err: errors.New("boom")}}
	if _, err := b.Ask(context.Background(), "", "u"); err == nil {
		t.Error("Ask should propagate navigator error")
	}
}

func TestBase_SetContextAndPriorObservations(t *testing.T) {
	store := recon.NewStore()
	store.Observe(output.Observation{Type: "mcp.inventory"})
	store.Observe(output.Observation{Type: "other.kind"})
	store.Observe(output.Observation{Type: "mcp.inventory"})

	var b reconllm.Base
	b.SetContext(recon.ProbeContext{Recon: store})

	if b.Store() != store {
		t.Error("Store() did not return the injected store")
	}
	got := b.PriorObservations("mcp.inventory")
	if len(got) != 2 {
		t.Errorf("PriorObservations(mcp.inventory) len = %d, want 2", len(got))
	}
}

func TestBase_PriorObservations_NilStore(t *testing.T) {
	var b reconllm.Base
	if got := b.PriorObservations("anything"); got != nil {
		t.Errorf("PriorObservations with nil store = %v, want nil", got)
	}
}

func TestBase_IsContextAwareRecon(t *testing.T) {
	var _ recon.ContextAwareRecon = (*reconllm.Base)(nil)
}

func TestDecodeJSON(t *testing.T) {
	type payload struct {
		A int      `json:"a"`
		B []string `json:"b"`
	}
	tests := []struct {
		name string
		in   string
	}{
		{"raw", `{"a":1,"b":["x"]}`},
		{"fenced json", "```json\n{\"a\":1,\"b\":[\"x\"]}\n```"},
		{"fenced no label", "```\n{\"a\":1,\"b\":[\"x\"]}\n```"},
		{"leading prose", "Here is the result:\n{\"a\":1,\"b\":[\"x\"]}"},
		{"trailing prose", "{\"a\":1,\"b\":[\"x\"]}\nThat's all."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p payload
			if err := reconllm.DecodeJSON(tt.in, &p); err != nil {
				t.Fatalf("DecodeJSON error: %v", err)
			}
			if p.A != 1 || len(p.B) != 1 || p.B[0] != "x" {
				t.Errorf("decoded = %+v, want {A:1 B:[x]}", p)
			}
		})
	}
}

// TestNewBase_ReusesJudgeCredsWhenNavigatorUnset: when the navigator falls back
// to the shared judge generator type, it must also inherit the judge's creds and
// model (judge_config), not just the type — otherwise "reuse the judge" fails.
func TestNewBase_ReusesJudgeCredsWhenNavigatorUnset(t *testing.T) {
	lastNavCfg = nil
	b, err := reconllm.NewBase(registry.Config{
		"judge_generator_type": "test.NavEcho",
		"judge_config":         map[string]any{"model": "judge-model", "api_key": "judge-key"},
	})
	if err != nil {
		t.Fatalf("NewBase: %v", err)
	}
	if _, err := b.Ask(context.Background(), "", "go"); err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if lastNavCfg["model"] != "judge-model" {
		t.Errorf("navigator model = %v, want judge-model (reused from judge_config)", lastNavCfg["model"])
	}
	if lastNavCfg["api_key"] != "judge-key" {
		t.Errorf("navigator api_key = %v, want judge-key (reused from judge_config)", lastNavCfg["api_key"])
	}
}
