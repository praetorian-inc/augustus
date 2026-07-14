// Package llm provides embeddable plumbing for LLM-driven reconnaissance
// modules — recon that uses an operator-side "navigator" LLM to interpret a
// target (classify its tools, read unstructured tool output, extract facts)
// and emit observations.
//
// Base is not itself a recon.Recon: it has no Name/Recon and is not registered.
// A concrete module embeds it to gain a configured navigator generator, opt-in
// access to prior observations (recon.ContextAwareRecon), and helpers to prompt
// the navigator and decode its JSON replies. This keeps the LLM concern in one
// tested place rather than smeared across every module that wants it.
//
// The verdict a downstream probe renders must stay evidence-based: the
// navigator interprets and proposes, but its output should be confirmed by
// deterministic means (e.g. round-trip validating a candidate identifier)
// before it is trusted. This package deliberately provides only the plumbing,
// not a scoring path.
package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/output"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

const (
	// defaultNavigatorType is used when neither navigator_generator_type nor
	// judge_generator_type is configured.
	defaultNavigatorType = "openai.OpenAI"
	// defaultMaxTokens guards against provider defaults that are too small for
	// structured recon replies (the Anthropic generator defaults to 150).
	defaultMaxTokens = 4096
)

// Compile-time assertion: an embedder inherits SetContext and thus satisfies
// ContextAwareRecon (so the recon runner injects the shared store).
var _ recon.ContextAwareRecon = (*Base)(nil)

// Base is embeddable plumbing shared by LLM-driven recon modules.
type Base struct {
	// Navigator is the operator-side LLM used to interpret the target. It is
	// exported so tests can inject a mock; otherwise it is created lazily from
	// navType/navCfg on first use.
	Navigator types.Generator

	navType string
	navCfg  registry.Config
	store   *recon.Store
}

// NewBase constructs a Base, resolving the navigator generator's type and config
// but NOT creating it yet. Creation is deferred to first use (Ask) so the common
// deterministic recon path requires no LLM/model configuration at all — a module
// that never calls the navigator never needs a valid generator. The navigator
// type resolves from navigator_generator_type, then judge_generator_type (so a
// scan's shared judge LLM is reused by default), then a built-in default; the
// model comes from navigator_model or model; max_tokens defaults high enough for
// structured replies unless overridden in navigator_config.
func NewBase(cfg registry.Config) (*Base, error) {
	navType := registry.GetString(cfg, "navigator_generator_type", "")
	usingJudge := navType == ""
	if usingJudge {
		navType = registry.GetString(cfg, "judge_generator_type", "")
	}
	if navType == "" {
		navType = defaultNavigatorType
		usingJudge = false
	}

	navCfg := registry.Config{}
	if raw, ok := cfg["navigator_config"].(map[string]any); ok {
		for k, v := range raw {
			navCfg[k] = v
		}
	} else if usingJudge {
		// Reuse the shared judge generator's config (model, api_key, base_url, …)
		// when the navigator falls back to the judge TYPE without its own
		// navigator_config — otherwise it would get the type but no credentials.
		if jc, ok := cfg["judge_config"].(map[string]any); ok {
			for k, v := range jc {
				navCfg[k] = v
			}
		}
	}
	if model := registry.GetString(cfg, "navigator_model", ""); model != "" {
		navCfg["model"] = model
	} else if model := registry.GetString(cfg, "model", ""); model != "" {
		navCfg["model"] = model
	}
	if _, ok := navCfg["max_tokens"]; !ok {
		navCfg["max_tokens"] = defaultMaxTokens
	}

	return &Base{navType: navType, navCfg: navCfg}, nil
}

// navigator returns the navigator generator, constructing it on first use (and
// caching it). An injected Navigator is used as-is. This is where a missing/bad
// LLM configuration finally errors — only for callers that actually need it.
func (b *Base) navigator() (types.Generator, error) {
	if b.Navigator != nil {
		return b.Navigator, nil
	}
	nav, err := generators.Create(b.navType, b.navCfg)
	if err != nil {
		return nil, fmt.Errorf("llm recon: create navigator %q: %w", b.navType, err)
	}
	b.Navigator = nav
	return nav, nil
}

// SetContext implements recon.ContextAwareRecon: the runner delivers the shared
// observation store before the embedding module runs.
func (b *Base) SetContext(pc recon.ProbeContext) { b.store = pc.Recon }

// Store returns the shared observation store, or nil if none was injected.
func (b *Base) Store() *recon.Store { return b.store }

// PriorObservations returns the observations of the given type recorded by
// earlier recon modules. It returns nil when no store is present.
func (b *Base) PriorObservations(typ string) []output.Observation {
	if b.store == nil {
		return nil
	}
	var out []output.Observation
	for _, o := range b.store.Observations() {
		if o.Type == typ {
			out = append(out, o)
		}
	}
	return out
}

// Ask runs a single navigator turn with an optional system prompt and returns
// the assistant's text.
func (b *Base) Ask(ctx context.Context, system, user string) (string, error) {
	nav, err := b.navigator()
	if err != nil {
		return "", err
	}
	conv := attempt.NewConversation()
	if system != "" {
		conv.WithSystem(system)
	}
	conv.AddPrompt(user)

	msgs, err := nav.Generate(ctx, conv, 1)
	if err != nil {
		return "", fmt.Errorf("llm recon: navigator generate: %w", err)
	}
	if len(msgs) == 0 {
		return "", fmt.Errorf("llm recon: navigator returned no messages")
	}
	return msgs[0].Content, nil
}

// DecodeJSON decodes the first JSON value in an LLM reply into v, tolerating the
// markdown code fences and surrounding prose that models routinely emit.
func DecodeJSON(text string, v any) error {
	s := stripToJSON(text)
	dec := json.NewDecoder(strings.NewReader(s))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("llm recon: decode JSON from navigator output: %w", err)
	}
	return nil
}

// stripToJSON extracts the JSON body from a model reply: it unwraps the first
// ``` code fence (dropping an optional language tag) if present, then trims any
// leading prose before the first JSON token. Trailing content is left for the
// streaming json.Decoder to ignore.
func stripToJSON(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "```"); i >= 0 {
		rest := s[i+3:]
		if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
			if firstLine := strings.TrimSpace(rest[:nl]); !strings.ContainsAny(firstLine, "{[") {
				rest = rest[nl+1:]
			}
		}
		if j := strings.Index(rest, "```"); j >= 0 {
			rest = rest[:j]
		}
		s = strings.TrimSpace(rest)
	}
	if k := strings.IndexAny(s, "{["); k > 0 {
		s = s[k:]
	}
	return s
}
