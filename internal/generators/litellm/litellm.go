package litellm

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/praetorian-inc/augustus/internal/generators/openaicompat"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	goopenai "github.com/sashabaranov/go-openai"
)

func init() {
	generators.Register("litellm.LiteLLM", NewLiteLLM)
}

// unsupportedMultipleGenProviders lists model prefixes that don't support the n parameter.
// These require multiple API calls for multiple generations.
var unsupportedMultipleGenProviders = []string{
	"openrouter/",
	"claude",
	"anthropic/",
	"replicate/",
	"bedrock",
	"petals",
	"palm/",
	"together_ai/",
	"text-bison",
	"chat-bison",
	"code-bison",
	"codechat-bison",
}

// LiteLLM is a generator that connects to a LiteLLM proxy server.
type LiteLLM struct {
	client *goopenai.Client
	model  string

	// Configuration
	temperature       float32
	maxTokens         int
	topP              float32
	frequencyPenalty  float32
	presencePenalty   float32
	stop              []string
	suppressedParams  map[string]bool
	supportsMultipleN bool
}

// NewLiteLLM creates a new LiteLLM generator from registry.Config.
func NewLiteLLM(m registry.Config) (generators.Generator, error) {
	cfg, err := ConfigFromMap(m)
	if err != nil {
		return nil, err
	}
	return NewLiteLLMTyped(cfg)
}

// NewLiteLLMTyped creates a new LiteLLM generator from typed config.
func NewLiteLLMTyped(cfg Config) (*LiteLLM, error) {
	g := &LiteLLM{
		model:            cfg.Model,
		temperature:      cfg.Temperature,
		maxTokens:        cfg.MaxTokens,
		topP:             cfg.TopP,
		frequencyPenalty: cfg.FrequencyPenalty,
		presencePenalty:  cfg.PresencePenalty,
		stop:             cfg.Stop,
		suppressedParams: make(map[string]bool),
	}

	// Build suppressed params set
	for _, p := range cfg.SuppressedParams {
		g.suppressedParams[p] = true
	}

	// Determine if model supports n parameter
	g.supportsMultipleN = true
	modelLower := strings.ToLower(cfg.Model)
	for _, prefix := range unsupportedMultipleGenProviders {
		if strings.HasPrefix(modelLower, strings.ToLower(prefix)) {
			g.supportsMultipleN = false
			break
		}
	}

	// Create OpenAI client pointing to LiteLLM proxy with proper HTTP configuration
	clientCfg := goopenai.DefaultConfig(cfg.APIKey)

	// Normalize proxy URL - ensure /v1 suffix
	proxyURL := strings.TrimSuffix(cfg.ProxyURL, "/")
	if !strings.HasSuffix(proxyURL, "/v1") {
		proxyURL = proxyURL + "/v1"
	}
	clientCfg.BaseURL = proxyURL

	// Configure HTTP client with timeouts and connection pooling
	clientCfg.HTTPClient = &http.Client{
		Timeout: 120 * time.Second, // 2 minute timeout for long-running LLM requests
		Transport: &http.Transport{
			MaxIdleConns:        100,              // Connection pool size
			MaxIdleConnsPerHost: 10,               // Per-host limit
			IdleConnTimeout:     90 * time.Second, // Keep connections alive
		},
	}

	g.client = goopenai.NewClientWithConfig(clientCfg)

	return g, nil
}

// Generate sends the conversation to LiteLLM and returns responses.
func (g *LiteLLM) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	if g.supportsMultipleN {
		return g.generateWithN(ctx, conv, n)
	}
	return g.generateMultipleCalls(ctx, conv, n)
}

// generateWithN uses the n parameter for a single API call.
func (g *LiteLLM) generateWithN(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	req := g.buildRequest(conv)

	if !g.suppressedParams["n"] {
		req.N = n
	}

	resp, err := g.client.CreateChatCompletion(ctx, req)
	if err != nil {
		return nil, openaicompat.WrapError("litellm", err)
	}

	responses := make([]attempt.Message, 0, len(resp.Choices))
	for _, choice := range resp.Choices {
		responses = append(responses, attempt.NewAssistantMessage(choice.Message.Content))
	}

	return responses, nil
}

// generateMultipleCalls makes n separate API calls for models that don't support n param.
func (g *LiteLLM) generateMultipleCalls(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	responses := make([]attempt.Message, 0, n)

	for i := 0; i < n; i++ {
		req := g.buildRequest(conv)
		req.N = 1 // Always single response per call

		resp, err := g.client.CreateChatCompletion(ctx, req)
		if err != nil {
			return nil, openaicompat.WrapError("litellm", err)
		}

		if len(resp.Choices) > 0 {
			responses = append(responses, attempt.NewAssistantMessage(resp.Choices[0].Message.Content))
		}
	}

	return responses, nil
}

// buildRequest constructs the chat completion request.
func (g *LiteLLM) buildRequest(conv *attempt.Conversation) goopenai.ChatCompletionRequest {
	messages := openaicompat.ConversationToMessages(conv)

	req := goopenai.ChatCompletionRequest{
		Model:    g.model,
		Messages: messages,
	}

	// Add optional parameters if not suppressed
	if g.temperature != 0 && !g.suppressedParams["temperature"] {
		req.Temperature = g.temperature
	}
	if g.maxTokens > 0 && !g.suppressedParams["max_tokens"] {
		req.MaxTokens = g.maxTokens
	}
	if g.topP != 0 && !g.suppressedParams["top_p"] {
		req.TopP = g.topP
	}
	if g.frequencyPenalty != 0 && !g.suppressedParams["frequency_penalty"] {
		req.FrequencyPenalty = g.frequencyPenalty
	}
	if g.presencePenalty != 0 && !g.suppressedParams["presence_penalty"] {
		req.PresencePenalty = g.presencePenalty
	}
	if len(g.stop) > 0 && !g.suppressedParams["stop"] {
		req.Stop = g.stop
	}

	return req
}

// ClearHistory is a no-op (stateless per call).
func (g *LiteLLM) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *LiteLLM) Name() string {
	return "litellm.LiteLLM"
}

// Description returns a human-readable description.
func (g *LiteLLM) Description() string {
	return "LiteLLM proxy generator for 100+ LLM providers (OpenAI, Anthropic, Azure, etc.)"
}
