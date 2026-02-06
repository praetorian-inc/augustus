package nim

import (
	"context"

	"github.com/praetorian-inc/augustus/internal/generators/openaicompat"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	goopenai "github.com/sashabaranov/go-openai"
)

// NVOpenAICompletion is a generator that wraps NVIDIA NIM completion endpoints.
// Unlike NIM (which uses chat/completions), this uses the v1/completions endpoint.
type NVOpenAICompletion struct {
	nimConfig
}

// NewNVOpenAICompletion creates a new NVOpenAICompletion generator from configuration.
func NewNVOpenAICompletion(cfg registry.Config) (generators.Generator, error) {
	nc, err := newNIMConfig(cfg, "nim.NVOpenAICompletion", 0.7)
	if err != nil {
		return nil, err
	}
	return &NVOpenAICompletion{nimConfig: *nc}, nil
}

// Generate sends the prompt to NIM completions endpoint and returns responses.
func (g *NVOpenAICompletion) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	// Convert conversation to a single prompt string
	prompt := conversationToPrompt(conv)

	req := goopenai.CompletionRequest{
		Model:  g.model,
		Prompt: prompt,
		N:      n,
	}

	// Add optional parameters if set
	if g.temperature != 0 {
		req.Temperature = g.temperature
	}
	if g.maxTokens > 0 {
		req.MaxTokens = g.maxTokens
	}
	if g.topP != 0 {
		req.TopP = g.topP
	}

	resp, err := g.client.CreateCompletion(ctx, req)
	if err != nil {
		return nil, openaicompat.WrapError("nim", err)
	}

	// Extract responses from choices
	responses := make([]attempt.Message, 0, len(resp.Choices))
	for _, choice := range resp.Choices {
		responses = append(responses, attempt.NewAssistantMessage(choice.Text))
	}

	return responses, nil
}

// conversationToPrompt converts an Augustus Conversation to a single prompt string.
func conversationToPrompt(conv *attempt.Conversation) string {
	prompt := ""

	// Add system message if present
	if conv.System != nil {
		prompt += conv.System.Content + "\n\n"
	}

	// Add turns - for completions, we just concatenate the prompts
	for _, turn := range conv.Turns {
		prompt += turn.Prompt.Content
		if turn.Response != nil {
			prompt += "\n" + turn.Response.Content + "\n"
		}
	}

	return prompt
}

// ClearHistory is a no-op for NVOpenAICompletion generator (stateless per call).
func (g *NVOpenAICompletion) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *NVOpenAICompletion) Name() string {
	return "nim.NVOpenAICompletion"
}

// Description returns a human-readable description.
func (g *NVOpenAICompletion) Description() string {
	return "NVIDIA NIM OpenAI-compatible completions endpoint for text generation"
}
