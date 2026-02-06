package nim

import (
	"context"

	"github.com/praetorian-inc/augustus/internal/generators/openaicompat"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	goopenai "github.com/sashabaranov/go-openai"
)

// NVMultimodal is a generator that wraps NVIDIA NIM multimodal endpoints.
// Supports text, image, and audio inputs.
type NVMultimodal struct {
	nimConfig
}

// NewNVMultimodal creates a new NVMultimodal generator from configuration.
func NewNVMultimodal(cfg registry.Config) (generators.Generator, error) {
	nc, err := newNIMConfig(cfg, "nim.NVMultimodal", 0.1)
	if err != nil {
		return nil, err
	}
	return &NVMultimodal{nimConfig: *nc}, nil
}

// Generate sends the conversation to NIM multimodal endpoint and returns responses.
func (g *NVMultimodal) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	// Convert conversation to OpenAI message format
	messages := openaicompat.ConversationToMessages(conv)

	req := goopenai.ChatCompletionRequest{
		Model:    g.model,
		Messages: messages,
		N:        n,
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

	resp, err := g.client.CreateChatCompletion(ctx, req)
	if err != nil {
		return nil, openaicompat.WrapError("nim", err)
	}

	// Extract responses from choices
	responses := make([]attempt.Message, 0, len(resp.Choices))
	for _, choice := range resp.Choices {
		responses = append(responses, attempt.NewAssistantMessage(choice.Message.Content))
	}

	return responses, nil
}

// ClearHistory is a no-op for NVMultimodal generator (stateless per call).
func (g *NVMultimodal) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *NVMultimodal) Name() string {
	return "nim.NVMultimodal"
}

// Description returns a human-readable description.
func (g *NVMultimodal) Description() string {
	return "NVIDIA NIM multimodal generator for text, image, and audio inputs"
}

// Vision is a generator that wraps NVIDIA NIM vision endpoints.
// This is a specialized version of NVMultimodal for text + image only.
type Vision struct {
	*NVMultimodal
}

// NewVision creates a new Vision generator from configuration.
func NewVision(cfg registry.Config) (generators.Generator, error) {
	// Vision is just a wrapper around NVMultimodal with a different name
	multimodal, err := NewNVMultimodal(cfg)
	if err != nil {
		return nil, err
	}

	return &Vision{
		NVMultimodal: multimodal.(*NVMultimodal),
	}, nil
}

// Name returns the generator's fully qualified name.
func (g *Vision) Name() string {
	return "nim.Vision"
}

// Description returns a human-readable description.
func (g *Vision) Description() string {
	return "NVIDIA NIM vision generator for text and image inputs"
}
