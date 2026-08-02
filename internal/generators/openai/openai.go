// Package openai provides an OpenAI generator for Augustus.
//
// This package implements the Generator interface for OpenAI's chat and
// completion APIs. It supports both chat models (GPT-4, GPT-3.5-turbo) and
// legacy completion models (gpt-3.5-turbo-instruct, davinci-002).
package openai

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	goopenai "github.com/sashabaranov/go-openai"

	"github.com/praetorian-inc/augustus/internal/attackengine"
	"github.com/praetorian-inc/augustus/internal/generators/openaicompat"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	generators.Register("openai.OpenAI", NewOpenAI)
}

// audioHTTPTimeout bounds a single custom-HTTP audio request so a hung upstream
// connection cannot block indefinitely when the caller's context carries no
// deadline. It is generous because audio synthesis is slower than text
// generation; per-request context cancellation still applies on top of it.
const audioHTTPTimeout = 120 * time.Second

// chatModels references the shared set of models that use the chat completions API.
var chatModels = openaicompat.ChatModels

// completionModels references the shared set of models that use the legacy completions API.
var completionModels = openaicompat.CompletionModels

// OpenAI is a generator that wraps the OpenAI API.
type OpenAI struct {
	types.UsageCounter // embedded; provides AccumulatedTokens()

	client *goopenai.Client
	model  string
	isChat bool

	// apiKey, baseURL, and httpClient support the custom audio HTTP path
	// (generateChatAudio), which bypasses the go-openai SDK.
	apiKey     string
	baseURL    string
	httpClient *http.Client

	// Configuration parameters
	temperature      float32
	maxTokens        int
	topP             float32
	frequencyPenalty float32
	presencePenalty  float32
	stop             []string
}

// NewOpenAI creates a new OpenAI generator from legacy registry.Config.
// This is the backward-compatible entry point.
func NewOpenAI(m registry.Config) (generators.Generator, error) {
	cfg, err := ConfigFromMap(m)
	if err != nil {
		return nil, err
	}
	return NewOpenAITyped(cfg)
}

// NewOpenAITyped creates a new OpenAI generator from typed configuration.
// This is the type-safe entry point for programmatic use.
func NewOpenAITyped(cfg Config) (*OpenAI, error) {
	g := &OpenAI{
		model:            cfg.Model,
		temperature:      cfg.Temperature,
		maxTokens:        cfg.MaxTokens,
		topP:             cfg.TopP,
		frequencyPenalty: cfg.FrequencyPenalty,
		presencePenalty:  cfg.PresencePenalty,
		stop:             cfg.Stop,
	}

	// Validate required fields
	if cfg.Model == "" {
		return nil, fmt.Errorf("openai generator requires model")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("openai generator requires api_key")
	}

	// Determine if this is a chat or completion model
	g.isChat = chatModels[cfg.Model]
	if !g.isChat && !completionModels[cfg.Model] {
		g.isChat = true // Default to chat for unknown models
	}

	// Create client config
	clientCfg := goopenai.DefaultConfig(cfg.APIKey)
	if cfg.BaseURL != "" {
		clientCfg.BaseURL = cfg.BaseURL
	}
	g.client = goopenai.NewClientWithConfig(clientCfg)

	g.apiKey = cfg.APIKey
	g.baseURL = cfg.BaseURL
	if g.baseURL == "" {
		g.baseURL = "https://api.openai.com/v1"
	}
	g.httpClient = &http.Client{Timeout: audioHTTPTimeout}

	return g, nil
}

// NewOpenAIWithOptions creates a new OpenAI generator using functional options.
// This is the recommended entry point for Go code.
//
// Usage:
//
//	g, err := NewOpenAIWithOptions(
//	    WithModel("gpt-4"),
//	    WithAPIKey("sk-..."),
//	    WithTemperature(0.5),
//	)
func NewOpenAIWithOptions(opts ...Option) (*OpenAI, error) {
	cfg := ApplyOptions(DefaultConfig(), opts...)
	return NewOpenAITyped(cfg)
}

// Generate sends the conversation to OpenAI and returns responses.
func (g *OpenAI) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	if g.isChat {
		return g.generateChat(ctx, conv, n)
	}
	return g.generateCompletion(ctx, conv, n)
}

// generateChat handles chat completion requests.
func (g *OpenAI) generateChat(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if conversationHasAudio(conv) {
		return g.generateChatAudio(ctx, conv, n)
	}

	// Convert conversation to OpenAI message format
	messages, err := openaicompat.ConversationToMessages(conv)
	if err != nil {
		return nil, openaicompat.WrapError("openai", err)
	}

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
	if g.frequencyPenalty != 0 {
		req.FrequencyPenalty = g.frequencyPenalty
	}
	if g.presencePenalty != 0 {
		req.PresencePenalty = g.presencePenalty
	}
	if len(g.stop) > 0 {
		req.Stop = g.stop
	}

	// Wire tool definitions from probe into the API request.
	if len(conv.Tools) > 0 {
		req.Tools = make([]goopenai.Tool, len(conv.Tools))
		for i, t := range conv.Tools {
			name, ok := t["name"].(string)
			if !ok || name == "" {
				return nil, fmt.Errorf("openai: tool at index %d missing valid string name", i)
			}
			fd := goopenai.FunctionDefinition{
				Name: name,
			}
			if desc, ok := t["description"].(string); ok {
				fd.Description = desc
			}
			if params, ok := t["parameters"]; ok {
				fd.Parameters = params
			}
			req.Tools[i] = goopenai.Tool{
				Type:     goopenai.ToolTypeFunction,
				Function: &fd,
			}
		}
		if conv.ToolChoice != "" {
			switch conv.ToolChoice {
			case "auto", "required", "none":
				req.ToolChoice = conv.ToolChoice
			default:
				req.ToolChoice = goopenai.ToolChoice{
					Type:     goopenai.ToolTypeFunction,
					Function: goopenai.ToolFunction{Name: conv.ToolChoice},
				}
			}
		}
	}

	resp, err := g.client.CreateChatCompletion(ctx, req)
	if err != nil {
		return nil, openaicompat.WrapError("openai", err)
	}
	g.AddTokens(int64(resp.Usage.TotalTokens))

	// Extract responses from choices, capturing any tool calls alongside text.
	responses := make([]attempt.Message, 0, len(resp.Choices))
	for _, choice := range resp.Choices {
		msg := attempt.NewAssistantMessage(choice.Message.Content)
		if toolCalls := attackengine.NormalizeOpenAIToolCalls(choice.Message.ToolCalls); toolCalls != nil {
			msg.ToolCalls = toolCalls
		}
		responses = append(responses, msg)
	}

	return responses, nil
}

// generateCompletion handles legacy completion requests.
func (g *OpenAI) generateCompletion(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	// For completion models, use the last prompt
	prompt := conv.LastPrompt()

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
	if g.frequencyPenalty != 0 {
		req.FrequencyPenalty = g.frequencyPenalty
	}
	if g.presencePenalty != 0 {
		req.PresencePenalty = g.presencePenalty
	}
	if len(g.stop) > 0 {
		req.Stop = g.stop
	}

	resp, err := g.client.CreateCompletion(ctx, req)
	if err != nil {
		return nil, openaicompat.WrapError("openai", err)
	}
	g.AddTokens(int64(resp.Usage.TotalTokens))

	// Extract responses from choices
	responses := make([]attempt.Message, 0, len(resp.Choices))
	for _, choice := range resp.Choices {
		responses = append(responses, attempt.NewAssistantMessage(choice.Text))
	}

	return responses, nil
}

// ClearHistory is a no-op for OpenAI generator (stateless per call).
func (g *OpenAI) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *OpenAI) Name() string {
	return "openai.OpenAI"
}

// SupportsVision reports vision capability based on the active model family.
// Chat-completion models go through the multipart image_url path in
// openaicompat.ConversationToMessages, but legacy completion models
// (gpt-3.5-turbo-instruct, davinci-002, babbage-002, etc.) use the
// CompletionRequest path that only carries the flattened LastPrompt() text.
// Reporting vision capability for completion models would silently drop image
// attachments. See types.VisionCapable.
func (g *OpenAI) SupportsVision() bool {
	if completionModels[g.model] {
		return false
	}
	// Default to true: any model not in the legacy completion set goes through
	// the chat path, which transmits image content blocks.
	return true
}

// SupportsAudio reports that the chat path can transmit audio attachments.
// The legacy completion path cannot, so it mirrors isChat.
func (g *OpenAI) SupportsAudio() bool { return g.isChat }

// Description returns a human-readable description.
func (g *OpenAI) Description() string {
	return "OpenAI API generator for GPT models (chat and completion)"
}

// conversationHasAudio reports whether any user turn carries audio attachments.
func conversationHasAudio(conv *attempt.Conversation) bool {
	for _, turn := range conv.Turns {
		if len(turn.Prompt.Audio) > 0 {
			return true
		}
	}
	return false
}

// generateChatAudio sends an audio-bearing chat request over a custom HTTP path.
// The pinned go-openai SDK cannot model input_audio content parts, so the request
// body is built and posted manually via openaicompat helpers.
//
// gpt-4o-audio-preview does not support n>1 with the audio modality (the API
// rejects it), so to honor Generate's contract of returning n responses this
// fans out n separate requests and aggregates their messages. Callers pass n=1
// in the common path, which issues exactly one request.
func (g *OpenAI) generateChatAudio(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	params := openaicompat.AudioChatParams{
		Voice:       "alloy",
		Format:      "wav",
		Temperature: g.temperature,
		TopP:        g.topP,
		MaxTokens:   g.maxTokens,
	}
	body, err := openaicompat.BuildAudioChatBody(g.model, conv, params)
	if err != nil {
		return nil, openaicompat.WrapError("openai", err)
	}

	all := make([]attempt.Message, 0, n)
	for range n {
		messages, err := g.doAudioRequest(ctx, body, params.Format)
		if err != nil {
			return nil, err
		}
		all = append(all, messages...)
	}
	return all, nil
}

// doAudioRequest issues a single custom-HTTP audio completion request and parses
// its response. format is the requested output audio format, used to label any
// returned audio bytes.
func (g *OpenAI) doAudioRequest(ctx context.Context, body []byte, format string) ([]attempt.Message, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, openaicompat.WrapError("openai", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+g.apiKey)

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, openaicompat.WrapError("openai", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, openaicompat.WrapError("openai", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openai: audio request failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	messages, tokens, err := openaicompat.ParseAudioChatResponse(respBody, format)
	if err != nil {
		return nil, openaicompat.WrapError("openai", err)
	}
	g.AddTokens(int64(tokens))
	return messages, nil
}
