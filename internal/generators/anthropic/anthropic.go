// Package anthropic provides an Anthropic Claude generator for Augustus.
//
// This package implements the Generator interface for Anthropic's Messages API.
// It supports Claude 3 and Claude 3.5 models (Opus, Sonnet, Haiku).
//
// Key differences from OpenAI:
//   - System prompts are passed as a separate parameter, not in messages
//   - max_tokens is required (not optional)
//   - Does not support n parameter for multiple completions per request
package anthropic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/praetorian-inc/augustus/internal/attackengine"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	generators.Register("anthropic.Anthropic", NewAnthropic)
}

// Default configuration values matching litellm patterns.
const (
	defaultMaxTokens   = 150
	defaultTemperature = 0.7
	defaultAPIVersion  = "2023-06-01"
	defaultBaseURL     = "https://api.anthropic.com/v1"
	defaultTimeout     = 90 * time.Second
)

// Anthropic is a generator that wraps the Anthropic Messages API.
type Anthropic struct {
	types.UsageCounter // embedded; provides AccumulatedTokens()

	apiKey     string
	baseURL    string
	apiVersion string
	model      string

	// Configuration parameters
	temperature   float64
	maxTokens     int
	topP          float64
	topK          int
	stopSequences []string

	// HTTP client for API calls
	client *http.Client
}

// NewAnthropic creates a new Anthropic generator from legacy registry.Config.
// This is the backward-compatible entry point.
func NewAnthropic(m registry.Config) (generators.Generator, error) {
	cfg, err := ConfigFromMap(m)
	if err != nil {
		return nil, err
	}
	return NewAnthropicTyped(cfg)
}

// NewAnthropicTyped creates a new Anthropic generator from typed configuration.
// This is the type-safe entry point for programmatic use.
func NewAnthropicTyped(cfg Config) (*Anthropic, error) {
	// Validate required fields
	if cfg.Model == "" {
		return nil, fmt.Errorf("anthropic generator requires model")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("anthropic generator requires api_key")
	}

	g := &Anthropic{
		model:         cfg.Model,
		apiKey:        cfg.APIKey,
		baseURL:       cfg.BaseURL,
		apiVersion:    cfg.APIVersion,
		temperature:   cfg.Temperature,
		maxTokens:     cfg.MaxTokens,
		topP:          cfg.TopP,
		topK:          cfg.TopK,
		stopSequences: cfg.StopSequences,
		client:        &http.Client{Timeout: defaultTimeout},
	}

	return g, nil
}

// NewAnthropicWithOptions creates a new Anthropic generator using functional options.
// This is the recommended entry point for Go code.
//
// Usage:
//
//	g, err := NewAnthropicWithOptions(
//	    WithModel("claude-3-5-sonnet-20241022"),
//	    WithAPIKey("..."),
//	    WithTemperature(0.5),
//	)
func NewAnthropicWithOptions(opts ...Option) (*Anthropic, error) {
	cfg := ApplyOptions(DefaultConfig(), opts...)
	return NewAnthropicTyped(cfg)
}

// messageRequest represents the Anthropic Messages API request format.
type messageRequest struct {
	Model         string               `json:"model"`
	MaxTokens     int                  `json:"max_tokens"`
	Messages      []Message            `json:"messages"`
	System        string               `json:"system,omitempty"`
	Temperature   float64              `json:"temperature,omitempty"`
	TopP          float64              `json:"top_p,omitempty"`
	TopK          int                  `json:"top_k,omitempty"`
	StopSequences []string             `json:"stop_sequences,omitempty"`
	Tools         []anthropicTool      `json:"tools,omitempty"`
	ToolChoice    *anthropicToolChoice `json:"tool_choice,omitempty"`
}

// anthropicTool is the Anthropic API tool definition format.
type anthropicTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"input_schema"`
}

// anthropicToolChoice controls how Claude selects tools.
type anthropicToolChoice struct {
	Type string `json:"type"`           // "auto", "any", or "tool"
	Name string `json:"name,omitempty"` // only when type="tool"
}

// messageResponse represents the Anthropic Messages API response format.
type messageResponse struct {
	ID           string         `json:"id"`
	Type         string         `json:"type"`
	Role         string         `json:"role"`
	Content      []contentBlock `json:"content"`
	StopReason   string         `json:"stop_reason"`
	StopSequence *string        `json:"stop_sequence"`
	Usage        usageStats     `json:"usage"`
}

// contentBlock represents a content block in the response.
// For text blocks, Type is "text" and Text carries the content.
// For thinking blocks, Type is "thinking" and Thinking carries the extended
// thinking (chain-of-thought) content.
// For tool_use blocks, Type is "tool_use", Name is the function name,
// Input is the arguments object, and ID is the tool call identifier.
type contentBlock struct {
	Type     string          `json:"type"`
	Text     string          `json:"text"`
	Thinking string          `json:"thinking,omitempty"`
	Name     string          `json:"name"`
	Input    json.RawMessage `json:"input"`
	ID       string          `json:"id"`
}

// usageStats represents token usage statistics.
type usageStats struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// errorResponse represents an Anthropic API error.
type errorResponse struct {
	Type  string      `json:"type"`
	Error errorDetail `json:"error"`
}

// errorDetail contains error information.
type errorDetail struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// Generate sends the conversation to Anthropic and returns responses.
// Since Anthropic doesn't support the n parameter, multiple generations
// require multiple API calls.
func (g *Anthropic) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	responses := make([]attempt.Message, 0, n)

	for i := 0; i < n; i++ {
		resp, err := g.generateOne(ctx, conv)
		if err != nil {
			return nil, err
		}
		responses = append(responses, resp)
	}

	return responses, nil
}

// generateOne performs a single API call and returns one response.
func (g *Anthropic) generateOne(ctx context.Context, conv *attempt.Conversation) (attempt.Message, error) {
	messages, system, err := BuildMessages(conv)
	if err != nil {
		return attempt.Message{}, err
	}

	req := messageRequest{
		Model:       g.model,
		MaxTokens:   g.maxTokens,
		Messages:    messages,
		System:      system,
		Temperature: g.temperature,
	}

	// Add optional parameters if set
	if g.topP != 0 {
		req.TopP = g.topP
	}
	if g.topK != 0 {
		req.TopK = g.topK
	}
	if len(g.stopSequences) > 0 {
		req.StopSequences = g.stopSequences
	}

	// Wire tool definitions from probe into the API request.
	if len(conv.Tools) > 0 {
		req.Tools = make([]anthropicTool, len(conv.Tools))
		for i, t := range conv.Tools {
			name, ok := t["name"].(string)
			if !ok || name == "" {
				return attempt.Message{}, fmt.Errorf("anthropic: tool at index %d missing valid string name", i)
			}
			at := anthropicTool{
				Name: name,
			}
			if desc, ok := t["description"].(string); ok {
				at.Description = desc
			}
			if params, ok := t["parameters"].(map[string]any); ok {
				at.InputSchema = params
			} else {
				at.InputSchema = map[string]any{"type": "object"}
			}
			req.Tools[i] = at
		}
		if conv.ToolChoice != "" {
			switch conv.ToolChoice {
			case "auto":
				req.ToolChoice = &anthropicToolChoice{Type: "auto"}
			case "required":
				req.ToolChoice = &anthropicToolChoice{Type: "any"}
			case "none":
				// Anthropic doesn't have "none" — omit tools instead.
				req.Tools = nil
				req.ToolChoice = nil
			default:
				req.ToolChoice = &anthropicToolChoice{Type: "tool", Name: conv.ToolChoice}
			}
		}
	}

	// Serialize request
	body, err := json.Marshal(req)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("anthropic: failed to marshal request: %w", err)
	}

	// Create HTTP request
	url := strings.TrimSuffix(g.baseURL, "/") + "/messages"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return attempt.Message{}, fmt.Errorf("anthropic: failed to create request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", g.apiKey)
	httpReq.Header.Set("anthropic-version", g.apiVersion)

	// Execute request
	httpResp, err := g.client.Do(httpReq)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("anthropic: request failed: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	// Read response body
	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("anthropic: failed to read response: %w", err)
	}

	// Handle errors
	if httpResp.StatusCode != http.StatusOK {
		return attempt.Message{}, g.handleError(httpResp.StatusCode, respBody)
	}

	// Parse successful response
	var resp messageResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return attempt.Message{}, fmt.Errorf("anthropic: failed to parse response: %w", err)
	}

	// Accumulate token usage per call (input + output).
	g.AddTokens(int64(resp.Usage.InputTokens + resp.Usage.OutputTokens))

	// Extract text, thinking, and tool_use blocks from content.
	var text, thinking string
	toolUseBlocks := make([]attackengine.AnthropicToolUseBlock, 0, len(resp.Content))
	for _, block := range resp.Content {
		switch block.Type {
		case "text":
			text += block.Text
		case "thinking":
			if thinking != "" {
				thinking += "\n"
			}
			thinking += block.Thinking
		case "tool_use":
			toolUseBlocks = append(toolUseBlocks, attackengine.AnthropicToolUseBlock{
				Type:  block.Type,
				ID:    block.ID,
				Name:  block.Name,
				Input: block.Input,
			})
		}
	}

	msg := attempt.NewAssistantMessage(text)
	msg.Reasoning = thinking
	if toolCalls := attackengine.NormalizeAnthropicToolUseBlocks(toolUseBlocks); toolCalls != nil {
		msg.ToolCalls = toolCalls
	}
	return msg, nil
}

// handleError processes API error responses.
func (g *Anthropic) handleError(statusCode int, body []byte) error {
	var errResp errorResponse
	if err := json.Unmarshal(body, &errResp); err != nil {
		return fmt.Errorf("anthropic: HTTP %d: %s", statusCode, string(body))
	}

	errType := errResp.Error.Type
	errMsg := errResp.Error.Message

	switch statusCode {
	case http.StatusTooManyRequests:
		return fmt.Errorf("anthropic: rate limit exceeded: %s", errMsg)
	case http.StatusBadRequest:
		return fmt.Errorf("anthropic: bad request (%s): %s", errType, errMsg)
	case http.StatusUnauthorized:
		return fmt.Errorf("anthropic: authentication error: %s", errMsg)
	case http.StatusForbidden:
		return fmt.Errorf("anthropic: permission denied: %s", errMsg)
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return fmt.Errorf("anthropic: server error (%d): %s", statusCode, errMsg)
	default:
		return fmt.Errorf("anthropic: API error (%d, %s): %s", statusCode, errType, errMsg)
	}
}

// ClearHistory is a no-op for Anthropic generator (stateless per call).
func (g *Anthropic) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *Anthropic) Name() string {
	return "anthropic.Anthropic"
}

// SupportsVision reports that the Anthropic Messages path transmits image
// content blocks (Claude 3+ vision). See types.VisionCapable.
func (g *Anthropic) SupportsVision() bool { return true }

// Description returns a human-readable description.
func (g *Anthropic) Description() string {
	return "Anthropic API generator for Claude models (Claude 3, Claude 3.5)"
}
