// Package cohere provides a Cohere generator for Augustus.
//
// This package implements the Generator interface for Cohere's chat and
// legacy generate APIs. It supports both the v2 chat API (recommended) and
// v1 generate API (legacy).
//
// Following Cohere's migration guide:
// - api_version="v2": Uses /v2/chat endpoint (recommended, default)
// - api_version="v1": Uses /v1/generate endpoint (legacy, supports num_generations)
package cohere

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

const (
	// defaultBaseURL is the default Cohere API endpoint.
	defaultBaseURL = "https://api.cohere.com"
	// defaultModel is the default model to use.
	defaultModel = "command"
	// defaultTemperature matches Python garak's default.
	defaultTemperature = 0.75
	// defaultTopP matches Python garak's default.
	defaultTopP = 0.75
	// generationLimit is the max generations per v1 API call (matches Python).
	generationLimit = 5
)

func init() {
	generators.Register("cohere.Cohere", NewCohere)
}

// Cohere is a generator that wraps the Cohere API.
type Cohere struct {
	client  *http.Client
	baseURL string
	apiKey  string
	model   string

	// API version: "v1" for legacy generate, "v2" for chat (default)
	apiVersion string

	// Configuration parameters
	temperature      float64
	maxTokens        int
	topK             int // k parameter
	topP             float64
	frequencyPenalty float64
	presencePenalty  float64
	stop             []string
}

// NewCohere creates a new Cohere generator from configuration.
func NewCohere(cfg registry.Config) (generators.Generator, error) {
	g := &Cohere{
		client:      &http.Client{},
		baseURL:     defaultBaseURL,
		model:       defaultModel,
		apiVersion:  "v2",
		temperature: defaultTemperature,
		topP:        defaultTopP,
	}

	// API key: from config or env var
	g.apiKey = registry.GetString(cfg, "api_key", "")
	if g.apiKey == "" {
		g.apiKey = os.Getenv("COHERE_API_KEY")
	}
	if g.apiKey == "" {
		return nil, fmt.Errorf("cohere generator requires 'api_key' configuration or COHERE_API_KEY environment variable")
	}

	// Optional: model name
	if model := registry.GetString(cfg, "model", ""); model != "" {
		g.model = model
	}

	// Optional: custom base URL (for testing)
	if baseURL := registry.GetString(cfg, "base_url", ""); baseURL != "" {
		g.baseURL = strings.TrimSuffix(baseURL, "/")
	}

	// Optional: API version
	if apiVersion := registry.GetString(cfg, "api_version", ""); apiVersion == "v1" || apiVersion == "v2" {
		g.apiVersion = apiVersion
		// Invalid values silently default to v2 (matches Python behavior)
	}

	// Optional: temperature
	g.temperature = registry.GetFloat64(cfg, "temperature", defaultTemperature)

	// Optional: max_tokens
	g.maxTokens = registry.GetInt(cfg, "max_tokens", 0)

	// Optional: k (top-k)
	g.topK = registry.GetInt(cfg, "k", 0)

	// Optional: p (top-p)
	g.topP = registry.GetFloat64(cfg, "p", defaultTopP)

	// Optional: frequency_penalty
	g.frequencyPenalty = registry.GetFloat64(cfg, "frequency_penalty", 0)

	// Optional: presence_penalty
	g.presencePenalty = registry.GetFloat64(cfg, "presence_penalty", 0)

	// Optional: stop sequences
	g.stop = registry.GetStringSlice(cfg, "stop", nil)

	return g, nil
}

// Generate sends the conversation to Cohere and returns responses.
func (g *Cohere) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	if g.apiVersion == "v1" {
		return g.generateV1(ctx, conv, n)
	}
	return g.generateV2(ctx, conv, n)
}

// generateV2 uses the v2 chat API (recommended).
// Note: Chat API doesn't support num_generations, so we make multiple calls.
func (g *Cohere) generateV2(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	responses := make([]attempt.Message, 0, n)

	for i := 0; i < n; i++ {
		msg, err := g.callChatAPI(ctx, conv)
		if err != nil {
			return nil, err
		}
		responses = append(responses, msg)
	}

	return responses, nil
}

// callChatAPI makes a single v2 chat API call.
func (g *Cohere) callChatAPI(ctx context.Context, conv *attempt.Conversation) (attempt.Message, error) {
	// Build request body
	reqBody := g.buildChatRequest(conv)

	body, err := json.Marshal(reqBody)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("cohere: failed to marshal request: %w", err)
	}

	endpoint := g.baseURL + "/v2/chat"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return attempt.Message{}, fmt.Errorf("cohere: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+g.apiKey)

	resp, err := g.client.Do(req)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("cohere: request failed: %w", err)
	}
	defer resp.Body.Close()

	if err := g.checkResponseError(resp); err != nil {
		return attempt.Message{}, err
	}

	// Parse response
	var chatResp chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return attempt.Message{}, fmt.Errorf("cohere: failed to decode response: %w", err)
	}

	// Extract text content
	content := g.extractChatContent(chatResp)
	return attempt.NewAssistantMessage(content), nil
}

// buildChatRequest constructs the v2 chat API request body.
func (g *Cohere) buildChatRequest(conv *attempt.Conversation) map[string]any {
	req := map[string]any{
		"model":       g.model,
		"messages":    g.conversationToMessages(conv),
		"temperature": g.temperature,
	}

	if g.maxTokens > 0 {
		req["max_tokens"] = g.maxTokens
	}
	if g.topK > 0 {
		req["k"] = g.topK
	}
	if g.topP != 0 {
		req["p"] = g.topP
	}
	if g.frequencyPenalty != 0 {
		req["frequency_penalty"] = g.frequencyPenalty
	}
	if g.presencePenalty != 0 {
		req["presence_penalty"] = g.presencePenalty
	}

	return req
}

// conversationToMessages converts an Augustus Conversation to Cohere message format.
func (g *Cohere) conversationToMessages(conv *attempt.Conversation) []map[string]any {
	messages := make([]map[string]any, 0)

	// Add system message if present
	if conv.System != nil {
		messages = append(messages, map[string]any{
			"role":    "system",
			"content": conv.System.Content,
		})
	}

	// Add turns
	for _, turn := range conv.Turns {
		// Add user message
		messages = append(messages, map[string]any{
			"role":    "user",
			"content": turn.Prompt.Content,
		})

		// Add assistant response if present
		if turn.Response != nil {
			messages = append(messages, map[string]any{
				"role":    "assistant",
				"content": turn.Response.Content,
			})
		}
	}

	return messages
}

// extractChatContent extracts text content from a v2 chat response.
func (g *Cohere) extractChatContent(resp chatResponse) string {
	if resp.Message.Content == nil {
		return ""
	}

	for _, item := range resp.Message.Content {
		if item.Type == "text" && item.Text != "" {
			return item.Text
		}
	}

	return ""
}

// generateV1 uses the legacy v1 generate API.
// Supports num_generations natively.
func (g *Cohere) generateV1(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	responses := make([]attempt.Message, 0, n)

	// Batch requests to respect generation limit
	for n > 0 {
		batchSize := n
		if batchSize > generationLimit {
			batchSize = generationLimit
		}

		batch, err := g.callGenerateAPI(ctx, conv, batchSize)
		if err != nil {
			return nil, err
		}

		responses = append(responses, batch...)
		n -= batchSize
	}

	return responses, nil
}

// callGenerateAPI makes a v1 generate API call.
func (g *Cohere) callGenerateAPI(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	// Get the last prompt
	prompt := conv.LastPrompt()

	// Build request body
	reqBody := map[string]any{
		"model":           g.model,
		"prompt":          prompt,
		"num_generations": n,
		"temperature":     g.temperature,
	}

	if g.maxTokens > 0 {
		reqBody["max_tokens"] = g.maxTokens
	}
	if g.topK > 0 {
		reqBody["k"] = g.topK
	}
	if g.topP != 0 {
		reqBody["p"] = g.topP
	}
	if g.frequencyPenalty != 0 {
		reqBody["frequency_penalty"] = g.frequencyPenalty
	}
	if g.presencePenalty != 0 {
		reqBody["presence_penalty"] = g.presencePenalty
	}
	if len(g.stop) > 0 {
		reqBody["end_sequences"] = g.stop
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("cohere: failed to marshal request: %w", err)
	}

	endpoint := g.baseURL + "/v1/generate"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("cohere: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+g.apiKey)

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cohere: request failed: %w", err)
	}
	defer resp.Body.Close()

	if err := g.checkResponseError(resp); err != nil {
		return nil, err
	}

	// Parse response
	var genResp generateResponse
	if err := json.NewDecoder(resp.Body).Decode(&genResp); err != nil {
		return nil, fmt.Errorf("cohere: failed to decode response: %w", err)
	}

	// Extract generations
	responses := make([]attempt.Message, 0, len(genResp.Generations))
	for _, gen := range genResp.Generations {
		responses = append(responses, attempt.NewAssistantMessage(gen.Text))
	}

	return responses, nil
}

// checkResponseError checks for API errors in the response.
func (g *Cohere) checkResponseError(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case 429:
		return fmt.Errorf("cohere: rate limit exceeded: %s", string(body))
	case 400:
		return fmt.Errorf("cohere: bad request: %s", string(body))
	case 401:
		return fmt.Errorf("cohere: authentication error: %s", string(body))
	case 500, 502, 503, 504:
		return fmt.Errorf("cohere: server error (%d): %s", resp.StatusCode, string(body))
	default:
		return fmt.Errorf("cohere: API error (%d): %s", resp.StatusCode, string(body))
	}
}

// ClearHistory is a no-op for Cohere generator (stateless per call).
func (g *Cohere) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *Cohere) Name() string {
	return "cohere.Cohere"
}

// Description returns a human-readable description.
func (g *Cohere) Description() string {
	return "Cohere API generator for Command models (chat and generate)"
}

// Response types for parsing Cohere API responses.

// chatResponse represents a v2 chat API response.
type chatResponse struct {
	ID           string         `json:"id"`
	FinishReason string         `json:"finish_reason"`
	Message      messageContent `json:"message"`
}

// messageContent represents message content in a chat response.
type messageContent struct {
	Role    string        `json:"role"`
	Content []contentItem `json:"content"`
}

// contentItem represents a content item in a message.
type contentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// generateResponse represents a v1 generate API response.
type generateResponse struct {
	ID          string       `json:"id"`
	Generations []generation `json:"generations"`
}

// generation represents a single generation in a v1 response.
type generation struct {
	ID           string `json:"id"`
	Text         string `json:"text"`
	FinishReason string `json:"finish_reason"`
}
