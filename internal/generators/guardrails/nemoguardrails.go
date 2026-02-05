// Package guardrails provides a NeMo Guardrails generator for Augustus.
//
// This package implements the Generator interface for NVIDIA's NeMo Guardrails,
// which provides a toolkit for adding programmable guardrails to LLM-based conversational systems.
package guardrails

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("guardrails.NeMoGuardrails", NewNeMoGuardrails)
}

// NeMoGuardrails is a generator that wraps the NeMo Guardrails HTTP API.
type NeMoGuardrails struct {
	client      *http.Client
	baseURL     string
	apiKey      string
	railsConfig string
}

// NewNeMoGuardrails creates a new NeMo Guardrails generator from configuration.
func NewNeMoGuardrails(cfg registry.Config) (generators.Generator, error) {
	g := &NeMoGuardrails{
		client: &http.Client{},
	}

	// Required: rails_config (path to config directory or config name)
	railsConfig, ok := cfg["rails_config"].(string)
	if !ok || railsConfig == "" {
		return nil, fmt.Errorf("nemo guardrails generator requires 'rails_config' configuration")
	}
	g.railsConfig = railsConfig

	// Required: base_url (HTTP endpoint)
	baseURL, ok := cfg["base_url"].(string)
	if !ok || baseURL == "" {
		return nil, fmt.Errorf("nemo guardrails generator requires 'base_url' configuration")
	}
	g.baseURL = strings.TrimSuffix(baseURL, "/")

	// Optional: API key for authentication
	if key, ok := cfg["api_key"].(string); ok && key != "" {
		g.apiKey = key
	}

	return g, nil
}

// Generate sends the conversation to NeMo Guardrails and returns responses.
func (g *NeMoGuardrails) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	// NeMo Guardrails doesn't support multiple generations in one call
	// Generate multiple responses by making multiple calls
	responses := make([]attempt.Message, 0, n)
	for i := 0; i < n; i++ {
		msg, err := g.callAPI(ctx, conv)
		if err != nil {
			return nil, err
		}
		responses = append(responses, msg)
	}

	return responses, nil
}

// callAPI makes a single API call to NeMo Guardrails.
func (g *NeMoGuardrails) callAPI(ctx context.Context, conv *attempt.Conversation) (attempt.Message, error) {
	// Build request body
	reqBody := g.buildRequest(conv)

	body, err := json.Marshal(reqBody)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("nemo guardrails: failed to marshal request: %w", err)
	}

	endpoint := g.baseURL + "/v1/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return attempt.Message{}, fmt.Errorf("nemo guardrails: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if g.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+g.apiKey)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("nemo guardrails: request failed: %w", err)
	}
	defer resp.Body.Close()

	if err := g.checkResponseError(resp); err != nil {
		return attempt.Message{}, err
	}

	// Parse response
	var apiResp apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return attempt.Message{}, fmt.Errorf("nemo guardrails: failed to decode response: %w", err)
	}

	// Extract content from response
	content := g.extractContent(apiResp)
	return attempt.NewAssistantMessage(content), nil
}

// buildRequest constructs the API request body.
func (g *NeMoGuardrails) buildRequest(conv *attempt.Conversation) map[string]any {
	req := map[string]any{
		"config_id": g.railsConfig,
		"messages":  g.conversationToMessages(conv),
	}

	return req
}

// conversationToMessages converts an Augustus Conversation to NeMo message format.
func (g *NeMoGuardrails) conversationToMessages(conv *attempt.Conversation) []map[string]string {
	messages := make([]map[string]string, 0)

	// Add system message if present
	if conv.System != nil {
		messages = append(messages, map[string]string{
			"role":    "system",
			"content": conv.System.Content,
		})
	}

	// Add turns
	for _, turn := range conv.Turns {
		// Add user message
		messages = append(messages, map[string]string{
			"role":    "user",
			"content": turn.Prompt.Content,
		})

		// Add assistant response if present
		if turn.Response != nil {
			messages = append(messages, map[string]string{
				"role":    "assistant",
				"content": turn.Response.Content,
			})
		}
	}

	return messages
}

// extractContent extracts text content from the API response.
func (g *NeMoGuardrails) extractContent(resp apiResponse) string {
	if len(resp.Messages) == 0 {
		return ""
	}

	// Return the last assistant message
	for i := len(resp.Messages) - 1; i >= 0; i-- {
		if resp.Messages[i].Role == "assistant" {
			return resp.Messages[i].Content
		}
	}

	return ""
}

// checkResponseError checks for API errors in the response.
func (g *NeMoGuardrails) checkResponseError(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case 429:
		return fmt.Errorf("nemo guardrails: rate limit exceeded: %s", string(body))
	case 400:
		return fmt.Errorf("nemo guardrails: bad request: %s", string(body))
	case 401:
		return fmt.Errorf("nemo guardrails: authentication error: %s", string(body))
	case 500, 502, 503, 504:
		return fmt.Errorf("nemo guardrails: server error (%d): %s", resp.StatusCode, string(body))
	default:
		return fmt.Errorf("nemo guardrails: API error (%d): %s", resp.StatusCode, string(body))
	}
}

// ClearHistory is a no-op for NeMo Guardrails generator (stateless per call).
func (g *NeMoGuardrails) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *NeMoGuardrails) Name() string {
	return "guardrails.NeMoGuardrails"
}

// Description returns a human-readable description.
func (g *NeMoGuardrails) Description() string {
	return "NeMo Guardrails generator for adding programmable guardrails to LLM conversations"
}

// Response types for parsing NeMo Guardrails API responses.

// apiResponse represents the API response structure.
type apiResponse struct {
	Messages []message `json:"messages"`
}

// message represents a single message in the response.
type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
