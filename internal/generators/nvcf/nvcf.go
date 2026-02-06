// Package nvcf provides NVIDIA Cloud Functions generators for Augustus.
//
// This package implements the Generator interface for NVIDIA Cloud Functions (NVCF),
// supporting both chat and completion modes with configurable function IDs.
package nvcf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

const (
	// DefaultBaseURL is the default NVCF API base URL.
	DefaultBaseURL = "https://api.nvcf.nvidia.com/v2/nvcf/pexec/functions"
)

func init() {
	generators.Register("nvcf.NvcfChat", NewNvcfChat)
	generators.Register("nvcf.NvcfCompletion", NewNvcfCompletion)
}

// NvcfChat is a generator for NVCF chat completion models.
type NvcfChat struct {
	client     *http.Client
	functionID string
	apiKey     string
	baseURL    string

	// Configuration parameters
	temperature float32
	maxTokens   int
	topP        float32
	model       string
}

// NewNvcfChat creates a new NvcfChat generator from configuration.
func NewNvcfChat(cfg registry.Config) (generators.Generator, error) {
	g := &NvcfChat{
		client:      &http.Client{},
		temperature: 0.7,
	}

	functionID, ok := cfg["function_id"].(string)
	if !ok || functionID == "" {
		return nil, fmt.Errorf("nvcf generator requires 'function_id' configuration")
	}
	g.functionID = functionID

	apiKey := ""
	if key, ok := cfg["api_key"].(string); ok && key != "" {
		apiKey = key
	} else {
		apiKey = os.Getenv("NVCF_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("nvcf generator requires 'api_key' configuration or NVCF_API_KEY environment variable")
	}
	g.apiKey = apiKey

	if baseURL, ok := cfg["base_url"].(string); ok && baseURL != "" {
		g.baseURL = baseURL
	} else {
		g.baseURL = DefaultBaseURL
	}

	if model, ok := cfg["model"].(string); ok && model != "" {
		g.model = model
	}

	if temp, ok := cfg["temperature"].(float64); ok {
		g.temperature = float32(temp)
	}

	if maxTokens, ok := cfg["max_tokens"].(int); ok {
		g.maxTokens = maxTokens
	} else if maxTokens, ok := cfg["max_tokens"].(float64); ok {
		g.maxTokens = int(maxTokens)
	}

	if topP, ok := cfg["top_p"].(float64); ok {
		g.topP = float32(topP)
	}

	return g, nil
}

// Generate sends the conversation to NVCF and returns responses.
func (g *NvcfChat) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}
	return g.generateChat(ctx, conv, n)
}

func (g *NvcfChat) generateChat(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	messages := g.conversationToMessages(conv)

	payload := map[string]any{
		"messages": messages,
	}

	if g.temperature != 0 {
		payload["temperature"] = g.temperature
	}
	if g.maxTokens > 0 {
		payload["max_tokens"] = g.maxTokens
	}
	if g.topP != 0 {
		payload["top_p"] = g.topP
	}
	if g.model != "" {
		payload["model"] = g.model
	}
	payload["stream"] = false

	url := fmt.Sprintf("%s/%s", g.baseURL, g.functionID)
	resp, err := g.makeRequest(ctx, url, payload)
	if err != nil {
		return nil, err
	}

	choices, ok := resp["choices"].([]any)
	if !ok {
		return nil, fmt.Errorf("nvcf: invalid response format - missing choices")
	}

	responses := make([]attempt.Message, 0, len(choices))
	for _, choice := range choices {
		choiceMap, ok := choice.(map[string]any)
		if !ok {
			continue
		}
		message, ok := choiceMap["message"].(map[string]any)
		if !ok {
			continue
		}
		content, ok := message["content"].(string)
		if !ok {
			continue
		}
		responses = append(responses, attempt.NewAssistantMessage(content))
	}

	return responses, nil
}

func (g *NvcfChat) conversationToMessages(conv *attempt.Conversation) []map[string]any {
	messages := make([]map[string]any, 0)

	if conv.System != nil {
		messages = append(messages, map[string]any{
			"role":    "system",
			"content": conv.System.Content,
		})
	}

	for _, turn := range conv.Turns {
		messages = append(messages, map[string]any{
			"role":    "user",
			"content": turn.Prompt.Content,
		})

		if turn.Response != nil {
			messages = append(messages, map[string]any{
				"role":    "assistant",
				"content": turn.Response.Content,
			})
		}
	}

	return messages
}

func (g *NvcfChat) makeRequest(ctx context.Context, url string, payload map[string]any) (map[string]any, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("nvcf: failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("nvcf: failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", g.apiKey))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvcf: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("nvcf: failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("nvcf: API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("nvcf: failed to parse response: %w", err)
	}

	return result, nil
}

func (g *NvcfChat) ClearHistory() {}

func (g *NvcfChat) Name() string {
	return "nvcf.NvcfChat"
}

func (g *NvcfChat) Description() string {
	return "NVIDIA Cloud Functions (NVCF) chat completion generator"
}

// NvcfCompletion is a generator for NVCF text completion models.
type NvcfCompletion struct {
	*NvcfChat
}

func NewNvcfCompletion(cfg registry.Config) (generators.Generator, error) {
	base, err := NewNvcfChat(cfg)
	if err != nil {
		return nil, err
	}

	return &NvcfCompletion{
		NvcfChat: base.(*NvcfChat),
	}, nil
}

func (g *NvcfCompletion) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}
	return g.generateCompletion(ctx, conv, n)
}

func (g *NvcfCompletion) generateCompletion(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	var prompt string
	if len(conv.Turns) > 0 {
		prompt = conv.Turns[len(conv.Turns)-1].Prompt.Content
	}

	payload := map[string]any{
		"prompt": prompt,
	}

	if g.temperature != 0 {
		payload["temperature"] = g.temperature
	}
	if g.maxTokens > 0 {
		payload["max_tokens"] = g.maxTokens
	}
	if g.topP != 0 {
		payload["top_p"] = g.topP
	}
	if g.model != "" {
		payload["model"] = g.model
	}
	payload["stream"] = false

	url := fmt.Sprintf("%s/%s", g.baseURL, g.functionID)
	resp, err := g.makeRequest(ctx, url, payload)
	if err != nil {
		return nil, err
	}

	choices, ok := resp["choices"].([]any)
	if !ok {
		return nil, fmt.Errorf("nvcf: invalid response format - missing choices")
	}

	responses := make([]attempt.Message, 0, len(choices))
	for _, choice := range choices {
		choiceMap, ok := choice.(map[string]any)
		if !ok {
			continue
		}
		text, ok := choiceMap["text"].(string)
		if !ok {
			continue
		}
		responses = append(responses, attempt.NewAssistantMessage(text))
	}

	return responses, nil
}

func (g *NvcfCompletion) Name() string {
	return "nvcf.NvcfCompletion"
}

func (g *NvcfCompletion) Description() string {
	return "NVIDIA Cloud Functions (NVCF) text Completion generator"
}
