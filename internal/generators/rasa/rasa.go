// Package rasa provides a Rasa REST API generator for Augustus.
//
// This package implements the Generator interface for Rasa chatbot framework,
// which uses a REST API at /webhooks/rest/webhook with a simple request/response format.
package rasa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("rasa.RasaRest", NewRasaRest)
}

// Config holds the configuration for Rasa REST generator.
type Config struct {
	BaseURL string
	Model   string
	Sender  string
}

// RasaRest is a generator for Rasa chatbot framework REST API.
type RasaRest struct {
	baseURL string
	model   string
	sender  string
	client  *http.Client
}

// NewRasaRest creates a new Rasa REST generator from configuration.
func NewRasaRest(cfg registry.Config) (generators.Generator, error) {
	// Extract base_url (required)
	baseURL, ok := cfg["base_url"].(string)
	if !ok || baseURL == "" {
		return nil, fmt.Errorf("rasa generator requires 'base_url' configuration")
	}

	// Extract model (required)
	model, ok := cfg["model"].(string)
	if !ok || model == "" {
		return nil, fmt.Errorf("rasa generator requires 'model' configuration")
	}

	// Extract sender (required)
	sender, ok := cfg["sender"].(string)
	if !ok || sender == "" {
		return nil, fmt.Errorf("rasa generator requires 'sender' configuration")
	}

	return &RasaRest{
		baseURL: baseURL,
		model:   model,
		sender:  sender,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// NewRasaRestTyped creates a new Rasa REST generator from typed configuration.
func NewRasaRestTyped(cfg Config) (*RasaRest, error) {
	// Validate required fields
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("rasa generator requires 'base_url' configuration")
	}
	if cfg.Model == "" {
		return nil, fmt.Errorf("rasa generator requires 'model' configuration")
	}
	if cfg.Sender == "" {
		return nil, fmt.Errorf("rasa generator requires 'sender' configuration")
	}

	return &RasaRest{
		baseURL: cfg.BaseURL,
		model:   cfg.Model,
		sender:  cfg.Sender,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// rasaRequest represents the Rasa REST API request format.
type rasaRequest struct {
	Sender  string `json:"sender"`
	Message string `json:"message"`
}

// rasaResponse represents the Rasa REST API response format.
type rasaResponse struct {
	Text string `json:"text"`
}

// Generate sends the conversation's last prompt to Rasa and returns responses.
func (r *RasaRest) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	prompt := conv.LastPrompt()

	// Create request
	reqBody := rasaRequest{
		Sender:  r.sender,
		Message: prompt,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("rasa: failed to marshal request: %w", err)
	}

	// Build URL
	url := r.baseURL + "/webhooks/rest/webhook"

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("rasa: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rasa: request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("rasa: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("rasa: failed to read response: %w", err)
	}

	// Parse response array
	var rasaResponses []rasaResponse
	if err := json.Unmarshal(respBody, &rasaResponses); err != nil {
		return nil, fmt.Errorf("rasa: failed to parse response: %w", err)
	}

	// Convert to messages (Rasa returns array, we return all responses)
	messages := make([]attempt.Message, 0, len(rasaResponses))
	for _, r := range rasaResponses {
		messages = append(messages, attempt.NewAssistantMessage(r.Text))
	}

	return messages, nil
}

// ClearHistory is a no-op for Rasa generator (stateless).
func (r *RasaRest) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (r *RasaRest) Name() string {
	return "rasa.RasaRest"
}

// Description returns a human-readable description.
func (r *RasaRest) Description() string {
	return "Rasa chatbot framework REST API generator"
}
