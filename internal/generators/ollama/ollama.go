// Package ollama provides Ollama generators for Augustus.
//
// This package implements the Generator interface for local Ollama instances.
// It supports both the generate endpoint (text completion) and chat endpoint
// (multi-turn conversation).
//
// Ollama runs LLMs locally, making it ideal for:
// - Privacy-sensitive testing (no data leaves your machine)
// - Cost-free testing after hardware investment
// - Offline development and testing
//
// Model names can be passed in short form like "llama2" or specific versions
// like "gemma:7b" or "llama2:latest".
package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("ollama.Ollama", NewOllama)
	generators.Register("ollama.OllamaChat", NewOllamaChat)
}

// Default configuration values matching Python's garak.
const (
	DefaultHost    = "http://127.0.0.1:11434"
	DefaultTimeout = 30 // seconds
)

// ollamaOptions represents the options passed to Ollama API.
type ollamaOptions struct {
	Temperature *float64 `json:"temperature,omitempty"`
	TopP        *float64 `json:"top_p,omitempty"`
	TopK        *int     `json:"top_k,omitempty"`
	NumPredict  *int     `json:"num_predict,omitempty"`
}

// generateRequest is the request body for /api/generate.
type generateRequest struct {
	Model   string         `json:"model"`
	Prompt  string         `json:"prompt"`
	Stream  bool           `json:"stream"`
	Options *ollamaOptions `json:"options,omitempty"`
}

// generateResponse is the response from /api/generate.
type generateResponse struct {
	Model     string `json:"model"`
	Response  string `json:"response"`
	Done      bool   `json:"done"`
	Error     string `json:"error,omitempty"`
}

// chatMessage represents a message in a chat conversation.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatRequest is the request body for /api/chat.
type chatRequest struct {
	Model    string         `json:"model"`
	Messages []chatMessage  `json:"messages"`
	Stream   bool           `json:"stream"`
	Options  *ollamaOptions `json:"options,omitempty"`
}

// chatResponse is the response from /api/chat.
type chatResponse struct {
	Model   string      `json:"model"`
	Message chatMessage `json:"message"`
	Done    bool        `json:"done"`
	Error   string      `json:"error,omitempty"`
}

// baseConfig holds common configuration for both Ollama generators.
type baseConfig struct {
	host        string
	model       string
	timeout     time.Duration
	httpClient  *http.Client
	temperature *float64
	topP        *float64
	topK        *int
	numPredict  *int
}

// parseBaseConfig extracts common configuration from registry.Config.
func parseBaseConfig(cfg registry.Config) (*baseConfig, error) {
	bc := &baseConfig{
		host:    DefaultHost,
		timeout: DefaultTimeout * time.Second,
	}

	// Required: model name
	model, ok := cfg["model"].(string)
	if !ok || model == "" {
		return nil, fmt.Errorf("ollama generator requires 'model' configuration")
	}
	bc.model = model

	// Host: from config or env var
	if host, ok := cfg["host"].(string); ok && host != "" {
		bc.host = host
	} else if envHost := os.Getenv("OLLAMA_HOST"); envHost != "" {
		bc.host = envHost
	}

	// Ensure host doesn't have trailing slash
	bc.host = strings.TrimSuffix(bc.host, "/")

	// Timeout: from config (in seconds)
	if timeout, ok := cfg["timeout"].(int); ok && timeout > 0 {
		bc.timeout = time.Duration(timeout) * time.Second
	} else if timeout, ok := cfg["timeout"].(float64); ok && timeout > 0 {
		bc.timeout = time.Duration(timeout) * time.Second
	}

	// Create HTTP client with timeout
	bc.httpClient = &http.Client{
		Timeout: bc.timeout,
	}

	// Optional generation parameters
	if temp, ok := cfg["temperature"].(float64); ok {
		bc.temperature = &temp
	}

	if topP, ok := cfg["top_p"].(float64); ok {
		bc.topP = &topP
	}

	if topK, ok := cfg["top_k"].(int); ok {
		bc.topK = &topK
	} else if topK, ok := cfg["top_k"].(float64); ok {
		k := int(topK)
		bc.topK = &k
	}

	if numPredict, ok := cfg["num_predict"].(int); ok {
		bc.numPredict = &numPredict
	} else if numPredict, ok := cfg["num_predict"].(float64); ok {
		np := int(numPredict)
		bc.numPredict = &np
	}

	return bc, nil
}

// buildOptions constructs ollamaOptions from baseConfig.
func (bc *baseConfig) buildOptions() *ollamaOptions {
	if bc.temperature == nil && bc.topP == nil && bc.topK == nil && bc.numPredict == nil {
		return nil
	}

	return &ollamaOptions{
		Temperature: bc.temperature,
		TopP:        bc.topP,
		TopK:        bc.topK,
		NumPredict:  bc.numPredict,
	}
}

// --- Ollama (generate endpoint) ---

// Ollama is a generator that uses Ollama's /api/generate endpoint.
type Ollama struct {
	*baseConfig
}

// NewOllama creates a new Ollama generator using the generate endpoint.
func NewOllama(cfg registry.Config) (generators.Generator, error) {
	bc, err := parseBaseConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &Ollama{baseConfig: bc}, nil
}

// Generate sends the conversation to Ollama's generate endpoint and returns responses.
func (g *Ollama) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	// Get the last prompt from the conversation
	prompt := conv.LastPrompt()

	// Ollama doesn't support n parameter, so we call multiple times
	responses := make([]attempt.Message, 0, n)
	for i := 0; i < n; i++ {
		msg, err := g.callGenerate(ctx, prompt)
		if err != nil {
			return nil, err
		}
		responses = append(responses, msg)
	}

	return responses, nil
}

// callGenerate makes a single call to the generate endpoint.
func (g *Ollama) callGenerate(ctx context.Context, prompt string) (attempt.Message, error) {
	reqBody := generateRequest{
		Model:   g.model,
		Prompt:  prompt,
		Stream:  false,
		Options: g.buildOptions(),
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("ollama: failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.host+"/api/generate", bytes.NewReader(jsonBody))
	if err != nil {
		return attempt.Message{}, fmt.Errorf("ollama: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("ollama: failed to connect to server: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("ollama: failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return attempt.Message{}, fmt.Errorf("ollama: server returned status %d: %s", resp.StatusCode, string(body))
	}

	var genResp generateResponse
	if err := json.Unmarshal(body, &genResp); err != nil {
		return attempt.Message{}, fmt.Errorf("ollama: failed to parse response: %w", err)
	}

	if genResp.Error != "" {
		return attempt.Message{}, fmt.Errorf("ollama: %s", genResp.Error)
	}

	return attempt.NewAssistantMessage(genResp.Response), nil
}

// ClearHistory is a no-op for Ollama generator (stateless per call).
func (g *Ollama) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *Ollama) Name() string {
	return "ollama.Ollama"
}

// Description returns a human-readable description.
func (g *Ollama) Description() string {
	return "Ollama generator using the generate endpoint for text completion"
}

// --- OllamaChat (chat endpoint) ---

// OllamaChat is a generator that uses Ollama's /api/chat endpoint.
type OllamaChat struct {
	*baseConfig
}

// NewOllamaChat creates a new Ollama generator using the chat endpoint.
func NewOllamaChat(cfg registry.Config) (generators.Generator, error) {
	bc, err := parseBaseConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &OllamaChat{baseConfig: bc}, nil
}

// Generate sends the conversation to Ollama's chat endpoint and returns responses.
func (g *OllamaChat) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	// Convert conversation to Ollama messages format
	messages := g.conversationToMessages(conv)

	// Ollama doesn't support n parameter, so we call multiple times
	responses := make([]attempt.Message, 0, n)
	for i := 0; i < n; i++ {
		msg, err := g.callChat(ctx, messages)
		if err != nil {
			return nil, err
		}
		responses = append(responses, msg)
	}

	return responses, nil
}

// conversationToMessages converts an Augustus Conversation to Ollama messages.
func (g *OllamaChat) conversationToMessages(conv *attempt.Conversation) []chatMessage {
	messages := make([]chatMessage, 0)

	// Add system message if present
	if conv.System != nil {
		messages = append(messages, chatMessage{
			Role:    "system",
			Content: conv.System.Content,
		})
	}

	// Add turns
	for _, turn := range conv.Turns {
		// Add user message
		messages = append(messages, chatMessage{
			Role:    "user",
			Content: turn.Prompt.Content,
		})

		// Add assistant response if present
		if turn.Response != nil {
			messages = append(messages, chatMessage{
				Role:    "assistant",
				Content: turn.Response.Content,
			})
		}
	}

	return messages
}

// callChat makes a single call to the chat endpoint.
func (g *OllamaChat) callChat(ctx context.Context, messages []chatMessage) (attempt.Message, error) {
	reqBody := chatRequest{
		Model:    g.model,
		Messages: messages,
		Stream:   false,
		Options:  g.buildOptions(),
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("ollama: failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.host+"/api/chat", bytes.NewReader(jsonBody))
	if err != nil {
		return attempt.Message{}, fmt.Errorf("ollama: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("ollama: failed to connect to server: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("ollama: failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return attempt.Message{}, fmt.Errorf("ollama: server returned status %d: %s", resp.StatusCode, string(body))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return attempt.Message{}, fmt.Errorf("ollama: failed to parse response: %w", err)
	}

	if chatResp.Error != "" {
		return attempt.Message{}, fmt.Errorf("ollama: %s", chatResp.Error)
	}

	return attempt.NewAssistantMessage(chatResp.Message.Content), nil
}

// ClearHistory is a no-op for OllamaChat generator (stateless per call).
func (g *OllamaChat) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *OllamaChat) Name() string {
	return "ollama.OllamaChat"
}

// Description returns a human-readable description.
func (g *OllamaChat) Description() string {
	return "Ollama generator using the chat endpoint for multi-turn conversations"
}
