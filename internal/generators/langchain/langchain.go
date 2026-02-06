// Package langchain provides a LangChain generator for Augustus.
//
// This package wraps LangChain LLM interfaces via their HTTP REST endpoint.
// LangChain models are typically served via langchain serve and expose an
// invoke endpoint that accepts prompts and returns responses.
package langchain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("langchain.LangChain", NewLangChain)
}

// LangChain is a generator that wraps LangChain LLM interfaces via REST API.
// It calls the invoke() method on the LangChain endpoint.
type LangChain struct {
	uri    string
	client *http.Client
}

// NewLangChain creates a new LangChain generator from configuration.
func NewLangChain(cfg registry.Config) (generators.Generator, error) {
	l := &LangChain{}

	// Required: URI
	if uri, ok := cfg["uri"].(string); ok && uri != "" {
		// Validate URI
		if _, err := url.Parse(uri); err != nil {
			return nil, fmt.Errorf("langchain: invalid URI: %w", err)
		}
		l.uri = uri
	} else {
		return nil, fmt.Errorf("langchain generator requires 'uri' configuration")
	}

	// Create HTTP client
	l.client = &http.Client{
		Timeout: 30 * time.Second,
	}

	return l, nil
}

// Generate sends the conversation to the LangChain endpoint and returns the response.
// Note: LangChain's invoke() method does not support n>1, so we only make one call.
func (l *LangChain) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	// LangChain invoke() does not support multiple generations
	// We call it once regardless of n value
	msg, err := l.callInvoke(ctx, conv)
	if err != nil {
		return nil, err
	}

	return []attempt.Message{msg}, nil
}

// callInvoke makes a single API call to the LangChain invoke endpoint.
func (l *LangChain) callInvoke(ctx context.Context, conv *attempt.Conversation) (attempt.Message, error) {
	// Convert conversation to LangChain format
	// LangChain expects: {"input": "prompt text"} or messages array
	prompt := conv.LastPrompt()

	reqBody := map[string]any{
		"input": prompt,
	}

	// For multi-turn conversations, pass messages
	if len(conv.Turns) > 1 || conv.System != nil {
		reqBody["input"] = conv.ToMessages()
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("langchain: failed to marshal request: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", l.uri, strings.NewReader(string(jsonData)))
	if err != nil {
		return attempt.Message{}, fmt.Errorf("langchain: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := l.client.Do(req)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("langchain: request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return attempt.Message{}, fmt.Errorf("langchain: API error %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("langchain: failed to read response: %w", err)
	}

	// LangChain invoke() typically returns: {"content": "response text"}
	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return attempt.Message{}, fmt.Errorf("langchain: failed to parse response: %w", err)
	}

	// Extract content
	content, ok := result["content"].(string)
	if !ok {
		return attempt.Message{}, fmt.Errorf("langchain: response missing 'content' field")
	}

	return attempt.NewAssistantMessage(content), nil
}

// ClearHistory is a no-op for LangChain generator (stateless per call).
func (l *LangChain) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (l *LangChain) Name() string {
	return "langchain.LangChain"
}

// Description returns a human-readable description.
func (l *LangChain) Description() string {
	return "LangChain LLM generator via REST invoke endpoint"
}
