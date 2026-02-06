// Package langchainserve provides a LangChain Serve generator for Augustus.
//
// This package wraps LangChain Serve applications exposed via HTTP REST endpoint.
// LangChain Serve applications expose an /invoke endpoint that accepts prompts
// in a specific format and returns responses.
package langchainserve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("langchain_serve.LangChainServe", NewLangChainServe)
}

// LangChainServe is a generator that wraps LangChain Serve applications via REST API.
// It calls the /invoke endpoint on the LangChain Serve application.
type LangChainServe struct {
	baseURL    string
	configHash string
	headers    map[string]string
	client     *http.Client
}

// NewLangChainServe creates a new LangChainServe generator from configuration.
func NewLangChainServe(cfg registry.Config) (generators.Generator, error) {
	ls := &LangChainServe{}

	// Required: base_url
	baseURL, ok := cfg["base_url"].(string)
	if !ok || baseURL == "" {
		return nil, fmt.Errorf("langchain_serve generator requires 'base_url' configuration")
	}

	// Validate base_url
	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("langchain_serve: invalid base_url: %w", err)
	}
	ls.baseURL = baseURL

	// Optional: config_hash
	if configHash, ok := cfg["config_hash"].(string); ok {
		ls.configHash = configHash
	}

	// Optional: headers
	if headers, ok := cfg["headers"].(map[string]any); ok {
		ls.headers = make(map[string]string)
		for k, v := range headers {
			if strVal, ok := v.(string); ok {
				ls.headers[k] = strVal
			}
		}
	}

	// Optional: timeout (default 30 seconds)
	timeout := 30 * time.Second
	if timeoutVal, ok := cfg["timeout"].(int); ok {
		timeout = time.Duration(timeoutVal) * time.Second
	}

	// Create HTTP client
	ls.client = &http.Client{
		Timeout: timeout,
	}

	return ls, nil
}

// Generate sends the conversation to the LangChain Serve endpoint and returns the response.
// Note: LangChain Serve's invoke endpoint does not support n>1, so we only make one call.
func (ls *LangChainServe) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	// LangChain Serve invoke does not support multiple generations
	// We call it once regardless of n value
	msg, err := ls.callInvoke(ctx, conv)
	if err != nil {
		return nil, err
	}

	return []attempt.Message{msg}, nil
}

// callInvoke makes a single API call to the LangChain Serve /invoke endpoint.
func (ls *LangChainServe) callInvoke(ctx context.Context, conv *attempt.Conversation) (attempt.Message, error) {
	// Convert conversation to LangChain Serve format
	// LangChain Serve expects: {"input": "prompt", "config": {}, "kwargs": {}}
	prompt := conv.LastPrompt()

	reqBody := map[string]any{
		"input":  prompt,
		"config": map[string]any{},
		"kwargs": map[string]any{},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("langchain_serve: failed to marshal request: %w", err)
	}

	// Build URL with config_hash query parameter if provided
	invokeURL := ls.baseURL + "/invoke"
	if ls.configHash != "" {
		parsedURL, _ := url.Parse(invokeURL)
		q := parsedURL.Query()
		q.Set("config_hash", ls.configHash)
		parsedURL.RawQuery = q.Encode()
		invokeURL = parsedURL.String()
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", invokeURL, bytes.NewReader(jsonData))
	if err != nil {
		return attempt.Message{}, fmt.Errorf("langchain_serve: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Add custom headers
	for k, v := range ls.headers {
		req.Header.Set(k, v)
	}

	// Execute request
	resp, err := ls.client.Do(req)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("langchain_serve: request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return attempt.Message{}, fmt.Errorf("langchain_serve: API error %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("langchain_serve: failed to read response: %w", err)
	}

	// LangChain Serve returns: {"output": ["response text"]}
	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return attempt.Message{}, fmt.Errorf("langchain_serve: failed to parse response: %w", err)
	}

	// Extract output array
	output, ok := result["output"].([]any)
	if !ok || len(output) == 0 {
		return attempt.Message{}, fmt.Errorf("langchain_serve: response missing 'output' field or empty array")
	}

	// Extract first element of output array
	content, ok := output[0].(string)
	if !ok {
		return attempt.Message{}, fmt.Errorf("langchain_serve: output[0] is not a string")
	}

	return attempt.NewAssistantMessage(content), nil
}

// ClearHistory is a no-op for LangChain Serve generator (stateless per call).
func (ls *LangChainServe) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (ls *LangChainServe) Name() string {
	return "langchain_serve.LangChainServe"
}

// Description returns a human-readable description.
func (ls *LangChainServe) Description() string {
	return "LangChain Serve application generator via REST /invoke endpoint"
}
