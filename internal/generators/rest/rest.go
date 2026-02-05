// Package rest provides a generic REST API generator for Augustus.
//
// This package implements the Generator interface for making HTTP requests to
// REST APIs. It supports configurable endpoints, HTTP methods, request templates
// with variable substitution, and flexible response parsing including JSONPath.
package rest

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/ratelimit"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"golang.org/x/net/http2"
)

func init() {
	generators.Register("rest.Rest", NewRest)
}

// defaultTransport returns an http.Transport configured for connection pooling.
// This prevents connection exhaustion under high-concurrency scanning.
// If proxyURL is provided, configures the transport to use the proxy.
func defaultTransport(proxyURL *url.URL) *http.Transport {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		MaxConnsPerHost:     100,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	}

	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
		// For proxy inspection tools like Burp Suite, disable TLS verification
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	// Enable HTTP/2 support
	http2.ConfigureTransport(transport)

	return transport
}

// Rest is a generic REST API generator that makes HTTP requests to configured endpoints.
// It supports request templating, JSON response parsing, and various HTTP methods.
type Rest struct {
	uri               string
	method            string
	headers           map[string]string
	reqTemplate       string
	responseJSON      bool
	responseJSONField string
	requestTimeout    time.Duration
	rateLimitCodes    map[int]bool
	skipCodes         map[int]bool
	apiKey            string
	proxyURL          *url.URL
	client            *http.Client
	limiter           *ratelimit.Limiter // Pre-request rate limiter
}

// NewRest creates a new REST generator from configuration.
func NewRest(cfg registry.Config) (generators.Generator, error) {
	r := &Rest{
		method:         "POST",
		reqTemplate:    "$INPUT",
		requestTimeout: 20 * time.Second,
		headers:        make(map[string]string),
		rateLimitCodes: map[int]bool{429: true},
		skipCodes:      make(map[int]bool),
	}

	// Required: URI
	if uri, ok := cfg["uri"].(string); ok && uri != "" {
		r.uri = uri
	} else {
		return nil, fmt.Errorf("rest generator requires 'uri' configuration")
	}

	// Optional: HTTP method
	if method, ok := cfg["method"].(string); ok && method != "" {
		r.method = strings.ToUpper(method)
		// Validate method
		validMethods := map[string]bool{
			"GET": true, "POST": true, "PUT": true, "PATCH": true,
			"DELETE": true, "HEAD": true, "OPTIONS": true,
		}
		if !validMethods[r.method] {
			r.method = "POST" // Default to POST for invalid methods
		}
	}

	// Optional: Headers
	if headers, ok := cfg["headers"].(map[string]any); ok {
		for k, v := range headers {
			if vs, ok := v.(string); ok {
				r.headers[k] = vs
			}
		}
	}

	// Optional: Request template
	if tmpl, ok := cfg["req_template"].(string); ok {
		r.reqTemplate = tmpl
	}

	// Optional: JSON request template object
	if tmplObj, ok := cfg["req_template_json_object"].(map[string]any); ok {
		data, err := json.Marshal(tmplObj)
		if err == nil {
			r.reqTemplate = string(data)
		}
	}

	// Optional: Response parsing
	if responseJSON, ok := cfg["response_json"].(bool); ok {
		r.responseJSON = responseJSON
	}
	if responseJSONField, ok := cfg["response_json_field"].(string); ok {
		r.responseJSONField = responseJSONField
	}

	// Validate JSON response configuration
	if r.responseJSON {
		if r.responseJSONField == "" {
			return nil, fmt.Errorf("rest generator: response_json is true but response_json_field is not set")
		}
	}

	// Optional: Timeout
	if timeout, ok := cfg["request_timeout"].(float64); ok {
		r.requestTimeout = time.Duration(timeout * float64(time.Second))
	} else if timeout, ok := cfg["request_timeout"].(int); ok {
		r.requestTimeout = time.Duration(timeout) * time.Second
	}

	// Optional: Rate limit codes
	if codes, ok := cfg["ratelimit_codes"].([]any); ok {
		r.rateLimitCodes = make(map[int]bool)
		for _, c := range codes {
			if code, ok := c.(int); ok {
				r.rateLimitCodes[code] = true
			} else if code, ok := c.(float64); ok {
				r.rateLimitCodes[int(code)] = true
			}
		}
	}

	// Optional: Skip codes
	if codes, ok := cfg["skip_codes"].([]any); ok {
		for _, c := range codes {
			if code, ok := c.(int); ok {
				r.skipCodes[code] = true
			} else if code, ok := c.(float64); ok {
				r.skipCodes[int(code)] = true
			}
		}
	}

	// Optional: API key
	if apiKey, ok := cfg["api_key"].(string); ok {
		r.apiKey = apiKey
	}

	// Optional: Proxy configuration
	var proxyURL *url.URL
	if proxyStr, ok := cfg["proxy"].(string); ok && proxyStr != "" {
		var err error
		proxyURL, err = url.Parse(proxyStr)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
	} else {
		// Fall back to environment variables (check both case variants)
		if envProxy := os.Getenv("HTTPS_PROXY"); envProxy != "" {
			proxyURL, _ = url.Parse(envProxy)
		} else if envProxy := os.Getenv("https_proxy"); envProxy != "" {
			proxyURL, _ = url.Parse(envProxy)
		} else if envProxy := os.Getenv("HTTP_PROXY"); envProxy != "" {
			proxyURL, _ = url.Parse(envProxy)
		} else if envProxy := os.Getenv("http_proxy"); envProxy != "" {
			proxyURL, _ = url.Parse(envProxy)
		}
	}
	r.proxyURL = proxyURL

	// Optional: Rate limiting (requests per second)
	// Supports both float64 (from JSON) and int
	if rateLimit, ok := cfg["rate_limit"].(float64); ok && rateLimit > 0 {
		// Token bucket: capacity must be >= 1.0 to allow at least one request
		// For rates < 1.0, we still need capacity for 1 token, but refill slowly
		capacity := rateLimit
		if capacity < 1.0 {
			capacity = 1.0 // Ensure we can always make at least one request
		}
		r.limiter = ratelimit.NewLimiter(capacity, rateLimit)
	} else if rateLimit, ok := cfg["rate_limit"].(int); ok && rateLimit > 0 {
		r.limiter = ratelimit.NewLimiter(float64(rateLimit), float64(rateLimit))
	}

	// Create HTTP client
	r.client = &http.Client{
		Transport: defaultTransport(r.proxyURL),
		Timeout:   r.requestTimeout,
	}

	return r, nil
}

// Generate sends the conversation's last prompt to the REST API and returns responses.
func (r *Rest) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		n = 1
	}

	responses := make([]attempt.Message, 0, n)

	for i := 0; i < n; i++ {
		msg, err := r.callAPI(ctx, conv)
		if err != nil {
			return nil, err
		}
		responses = append(responses, msg)
	}

	return responses, nil
}

// callAPI makes a single API call and returns the response.
func (r *Rest) callAPI(ctx context.Context, conv *attempt.Conversation) (attempt.Message, error) {
	// Apply rate limiting if configured
	if r.limiter != nil {
		if err := r.limiter.Wait(ctx); err != nil {
			return attempt.Message{}, fmt.Errorf("rest: rate limit wait cancelled: %w", err)
		}
	}

	prompt := conv.LastPrompt()

	// Populate request template
	body := r.populateTemplate(r.reqTemplate, prompt)

	// Populate headers
	headers := make(map[string]string)
	for k, v := range r.headers {
		headers[k] = r.populateTemplate(v, prompt)
	}

	// Create request
	var req *http.Request
	var err error

	if r.method == "GET" {
		// For GET requests, append to URL as query params
		req, err = http.NewRequestWithContext(ctx, r.method, r.uri+"?"+body, nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, r.method, r.uri, bytes.NewBufferString(body))
	}
	if err != nil {
		return attempt.Message{}, fmt.Errorf("rest: failed to create request: %w", err)
	}

	// Set headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Execute request
	resp, err := r.client.Do(req)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("rest: request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle skip codes
	if r.skipCodes[resp.StatusCode] {
		return attempt.NewAssistantMessage(""), nil
	}

	// Handle rate limit codes
	if r.rateLimitCodes[resp.StatusCode] {
		return attempt.Message{}, fmt.Errorf("rest: rate limited: %d %s", resp.StatusCode, resp.Status)
	}

	// Handle client errors (4xx)
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return attempt.Message{}, fmt.Errorf("rest: client error: %d %s", resp.StatusCode, resp.Status)
	}

	// Handle server errors (5xx)
	if resp.StatusCode >= 500 {
		return attempt.Message{}, fmt.Errorf("rest: server error: %d %s", resp.StatusCode, resp.Status)
	}

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("rest: failed to read response: %w", err)
	}

	// Check if response is SSE (Server-Sent Events)
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/event-stream") {
		// Parse SSE format
		content := r.parseSSE(respBody)
		return attempt.NewAssistantMessage(content), nil
	}

	// Parse response normally
	content, err := r.parseResponse(respBody)
	if err != nil {
		return attempt.Message{}, err
	}

	return attempt.NewAssistantMessage(content), nil
}

// populateTemplate replaces $INPUT and $KEY placeholders in the template.
func (r *Rest) populateTemplate(template, input string) string {
	result := template

	// Replace $KEY with API key
	if strings.Contains(result, "$KEY") && r.apiKey != "" {
		result = strings.ReplaceAll(result, "$KEY", r.apiKey)
	}

	// Replace $INPUT with JSON-escaped input
	if strings.Contains(result, "$INPUT") {
		escaped := jsonEscape(input)
		result = strings.ReplaceAll(result, "$INPUT", escaped)
	}

	return result
}

// jsonEscape escapes a string for use in JSON.
func jsonEscape(s string) string {
	// Use json.Marshal and trim the surrounding quotes
	data, err := json.Marshal(s)
	if err != nil {
		return s
	}
	// Remove surrounding quotes
	return string(data[1 : len(data)-1])
}

// parseResponse extracts the response content based on configuration.
func (r *Rest) parseResponse(body []byte) (string, error) {
	if !r.responseJSON {
		return string(body), nil
	}

	// Parse JSON response
	var data any
	if err := json.Unmarshal(body, &data); err != nil {
		return "", fmt.Errorf("rest: failed to parse JSON response: %w", err)
	}

	// Extract field using simple path or JSONPath
	return r.extractField(data, r.responseJSONField)
}

// extractField extracts a value from JSON data using a field path or JSONPath.
func (r *Rest) extractField(data any, field string) (string, error) {
	// Check if it's a JSONPath (starts with $)
	if strings.HasPrefix(field, "$") {
		return r.evaluateJSONPath(data, field)
	}

	// Simple field extraction
	return r.extractSimpleField(data, field)
}

// extractSimpleField extracts a simple field from the data.
func (r *Rest) extractSimpleField(data any, field string) (string, error) {
	switch d := data.(type) {
	case map[string]any:
		if val, ok := d[field]; ok {
			return valueToString(val), nil
		}
		return "", fmt.Errorf("rest: field %q not found in response", field)

	case []any:
		if len(d) == 0 {
			return "", fmt.Errorf("rest: empty array response")
		}
		// Extract from first element
		if obj, ok := d[0].(map[string]any); ok {
			if val, ok := obj[field]; ok {
				return valueToString(val), nil
			}
		}
		return "", fmt.Errorf("rest: field %q not found in array response", field)

	default:
		return "", fmt.Errorf("rest: unexpected response type %T", data)
	}
}

// evaluateJSONPath evaluates a JSONPath expression against the data.
// Supports basic JSONPath: $.field.nested, $[0].field, $.field[*]
func (r *Rest) evaluateJSONPath(data any, path string) (string, error) {
	// Remove leading $
	path = strings.TrimPrefix(path, "$")
	if path == "" {
		return valueToString(data), nil
	}

	// Parse path segments
	segments := parseJSONPath(path)

	current := data
	for _, seg := range segments {
		var err error
		current, err = navigateSegment(current, seg)
		if err != nil {
			return "", err
		}
	}

	return valueToString(current), nil
}

// parseJSONPath splits a JSONPath into segments.
func parseJSONPath(path string) []string {
	var segments []string
	var current strings.Builder

	for i := 0; i < len(path); i++ {
		c := path[i]
		switch c {
		case '.':
			if current.Len() > 0 {
				segments = append(segments, current.String())
				current.Reset()
			}
		case '[':
			if current.Len() > 0 {
				segments = append(segments, current.String())
				current.Reset()
			}
			// Find matching ]
			j := i + 1
			for j < len(path) && path[j] != ']' {
				j++
			}
			if j < len(path) {
				segments = append(segments, "["+path[i+1:j]+"]")
				i = j
			}
		default:
			current.WriteByte(c)
		}
	}

	if current.Len() > 0 {
		segments = append(segments, current.String())
	}

	return segments
}

// navigateSegment navigates one segment of a JSONPath.
func navigateSegment(data any, seg string) (any, error) {
	// Array index: [0], [1], etc.
	if strings.HasPrefix(seg, "[") && strings.HasSuffix(seg, "]") {
		idx := seg[1 : len(seg)-1]
		arr, ok := data.([]any)
		if !ok {
			return nil, fmt.Errorf("rest: expected array for index %s", seg)
		}
		var i int
		if _, err := fmt.Sscanf(idx, "%d", &i); err != nil {
			return nil, fmt.Errorf("rest: invalid array index %s", seg)
		}
		if i < 0 || i >= len(arr) {
			return nil, fmt.Errorf("rest: array index %d out of bounds", i)
		}
		return arr[i], nil
	}

	// Object field
	obj, ok := data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("rest: expected object for field %s", seg)
	}
	val, ok := obj[seg]
	if !ok {
		return nil, fmt.Errorf("rest: field %q not found", seg)
	}
	return val, nil
}

// valueToString converts a value to string.
func valueToString(val any) string {
	switch v := val.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%v", v)
	case bool:
		return fmt.Sprintf("%v", v)
	case nil:
		return ""
	default:
		// For complex types, marshal to JSON
		data, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(data)
	}
}

// parseSSE extracts text content from Server-Sent Events (SSE) format.
// SSE format: data: {...}\n\ndata: {...}\n\n
func (r *Rest) parseSSE(body []byte) string {
	var textParts []string
	lines := strings.Split(string(body), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// SSE data lines start with "data:"
		if !strings.HasPrefix(line, "data:") {
			continue
		}

		// Remove "data:" prefix
		jsonStr := strings.TrimPrefix(line, "data:")
		jsonStr = strings.TrimSpace(jsonStr)

		if jsonStr == "" {
			continue
		}

		// Try to parse as JSON
		var data map[string]any
		if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
			// Not valid JSON, skip
			continue
		}

		// Extract text from various possible structures
		if delta, ok := data["delta"].(map[string]any); ok {
			if text, ok := delta["text"].(string); ok && text != "" {
				textParts = append(textParts, text)
			}
		}

		// Alternative: {"message":{"parts":[{"text":"..."}]}}
		if message, ok := data["message"].(map[string]any); ok {
			if parts, ok := message["parts"].([]any); ok {
				for _, part := range parts {
					if partMap, ok := part.(map[string]any); ok {
						if text, ok := partMap["text"].(string); ok && text != "" {
							textParts = append(textParts, text)
						}
					}
				}
			}
		}

		// Direct text field
		if text, ok := data["text"].(string); ok && text != "" {
			textParts = append(textParts, text)
		}

		// Content field
		if content, ok := data["content"].(string); ok && content != "" {
			textParts = append(textParts, content)
		}
	}

	// Join all extracted text
	if len(textParts) > 0 {
		return strings.Join(textParts, "")
	}

	// Fallback: return raw body if no text extracted
	return string(body)
}

// ClearHistory is a no-op for REST generator (stateless).
func (r *Rest) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (r *Rest) Name() string {
	return "rest.Rest"
}

// Description returns a human-readable description.
func (r *Rest) Description() string {
	return "Generic REST API generator for HTTP-based LLM endpoints with SSE support"
}
