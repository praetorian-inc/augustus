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
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/praetorian-inc/augustus/internal/parsers/extract"
	"github.com/praetorian-inc/augustus/internal/parsers/sse"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/hooks"
	"github.com/praetorian-inc/augustus/pkg/ratelimit"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	generators.Register("rest.Rest", NewRest)
}

// defaultTransport returns an http.Transport configured for connection pooling.
// This prevents connection exhaustion under high-concurrency scanning.
// If proxyURL is provided, configures the transport to use the proxy.
// If insecureSkipVerify is true, disables TLS certificate verification.
func defaultTransport(proxyURL *url.URL, insecureSkipVerify bool) *http.Transport {
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
	}
	if insecureSkipVerify {
		transport.TLSClientConfig.InsecureSkipVerify = true
		log.Printf("WARNING: TLS certificate verification disabled (insecure_skip_verify=true)")
	}

	// Enable HTTP/2 support
	_ = http2.ConfigureTransport(transport)

	return transport
}

// Compile-time interface assertions.
var (
	_ generators.Generator      = (*Rest)(nil)
	_ hooks.RawResponseProvider = (*Rest)(nil)
)

// Rest is a generic REST API generator that makes HTTP requests to configured endpoints.
// It supports request templating, JSON response parsing, and various HTTP methods.
type Rest struct {
	uri                string
	method             string
	headers            map[string]string
	reqTemplate        string
	responseJSON       bool
	responseJSONField  string
	requestTimeout     time.Duration
	rateLimitCodes     map[int]bool
	skipCodes          map[int]bool
	apiKey             string
	proxyURL           *url.URL
	insecureSkipVerify bool
	client             *http.Client
	limiter            *ratelimit.Limiter // Pre-request rate limiter

	// Configurable SSE parsing
	sseTextField   string // JSONPath for text extraction (e.g., "$.content.text")
	sseMode        string // "delta" or "last"
	sseFilterField string // JSONPath for event filtering (e.g., "$.content.type")
	sseFilterValue string // Value to match for filter (e.g., "CHAT_TEXT")

	// Raw response storage for runtime hooks
	mu          sync.Mutex // protects lastRawResp
	lastRawResp []byte
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

	// Required: URI (also accept "endpoint" as alias for compatibility with GeneratorConfig)
	if uri, ok := cfg["uri"].(string); ok && uri != "" {
		r.uri = uri
		if endpoint, ok := cfg["endpoint"].(string); ok && endpoint != "" && endpoint != uri {
			slog.Warn("both 'uri' and 'endpoint' specified; using 'uri'",
				"uri", uri, "endpoint", endpoint)
		}
	} else if endpoint, ok := cfg["endpoint"].(string); ok && endpoint != "" {
		r.uri = endpoint
	} else {
		return nil, fmt.Errorf("rest generator requires 'uri' or 'endpoint' configuration")
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

	// Optional: Request template (also accept "body" as alias for compatibility with GeneratorConfig)
	if tmpl, ok := cfg["req_template"].(string); ok {
		r.reqTemplate = tmpl
		if body, ok := cfg["body"].(string); ok && body != tmpl {
			slog.Warn("both 'req_template' and 'body' specified; using 'req_template'",
				"req_template", tmpl, "body", body)
		}
	} else if body, ok := cfg["body"].(string); ok {
		r.reqTemplate = body
	}

	// Optional: JSON request template object
	if tmplObj, ok := cfg["req_template_json_object"].(map[string]any); ok {
		data, err := json.Marshal(tmplObj)
		if err == nil {
			r.reqTemplate = string(data)
		}
	}

	// Optional: Response parsing
	_, responseJSONExplicit := cfg["response_json"].(bool)
	if responseJSON, ok := cfg["response_json"].(bool); ok {
		r.responseJSON = responseJSON
	}
	if responseJSONField, ok := cfg["response_json_field"].(string); ok {
		r.responseJSONField = responseJSONField
		if responsePath, ok := cfg["response_path"].(string); ok && responsePath != responseJSONField {
			slog.Warn("both 'response_json_field' and 'response_path' specified; using 'response_json_field'",
				"response_json_field", responseJSONField, "response_path", responsePath)
		}
	} else if responsePath, ok := cfg["response_path"].(string); ok {
		r.responseJSONField = responsePath
		if responseJSONExplicit && !r.responseJSON {
			slog.Warn("'response_path' would enable JSON parsing, but 'response_json' is explicitly false; respecting 'response_json: false'",
				"response_path", responsePath)
		} else {
			r.responseJSON = true
		}
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

	// Optional: Insecure skip verify
	if insecure, ok := cfg["insecure_skip_verify"].(bool); ok {
		r.insecureSkipVerify = insecure
	}

	// Optional: SSE configuration
	if sseTextField, ok := cfg["sse_text_field"].(string); ok {
		r.sseTextField = sseTextField
	}
	if sseMode, ok := cfg["sse_mode"].(string); ok && sseMode != "" {
		if sseMode != "delta" && sseMode != "last" {
			return nil, fmt.Errorf("sse_mode must be \"delta\" or \"last\", got %q", sseMode)
		}
		r.sseMode = sseMode
	}
	if r.sseTextField != "" && r.sseMode == "" {
		r.sseMode = "delta"
	}
	if sseFilterField, ok := cfg["sse_filter_field"].(string); ok {
		r.sseFilterField = sseFilterField
	}
	if sseFilterValue, ok := cfg["sse_filter_value"].(string); ok {
		r.sseFilterValue = sseFilterValue
	}
	if (r.sseFilterField != "") != (r.sseFilterValue != "") {
		return nil, fmt.Errorf("sse_filter_field and sse_filter_value must both be set or both be empty")
	}

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
		Transport: defaultTransport(r.proxyURL, r.insecureSkipVerify),
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

	// Get hook variables from context for template substitution
	hookVars := types.HookVarsFromContext(ctx)

	// Populate request template
	body := r.populateTemplate(r.reqTemplate, prompt, hookVars)

	// Replace $MESSAGES with full conversation as a JSON array of
	// {"role","content"} objects. Enables multi-turn probes to send
	// conversation history to REST endpoints.
	// Template usage: "messages": $MESSAGES  (no quotes — raw JSON)
	// Replaced after populateTemplate to prevent $INPUT/$KEY substitution
	// inside message content.
	if strings.Contains(body, "$MESSAGES") {
		body = strings.ReplaceAll(body, "$MESSAGES", conversationToJSON(conv))
	}

	// Populate headers
	headers := make(map[string]string)
	for k, v := range r.headers {
		headers[k] = r.populateTemplate(v, prompt, hookVars)
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
	defer func() { _ = resp.Body.Close() }()

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
	// Cap response body to 10MB to prevent OOM from malicious endpoints.
	const maxResponseSize = 10 * 1024 * 1024
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return attempt.Message{}, fmt.Errorf("rest: failed to read response: %w", err)
	}

	// Store raw response for runtime hooks
	r.mu.Lock()
	r.lastRawResp = respBody
	r.mu.Unlock()

	// Check if response is SSE (Server-Sent Events)
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/event-stream") {
		content := sse.Parse(respBody, sse.Options{
			TextField:   r.sseTextField,
			Mode:        r.sseMode,
			FilterField: r.sseFilterField,
			FilterValue: r.sseFilterValue,
		})
		return attempt.NewAssistantMessage(content), nil
	}

	// Parse response normally
	content, err := extract.Response(respBody, r.responseJSON, r.responseJSONField)
	if err != nil {
		return attempt.Message{}, err
	}

	return attempt.NewAssistantMessage(content), nil
}

// populateTemplate replaces $INPUT and $KEY placeholders in the template.
func (r *Rest) populateTemplate(template, input string, hookVars map[string]string) string {
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

	// Replace hook variables ($VARNAME patterns from runtime hooks)
	// Values are JSON-escaped to prevent malformed JSON when hook output
	// contains special characters (quotes, backslashes, etc.)
	// Sort keys by length (longest first) to prevent prefix collisions
	// e.g., $ID_TOKEN must be substituted before $ID
	keys := make([]string, 0, len(hookVars))
	for k := range hookVars {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j])
	})
	for _, k := range keys {
		placeholder := "$" + k
		if strings.Contains(result, placeholder) {
			result = strings.ReplaceAll(result, placeholder, jsonEscape(hookVars[k]))
		}
	}

	return result
}

// conversationToJSON serializes a Conversation as a JSON array of message objects.
// Each message has "role" and "content" fields.
// Used by the $MESSAGES template variable for multi-turn REST requests.
func conversationToJSON(conv *attempt.Conversation) string {
	msgs := conv.ToMessages()
	type jsonMsg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	out := make([]jsonMsg, len(msgs))
	for i, m := range msgs {
		out[i] = jsonMsg{Role: string(m.Role), Content: m.Content}
	}
	data, err := json.Marshal(out)
	if err != nil {
		return "[]"
	}
	return string(data)
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

// ClearHistory is a no-op for REST generator (stateless).
func (r *Rest) ClearHistory() {}

// LastRawResponse returns the raw HTTP response body from the most recent API call.
// This implements the hooks.RawResponseProvider interface.
func (r *Rest) LastRawResponse() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastRawResp
}

// Name returns the generator's fully qualified name.
func (r *Rest) Name() string {
	return "rest.Rest"
}

// Description returns a human-readable description.
func (r *Rest) Description() string {
	return "Generic REST API generator for HTTP-based LLM endpoints with SSE support"
}
