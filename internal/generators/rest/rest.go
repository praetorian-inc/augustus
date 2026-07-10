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
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

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
	_ types.VisionCapable       = (*Rest)(nil)
)

// bodyModeRawBinary is the body_mode value that sends the probe's image as the
// raw HTTP request body (e.g. for endpoints that accept image/* directly).
const bodyModeRawBinary = "raw_binary"

// validCaptureKey restricts upload capture variable names to uppercase
// alphanumeric and underscores, matching the runtime hook-var key rule.
var validCaptureKey = regexp.MustCompile(`^[A-Z0-9_]+$`)

// multipartConfig describes how to send the request as multipart/form-data.
// The probe's image is attached as a file part under fileField; any additional
// text fields are populated from templates (supporting $INPUT, $KEY, hook vars).
type multipartConfig struct {
	fileField string
	filename  string
	fields    map[string]string
}

// requestSpec carries the per-request fields the builders need, so the same
// builders serve both the main ("analyze") request and the pre-request upload.
type requestSpec struct {
	uri         string
	method      string
	headers     map[string]string
	reqTemplate string
	bodyMode    string
	multipart   *multipartConfig
}

// mainSpec returns the requestSpec for the generator's primary request,
// populated from the top-level configuration.
func (r *Rest) mainSpec() requestSpec {
	return requestSpec{
		uri:         r.uri,
		method:      r.method,
		headers:     r.headers,
		reqTemplate: r.reqTemplate,
		bodyMode:    r.bodyMode,
		multipart:   r.multipart,
	}
}

// Rest is a generic REST API generator that makes HTTP requests to configured endpoints.
// It supports request templating, JSON response parsing, and various HTTP methods.
type Rest struct {
	types.UsageCounter // embedded but never incremented: REST endpoints return no token usage.
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

	// Optional: reasoning extraction (for reasoning models that expose CoT)
	reasoningJSONField string // JSONPath for reasoning content (e.g., "$.choices[0].message.reasoning_content")

	// Configurable SSE parsing
	sseTextField   string // JSONPath for text extraction (e.g., "$.content.text")
	sseMode        string // "delta" or "last"
	sseFilterField string // JSONPath for event filtering (e.g., "$.content.type")
	sseFilterValue string // Value to match for filter (e.g., "CHAT_TEXT")

	// Multimodal image transport
	bodyMode  string           // "" (template) or bodyModeRawBinary
	multipart *multipartConfig // non-nil when sending multipart/form-data

	// Two-step upload flow: when set, an upload pre-request runs before the main
	// request, capturing values substituted into it via $VAR placeholders.
	upload *uploadConfig

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

	// Optional: Reasoning extraction path (for reasoning models).
	// An empty string is treated as unset (no-op) so it doesn't silently
	// force JSON parsing on a target that returns plain text.
	if reasoningPath, ok := cfg["reasoning_path"].(string); ok && reasoningPath != "" {
		r.reasoningJSONField = reasoningPath
		// Reasoning extraction requires JSON parsing
		if !r.responseJSON {
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

	// Optional: multimodal image transport.
	if err := r.configureImageTransport(cfg); err != nil {
		return nil, err
	}

	// Optional: two-step upload flow.
	if err := r.configureUpload(cfg); err != nil {
		return nil, err
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

	// The first image on the last prompt (if any) is the probe-injected image.
	// Image data never enters config — Augustus attaches it at run time.
	var img *attempt.Image
	if pm := conv.LastPromptMessage(); pm != nil && len(pm.Images) > 0 {
		img = &pm.Images[0]
	}

	// Two-step flow: upload the image first, capture handle(s) into the var map,
	// then send the main request with the image omitted (it was consumed above).
	if r.upload != nil {
		captured, err := r.doUpload(ctx, conv, prompt, hookVars, img)
		if err != nil {
			return attempt.Message{}, err
		}
		merged := make(map[string]string, len(hookVars)+len(captured))
		for k, v := range hookVars {
			merged[k] = v
		}
		for k, v := range captured {
			merged[k] = v // captured values win on key collision
		}
		hookVars = merged
		img = nil
	}

	// Build the HTTP request body and content type according to the configured
	// wire mode (raw binary, multipart, or JSON template).
	req, err := r.buildRequest(ctx, r.mainSpec(), conv, prompt, hookVars, img)
	if err != nil {
		return attempt.Message{}, err
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
		// Parse SSE format
		content := r.parseSSE(respBody)
		return attempt.NewAssistantMessage(content), nil
	}

	// Parse response normally
	content, err := r.parseResponse(respBody)
	if err != nil {
		return attempt.Message{}, err
	}

	msg := attempt.NewAssistantMessage(content)

	// Extract reasoning content if configured
	if r.reasoningJSONField != "" {
		reasoning, _ := r.parseReasoning(respBody)
		msg.Reasoning = reasoning
	}

	return msg, nil
}

// buildRequest constructs an outgoing HTTP request for spec, dispatching on the
// spec's image-transport mode. The spec's URI is run through populateTemplate so
// $INPUT/$KEY/hook/captured vars (e.g. /analyze/$FILE_ID) resolve. Image bytes
// (when an image is attached) are placed on the wire per mode; encode errors are
// surfaced (wrapped), never silently dropped.
func (r *Rest) buildRequest(
	ctx context.Context,
	spec requestSpec,
	conv *attempt.Conversation,
	prompt string,
	hookVars map[string]string,
	img *attempt.Image,
) (*http.Request, error) {
	spec.uri = r.populateTemplate(spec.uri, prompt, hookVars)
	switch {
	case spec.bodyMode == bodyModeRawBinary:
		return r.buildRawBinaryRequest(ctx, spec, prompt, hookVars, img)
	case spec.multipart != nil:
		return r.buildMultipartRequest(ctx, spec, prompt, hookVars, img)
	default:
		return r.buildTemplateRequest(ctx, spec, conv, prompt, hookVars, img)
	}
}

// buildTemplateRequest builds the default JSON/template request (Mode A),
// substituting $INPUT, $MESSAGES, and — when an image is attached — the
// $IMAGE_DATAURI / $IMAGE_B64 / $IMAGE_MIME placeholders. The base64, data-URI,
// and MIME values are JSON-safe, so no additional escaping is applied.
func (r *Rest) buildTemplateRequest(
	ctx context.Context,
	spec requestSpec,
	conv *attempt.Conversation,
	prompt string,
	hookVars map[string]string,
	img *attempt.Image,
) (*http.Request, error) {
	body := r.populateTemplate(spec.reqTemplate, prompt, hookVars)

	// Replace $MESSAGES with the full conversation as a JSON array. Guarded on a
	// non-nil conv because the upload pre-request may build without one.
	if conv != nil && strings.Contains(body, "$MESSAGES") {
		body = strings.ReplaceAll(body, "$MESSAGES", conversationToJSON(conv))
	}

	if img != nil && strings.Contains(body, "$IMAGE_") {
		b64, err := img.ToBase64()
		if err != nil {
			return nil, fmt.Errorf("rest: encode image: %w", err)
		}
		body = strings.ReplaceAll(body, "$IMAGE_DATAURI", "data:"+img.MimeType+";base64,"+b64)
		body = strings.ReplaceAll(body, "$IMAGE_B64", b64)
		body = strings.ReplaceAll(body, "$IMAGE_MIME", img.MimeType)
	}

	var req *http.Request
	var err error
	if spec.method == "GET" {
		req, err = http.NewRequestWithContext(ctx, spec.method, spec.uri+"?"+body, nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, spec.method, spec.uri, bytes.NewBufferString(body))
	}
	if err != nil {
		return nil, fmt.Errorf("rest: failed to create request: %w", err)
	}

	r.applyHeaders(req, spec.headers, prompt, hookVars)
	return req, nil
}

// buildRawBinaryRequest builds a request whose body is the raw image bytes
// (Mode C). The request Content-Type defaults to the image's MIME type, but
// configured headers are applied afterward so an explicit Content-Type header
// can override it. $INPUT/$MESSAGES template population is skipped.
func (r *Rest) buildRawBinaryRequest(
	ctx context.Context,
	spec requestSpec,
	prompt string,
	hookVars map[string]string,
	img *attempt.Image,
) (*http.Request, error) {
	if img == nil {
		return nil, fmt.Errorf("rest: body_mode raw_binary requires an image attachment")
	}

	data, err := img.Bytes()
	if err != nil {
		return nil, fmt.Errorf("rest: read image bytes: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, spec.method, spec.uri, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("rest: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", img.MimeType)
	r.applyHeaders(req, spec.headers, prompt, hookVars)
	return req, nil
}

// buildMultipartRequest builds a multipart/form-data request (Mode B). Text
// fields are written in sorted key order (deterministic output) from their
// templates; when an image is attached it is added as a file part under the
// configured file_field with the image's MIME type. The boundary-bearing
// Content-Type is set AFTER configured headers so the boundary always matches
// the actual body.
func (r *Rest) buildMultipartRequest(
	ctx context.Context,
	spec requestSpec,
	prompt string,
	hookVars map[string]string,
	img *attempt.Image,
) (*http.Request, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	keys := make([]string, 0, len(spec.multipart.fields))
	for k := range spec.multipart.fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		value := r.populateTemplate(spec.multipart.fields[k], prompt, hookVars)
		if err := writer.WriteField(k, value); err != nil {
			return nil, fmt.Errorf("rest: write multipart field %q: %w", k, err)
		}
	}

	if img != nil {
		data, err := img.Bytes()
		if err != nil {
			return nil, fmt.Errorf("rest: read image bytes: %w", err)
		}
		header := textproto.MIMEHeader{}
		header.Set("Content-Disposition", fmt.Sprintf(
			`form-data; name=%q; filename=%q`, spec.multipart.fileField, spec.multipart.filename))
		header.Set("Content-Type", img.MimeType)
		part, err := writer.CreatePart(header)
		if err != nil {
			return nil, fmt.Errorf("rest: create multipart file part: %w", err)
		}
		if _, err := part.Write(data); err != nil {
			return nil, fmt.Errorf("rest: write multipart file part: %w", err)
		}
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("rest: close multipart writer: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, spec.method, spec.uri, &buf)
	if err != nil {
		return nil, fmt.Errorf("rest: failed to create request: %w", err)
	}

	r.applyHeaders(req, spec.headers, prompt, hookVars)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req, nil
}

// applyHeaders sets the given headers on req, substituting templates.
func (r *Rest) applyHeaders(req *http.Request, headers map[string]string, prompt string, hookVars map[string]string) {
	for k, v := range headers {
		req.Header.Set(k, r.populateTemplate(v, prompt, hookVars))
	}
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

// jsonEscape escapes a string for use in JSON (quotes, backslashes, control
// characters). HTML escaping is deliberately disabled — json.Marshal's default
// SetEscapeHTML(true) rewrites the raw bytes '&', '<', '>' to the Unicode
// escape sequences \u0026, \u003c, \u003e, which is harmless in a JSON body
// (the server JSON-decodes it back to the original byte) but corrupts values
// substituted into a request HEADER or URI, where there is no decode step.
// Raw '&<>' are valid inside a JSON string, valid in header values, and
// correct in URL query strings, so disabling HTML escaping fixes header/URI
// substitution without breaking JSON bodies.
func jsonEscape(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return s
	}
	out := buf.String()
	// enc.Encode wraps in quotes and appends a trailing newline; strip both.
	return out[1 : len(out)-2]
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

// parseReasoning extracts reasoning/chain-of-thought content from a JSON response.
// Returns empty string on any error (reasoning is optional).
func (r *Rest) parseReasoning(body []byte) (string, error) {
	var data any
	if err := json.Unmarshal(body, &data); err != nil {
		return "", err
	}
	return r.extractField(data, r.reasoningJSONField)
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
//
// When sseTextField is configured, uses configurable JSONPath-based extraction.
// Otherwise, falls back to the built-in heuristic matching common SSE structures.
func (r *Rest) parseSSE(body []byte) string {
	if r.sseTextField != "" {
		return r.parseSSEConfigurable(body)
	}
	return r.parseSSEDefault(body)
}

// parseSSEDefault is the original built-in SSE parser that matches common structures.
func (r *Rest) parseSSEDefault(body []byte) string {
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

		// Try to parse as JSON object
		var data map[string]any
		if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
			// Not a JSON object; try as a plain JSON string (e.g., data: "Hello world")
			var strData string
			if err := json.Unmarshal([]byte(jsonStr), &strData); err == nil && strData != "" {
				textParts = append(textParts, strData)
			}
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

// parseSSEConfigurable parses SSE events using user-configured JSONPath fields.
// It supports two modes:
//   - "delta": concatenates extracted text from all matching events
//   - "last": keeps only the last non-empty extracted text (for cumulative streams)
func (r *Rest) parseSSEConfigurable(body []byte) string {
	var result string
	var parts []string
	lines := strings.Split(string(body), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if !strings.HasPrefix(line, "data:") {
			continue
		}

		jsonStr := strings.TrimPrefix(line, "data:")
		jsonStr = strings.TrimSpace(jsonStr)
		if jsonStr == "" {
			continue
		}

		var data any
		if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
			continue
		}

		// Apply filter if configured
		if r.sseFilterField != "" && r.sseFilterValue != "" {
			filterVal, err := r.evaluateJSONPath(data, r.sseFilterField)
			if err != nil || filterVal != r.sseFilterValue {
				continue
			}
		}

		// Extract text using configured JSONPath
		text, err := r.evaluateJSONPath(data, r.sseTextField)
		if err != nil || text == "" {
			continue
		}

		if r.sseMode == "last" {
			result = text
		} else {
			parts = append(parts, text)
		}
	}

	if r.sseMode == "last" {
		if result != "" {
			return result
		}
	} else if len(parts) > 0 {
		return strings.Join(parts, "")
	}

	// Fallback: return raw body if no text extracted
	return string(body)
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

// SupportsVision reports whether this REST target is configured with somewhere
// for an image to go. It implements the optional types.VisionCapable interface.
//
// Returning true unconditionally would let a REST target that is NOT configured
// for images claim vision support and then silently send a text-only request —
// exactly the silent-drop trap that finding #8 fixed. Vision is true only when
// the configured wire shape can actually carry the image: raw-binary body,
// multipart file part, or a JSON template containing an $IMAGE_ placeholder.
func (r *Rest) SupportsVision() bool {
	if r.upload != nil && r.upload.carriesImage() {
		return true
	}
	return r.bodyMode == bodyModeRawBinary ||
		r.multipart != nil ||
		strings.Contains(r.reqTemplate, "$IMAGE_")
}

// parseImageTransport reads the optional body_mode and multipart settings from a
// config sub-map and returns the resulting transport. body_mode raw_binary and
// multipart are mutually exclusive. Used for both the top-level request and the
// upload pre-request.
func parseImageTransport(m map[string]any) (string, *multipartConfig, error) {
	var bodyMode string
	if mode, ok := m["body_mode"].(string); ok && mode != "" {
		if mode != bodyModeRawBinary {
			return "", nil, fmt.Errorf("rest: invalid body_mode %q (only %q is supported)", mode, bodyModeRawBinary)
		}
		bodyMode = mode
	}

	raw, ok := m["multipart"]
	if !ok {
		return bodyMode, nil, nil
	}
	mpRaw, ok := raw.(map[string]any)
	if !ok {
		return "", nil, fmt.Errorf("rest: multipart must be an object")
	}
	if bodyMode == bodyModeRawBinary {
		return "", nil, fmt.Errorf("rest: body_mode %q and multipart are mutually exclusive", bodyModeRawBinary)
	}

	fileField, _ := mpRaw["file_field"].(string)
	if fileField == "" {
		return "", nil, fmt.Errorf("rest: multipart requires a non-empty file_field")
	}

	filename := "image.png"
	if fn, ok := mpRaw["filename"].(string); ok && fn != "" {
		filename = fn
	}

	fields := make(map[string]string)
	if rawFields, ok := mpRaw["fields"].(map[string]any); ok {
		for k, v := range rawFields {
			if vs, ok := v.(string); ok {
				fields[k] = vs
			}
		}
	}

	return bodyMode, &multipartConfig{fileField: fileField, filename: filename, fields: fields}, nil
}

// configureImageTransport parses the top-level body_mode and multipart settings
// that control how a probe's image is placed on the wire.
func (r *Rest) configureImageTransport(cfg registry.Config) error {
	bodyMode, mp, err := parseImageTransport(cfg)
	if err != nil {
		return err
	}
	r.bodyMode = bodyMode
	r.multipart = mp
	return nil
}

// uploadConfig describes the pre-request "upload" step of a two-step multimodal
// flow: it sends the probe's image to an upload endpoint and captures named
// values from the response for substitution into the main ("analyze") request.
type uploadConfig struct {
	uri         string
	method      string
	headers     map[string]string
	reqTemplate string
	bodyMode    string
	multipart   *multipartConfig
	// capture maps a variable name (^[A-Z0-9_]+$) to a source: a JSONPath into
	// the response body ("$.data.id"), or "header:Name" for a response header.
	capture map[string]string
}

// toRequestSpec adapts the upload config to the shared requestSpec used by the
// request builders.
func (u *uploadConfig) toRequestSpec() requestSpec {
	return requestSpec{
		uri:         u.uri,
		method:      u.method,
		headers:     u.headers,
		reqTemplate: u.reqTemplate,
		bodyMode:    u.bodyMode,
		multipart:   u.multipart,
	}
}

// carriesImage reports whether the upload step is configured with somewhere for
// the image to go (raw-binary body, multipart file part, or an $IMAGE_ template).
func (u *uploadConfig) carriesImage() bool {
	return u.bodyMode == bodyModeRawBinary ||
		u.multipart != nil ||
		strings.Contains(u.reqTemplate, "$IMAGE_")
}

// configureUpload parses and validates the optional "upload" config block.
func (r *Rest) configureUpload(cfg registry.Config) error {
	raw, ok := cfg["upload"]
	if !ok {
		return nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("rest: upload must be an object")
	}

	u := &uploadConfig{
		method:  "POST",
		headers: make(map[string]string),
		capture: make(map[string]string),
	}

	uri, _ := m["uri"].(string)
	if uri == "" {
		return fmt.Errorf("rest: upload requires a non-empty uri")
	}
	u.uri = uri

	if method, ok := m["method"].(string); ok && method != "" {
		u.method = strings.ToUpper(method)
	}

	if headers, ok := m["headers"].(map[string]any); ok {
		for k, v := range headers {
			if vs, ok := v.(string); ok {
				u.headers[k] = vs
			}
		}
	}

	if tmpl, ok := m["req_template"].(string); ok {
		u.reqTemplate = tmpl
	}

	bodyMode, mp, err := parseImageTransport(m)
	if err != nil {
		return err
	}
	u.bodyMode = bodyMode
	u.multipart = mp

	if !u.carriesImage() {
		return fmt.Errorf("rest: upload requires an image transport mode " +
			"(body_mode raw_binary, multipart, or a req_template containing $IMAGE_)")
	}

	if rawCapture, ok := m["capture"].(map[string]any); ok {
		for k, v := range rawCapture {
			vs, ok := v.(string)
			if !ok {
				return fmt.Errorf("rest: upload capture %q must be a string", k)
			}
			if !validCaptureKey.MatchString(k) {
				return fmt.Errorf("rest: upload capture key %q must match ^[A-Z0-9_]+$", k)
			}
			if vs == "" {
				return fmt.Errorf("rest: upload capture %q must have a non-empty source", k)
			}
			if strings.HasPrefix(vs, captureHeaderPrefix) && strings.TrimPrefix(vs, captureHeaderPrefix) == "" {
				return fmt.Errorf("rest: upload capture %q: header source must name a header (got %q)", k, vs)
			}
			u.capture[k] = vs
		}
	}

	r.upload = u
	return nil
}

// captureHeaderPrefix marks a capture source that reads a response header
// ("header:Location") rather than a JSONPath into the response body.
const captureHeaderPrefix = "header:"

// parseCapture applies the upload step's capture rules to the upload response,
// returning variable name -> captured value. Body captures use the JSON field /
// JSONPath engine; "header:Name" captures read a response header. A declared
// capture that resolves to an empty value is an error (fail-loud: never let the
// main request proceed with a missing handle).
func (r *Rest) parseCapture(resp *http.Response, body []byte) (map[string]string, error) {
	out := make(map[string]string, len(r.upload.capture))

	// Decode the body once, only if a body capture is present.
	var decoded any
	var decodedErr error
	var decodedOnce bool
	ensureDecoded := func() error {
		if !decodedOnce {
			decodedOnce = true
			decodedErr = json.Unmarshal(body, &decoded)
		}
		return decodedErr
	}

	for name, source := range r.upload.capture {
		if strings.HasPrefix(source, captureHeaderPrefix) {
			headerName := strings.TrimPrefix(source, captureHeaderPrefix)
			val := resp.Header.Get(headerName)
			if val == "" {
				return nil, fmt.Errorf("rest: upload capture %q: response header %q is empty or absent", name, headerName)
			}
			out[name] = val
			continue
		}

		if err := ensureDecoded(); err != nil {
			return nil, fmt.Errorf("rest: upload capture %q: parse response JSON: %w", name, err)
		}
		val, err := r.extractField(decoded, source)
		if err != nil {
			return nil, fmt.Errorf("rest: upload capture %q: %w", name, err)
		}
		if val == "" {
			return nil, fmt.Errorf("rest: upload capture %q resolved to an empty value at %q", name, source)
		}
		out[name] = val
	}

	return out, nil
}

// doUpload runs the two-step flow's pre-request: it sends the probe's image to
// the upload endpoint and returns the captured variables. Any non-2xx status or
// an unresolved capture is an error, so the main request never proceeds with a
// missing handle.
func (r *Rest) doUpload(
	ctx context.Context,
	conv *attempt.Conversation,
	prompt string,
	hookVars map[string]string,
	img *attempt.Image,
) (map[string]string, error) {
	if img == nil {
		return nil, fmt.Errorf("rest: upload flow requires an image attachment")
	}

	req, err := r.buildRequest(ctx, r.upload.toRequestSpec(), conv, prompt, hookVars, img)
	if err != nil {
		return nil, fmt.Errorf("rest: build upload request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rest: upload request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("rest: upload returned non-2xx status: %d %s", resp.StatusCode, resp.Status)
	}

	const maxResponseSize = 10 * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("rest: read upload response: %w", err)
	}

	return r.parseCapture(resp, body)
}
