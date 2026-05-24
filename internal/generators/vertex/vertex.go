// Package vertex provides a Google Cloud Vertex AI generator for Augustus.
//
// This package implements the Generator interface for Google's Vertex AI API.
// It supports Gemini models (gemini-pro, gemini-pro-vision) and PaLM 2 models
// (text-bison, chat-bison).
//
// Authentication:
//   - API key from config or GOOGLE_API_KEY environment variable
//   - Application Default Credentials (ADC) for production
//
// Key differences from other generators:
//   - Uses contents array instead of messages
//   - System prompts via systemInstruction parameter
//   - Generation parameters via generationConfig object
package vertex

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/praetorian-inc/augustus/internal/attackengine"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("vertex.Vertex", NewVertex)
}

// Default configuration values.
const (
	defaultMaxOutputTokens = 150
	defaultTemperature     = 0.7
	defaultLocation        = "us-central1"
	defaultTimeout         = 90 * time.Second
)

// Vertex is a generator that wraps the Google Cloud Vertex AI API.
type Vertex struct {
	apiKey    string
	baseURL   string
	projectID string
	location  string
	model     string

	// Configuration parameters
	temperature     float64
	maxOutputTokens int
	topP            float64
	topK            int
	stopSequences   []string

	// HTTP client for API calls
	client *http.Client
}

// NewVertex creates a new Vertex AI generator from legacy registry.Config.
// This is the backward-compatible entry point.
func NewVertex(m registry.Config) (generators.Generator, error) {
	cfg, err := ConfigFromMap(m)
	if err != nil {
		return nil, err
	}
	return NewVertexTyped(cfg)
}

// NewVertexTyped creates a new Vertex AI generator from typed configuration.
// This is the type-safe entry point for programmatic use.
func NewVertexTyped(cfg Config) (*Vertex, error) {
	// Validate required fields
	if cfg.Model == "" {
		return nil, fmt.Errorf("vertex generator requires model")
	}
	if cfg.ProjectID == "" {
		return nil, fmt.Errorf("vertex generator requires project_id")
	}

	g := &Vertex{
		model:           cfg.Model,
		projectID:       cfg.ProjectID,
		location:        cfg.Location,
		apiKey:          cfg.APIKey,
		temperature:     cfg.Temperature,
		maxOutputTokens: cfg.MaxOutputTokens,
		topP:            cfg.TopP,
		topK:            cfg.TopK,
		stopSequences:   cfg.StopSequences,
		client:          &http.Client{Timeout: defaultTimeout},
	}

	// Set base URL: from config or build default from location
	if cfg.BaseURL != "" {
		g.baseURL = cfg.BaseURL
	} else {
		g.baseURL = fmt.Sprintf("https://%s-aiplatform.googleapis.com/v1", g.location)
	}

	return g, nil
}

// NewVertexWithOptions creates a new Vertex AI generator using functional options.
// This is the recommended entry point for Go code.
//
// Usage:
//
//	g, err := NewVertexWithOptions(
//	    WithModel("gemini-pro"),
//	    WithProjectID("my-project"),
//	    WithAPIKey("..."),
//	)
func NewVertexWithOptions(opts ...Option) (*Vertex, error) {
	cfg := ApplyOptions(DefaultConfig(), opts...)
	return NewVertexTyped(cfg)
}

// contentPart represents a part in a content block.
// Supports text, function call, and function response parts.
type contentPart struct {
	Text             string        `json:"text,omitempty"`
	FunctionCall     *functionCall `json:"functionCall,omitempty"`
	FunctionResponse *functionResp `json:"functionResponse,omitempty"`
}

// functionCall represents a function call made by the model.
type functionCall struct {
	Name string         `json:"name"`
	Args map[string]any `json:"args"`
}

// functionResp represents a function response sent to the model.
type functionResp struct {
	Name     string         `json:"name"`
	Response map[string]any `json:"response"`
}

// toolDeclaration holds function declarations for a set of tools.
type toolDeclaration struct {
	FunctionDeclarations []functionDeclaration `json:"functionDeclarations"`
}

// functionDeclaration describes a single callable function.
type functionDeclaration struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Parameters  any    `json:"parameters,omitempty"`
}

// toolConfig controls how the model selects tools.
type toolConfig struct {
	FunctionCallingConfig *functionCallingConfig `json:"functionCallingConfig,omitempty"`
}

// functionCallingConfig specifies the tool selection mode.
type functionCallingConfig struct {
	Mode                 string   `json:"mode"`
	AllowedFunctionNames []string `json:"allowedFunctionNames,omitempty"`
}

// content represents a message content.
type content struct {
	Role  string        `json:"role"`
	Parts []contentPart `json:"parts"`
}

// generationConfig represents generation parameters.
type generationConfig struct {
	Temperature     float64  `json:"temperature,omitempty"`
	MaxOutputTokens int      `json:"maxOutputTokens,omitempty"`
	TopP            float64  `json:"topP,omitempty"`
	TopK            int      `json:"topK,omitempty"`
	StopSequences   []string `json:"stopSequences,omitempty"`
}

// generateRequest represents the Vertex AI generateContent API request.
type generateRequest struct {
	Contents          []content         `json:"contents"`
	SystemInstruction *content          `json:"systemInstruction,omitempty"`
	GenerationConfig  *generationConfig `json:"generationConfig,omitempty"`
	Tools             []toolDeclaration `json:"tools,omitempty"`
	ToolConfig        *toolConfig       `json:"toolConfig,omitempty"`
}

// candidate represents a response candidate.
type candidate struct {
	Content      content `json:"content"`
	FinishReason string  `json:"finishReason"`
}

// usageMetadata represents token usage statistics.
type usageMetadata struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

// generateResponse represents the Vertex AI API response.
type generateResponse struct {
	Candidates    []candidate   `json:"candidates"`
	UsageMetadata usageMetadata `json:"usageMetadata"`
}

// errorResponse represents a Vertex AI API error.
type errorResponse struct {
	Error errorDetail `json:"error"`
}

// errorDetail contains error information.
type errorDetail struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

// Generate sends the conversation to Vertex AI and returns responses.
func (g *Vertex) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	responses := make([]attempt.Message, 0, n)

	for i := 0; i < n; i++ {
		resp, err := g.generateOne(ctx, conv)
		if err != nil {
			return nil, err
		}
		responses = append(responses, resp)
	}

	return responses, nil
}

// generateOne performs a single API call and returns one response.
func (g *Vertex) generateOne(ctx context.Context, conv *attempt.Conversation) (attempt.Message, error) {
	// Build request
	req := generateRequest{
		Contents: g.conversationToContents(conv),
	}

	// Add system instruction if present
	if conv.System != nil {
		req.SystemInstruction = &content{
			Parts: []contentPart{
				{Text: conv.System.Content},
			},
		}
	}

	// Add generation config
	genConfig := generationConfig{
		Temperature:     g.temperature,
		MaxOutputTokens: g.maxOutputTokens,
	}
	if g.topP != 0 {
		genConfig.TopP = g.topP
	}
	if g.topK != 0 {
		genConfig.TopK = g.topK
	}
	if len(g.stopSequences) > 0 {
		genConfig.StopSequences = g.stopSequences
	}
	req.GenerationConfig = &genConfig

	// Wire tool definitions from probe into the API request.
	if len(conv.Tools) > 0 {
		decls := make([]functionDeclaration, len(conv.Tools))
		for i, t := range conv.Tools {
			name, ok := t["name"].(string)
			if !ok || name == "" {
				return attempt.Message{}, fmt.Errorf("vertex: tool at index %d missing valid string name", i)
			}
			fd := functionDeclaration{Name: name}
			if desc, ok := t["description"].(string); ok {
				fd.Description = desc
			}
			if params, ok := t["parameters"]; ok {
				fd.Parameters = params
			}
			decls[i] = fd
		}
		req.Tools = []toolDeclaration{{FunctionDeclarations: decls}}

		if conv.ToolChoice != "" {
			switch conv.ToolChoice {
			case "auto":
				req.ToolConfig = &toolConfig{FunctionCallingConfig: &functionCallingConfig{Mode: "AUTO"}}
			case "required":
				req.ToolConfig = &toolConfig{FunctionCallingConfig: &functionCallingConfig{Mode: "ANY"}}
			case "none":
				req.Tools = nil
				req.ToolConfig = &toolConfig{FunctionCallingConfig: &functionCallingConfig{Mode: "NONE"}}
			default:
				req.ToolConfig = &toolConfig{FunctionCallingConfig: &functionCallingConfig{
					Mode:                 "ANY",
					AllowedFunctionNames: []string{conv.ToolChoice},
				}}
			}
		}
	}

	// Serialize request
	body, err := json.Marshal(req)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("vertex: failed to marshal request: %w", err)
	}

	// Build URL
	url := fmt.Sprintf("%s/projects/%s/locations/%s/publishers/google/models/%s:generateContent",
		strings.TrimSuffix(g.baseURL, "/"),
		g.projectID,
		g.location,
		g.model,
	)

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return attempt.Message{}, fmt.Errorf("vertex: failed to create request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	if g.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+g.apiKey)
	}

	// Execute request
	httpResp, err := g.client.Do(httpReq)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("vertex: request failed: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	// Read response body
	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("vertex: failed to read response: %w", err)
	}

	// Handle errors
	if httpResp.StatusCode != http.StatusOK {
		return attempt.Message{}, g.handleError(httpResp.StatusCode, respBody)
	}

	// Parse successful response
	var resp generateResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return attempt.Message{}, fmt.Errorf("vertex: failed to parse response: %w", err)
	}

	// Extract text and function calls from first candidate
	if len(resp.Candidates) == 0 {
		return attempt.Message{}, fmt.Errorf("vertex: no candidates in response")
	}

	var text string
	var funcCalls []attackengine.GeminiFunctionCall
	for _, part := range resp.Candidates[0].Content.Parts {
		if part.Text != "" {
			text += part.Text
		}
		if part.FunctionCall != nil {
			funcCalls = append(funcCalls, attackengine.GeminiFunctionCall{
				Name: part.FunctionCall.Name,
				Args: part.FunctionCall.Args,
			})
		}
	}

	msg := attempt.NewAssistantMessage(text)
	if toolCalls := attackengine.NormalizeGeminiFunctionCalls(funcCalls); toolCalls != nil {
		msg.ToolCalls = toolCalls
	}
	return msg, nil
}

// conversationToContents converts an Augustus Conversation to Vertex AI contents.
func (g *Vertex) conversationToContents(conv *attempt.Conversation) []content {
	contents := make([]content, 0)

	// Note: System message is NOT included in contents array for Vertex AI
	// It's passed as a separate systemInstruction parameter

	for _, turn := range conv.Turns {
		switch turn.Prompt.Role {
		case attempt.RoleTool:
			// Tool result: "function" role with functionResponse part.
			// Gemini uses the function name (not call ID) to match responses.
			var respData map[string]any
			if err := json.Unmarshal([]byte(turn.Prompt.Content), &respData); err != nil {
				respData = map[string]any{"result": turn.Prompt.Content}
			}
			// ToolCallID holds the function name for Gemini tool results.
			name := turn.Prompt.ToolCallID
			contents = append(contents, content{
				Role: "function",
				Parts: []contentPart{{
					FunctionResponse: &functionResp{Name: name, Response: respData},
				}},
			})
		default:
			// Standard user message
			contents = append(contents, content{
				Role: "user",
				Parts: []contentPart{
					{Text: turn.Prompt.Content},
				},
			})
		}

		// Add model response if present
		if turn.Response != nil {
			parts := []contentPart{}
			if turn.Response.Content != "" {
				parts = append(parts, contentPart{Text: turn.Response.Content})
			}
			for _, tc := range turn.Response.ToolCalls {
				name, _ := tc["name"].(string)
				args, _ := tc["args"].(map[string]any)
				if name != "" {
					parts = append(parts, contentPart{
						FunctionCall: &functionCall{Name: name, Args: args},
					})
				}
			}
			if len(parts) > 0 {
				contents = append(contents, content{Role: "model", Parts: parts})
			}
		}
	}

	return contents
}

// handleError processes API error responses.
func (g *Vertex) handleError(statusCode int, body []byte) error {
	var errResp errorResponse
	if err := json.Unmarshal(body, &errResp); err != nil {
		return fmt.Errorf("vertex: HTTP %d: %s", statusCode, string(body))
	}

	errCode := errResp.Error.Code
	errMsg := errResp.Error.Message
	errStatus := errResp.Error.Status

	switch statusCode {
	case http.StatusTooManyRequests:
		return fmt.Errorf("vertex: rate limit exceeded: %s", errMsg)
	case http.StatusBadRequest:
		return fmt.Errorf("vertex: bad request (%s): %s", errStatus, errMsg)
	case http.StatusUnauthorized:
		return fmt.Errorf("vertex: authentication error: %s", errMsg)
	case http.StatusForbidden:
		return fmt.Errorf("vertex: permission denied: %s", errMsg)
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return fmt.Errorf("vertex: server error (%d): %s", statusCode, errMsg)
	default:
		return fmt.Errorf("vertex: API error (%d, %s): %s", errCode, errStatus, errMsg)
	}
}

// ClearHistory is a no-op for Vertex generator (stateless per call).
func (g *Vertex) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *Vertex) Name() string {
	return "vertex.Vertex"
}

// Description returns a human-readable description.
func (g *Vertex) Description() string {
	return "Google Cloud Vertex AI generator for Gemini and PaLM 2 models"
}
