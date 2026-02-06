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
	temperature      float64
	maxOutputTokens  int
	topP             float64
	topK             int
	stopSequences    []string

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
type contentPart struct {
	Text string `json:"text"`
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
	defer httpResp.Body.Close()

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

	// Extract text from first candidate
	if len(resp.Candidates) == 0 {
		return attempt.Message{}, fmt.Errorf("vertex: no candidates in response")
	}

	var text string
	for _, part := range resp.Candidates[0].Content.Parts {
		text += part.Text
	}

	return attempt.NewAssistantMessage(text), nil
}

// conversationToContents converts an Augustus Conversation to Vertex AI contents.
func (g *Vertex) conversationToContents(conv *attempt.Conversation) []content {
	contents := make([]content, 0)

	// Note: System message is NOT included in contents array for Vertex AI
	// It's passed as a separate systemInstruction parameter

	for _, turn := range conv.Turns {
		// Add user message
		contents = append(contents, content{
			Role: "user",
			Parts: []contentPart{
				{Text: turn.Prompt.Content},
			},
		})

		// Add model response if present
		if turn.Response != nil {
			contents = append(contents, content{
				Role: "model",
				Parts: []contentPart{
					{Text: turn.Response.Content},
				},
			})
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
