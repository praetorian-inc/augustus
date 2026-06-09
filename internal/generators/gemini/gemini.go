// Package gemini provides a Google Gemini API generator for Augustus.
//
// This package implements the Generator interface for Google's direct Gemini
// API (generativelanguage.googleapis.com). It is the simpler, lower-friction
// sibling of the vertex generator — auth is a single API key (no GCP project,
// no ADC, no service account), and the endpoint is project-agnostic.
//
// Use this generator for one-shot scans, pentests, or any environment where
// a GCP project is not provisioned. For production-grade GCP integrations,
// prefer vertex.Vertex (Vertex AI hosts the same Gemini models with IAM /
// VPC-SC / data residency guarantees).
//
// Authentication:
//   - API key from config or GEMINI_API_KEY environment variable
//
// Wire format (identical to vertex.Vertex — Google publishes a single Gemini
// REST schema):
//   - contents[] array with role+parts; parts carry text or inlineData
//   - systemInstruction for system prompts
//   - generationConfig for sampling parameters
package gemini

import (
	"bytes"
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
	generators.Register("gemini.Gemini", NewGemini)
}

// Default configuration values.
const (
	defaultMaxOutputTokens = 150
	defaultTemperature     = 0.7
	defaultBaseURL         = "https://generativelanguage.googleapis.com/v1beta"
	defaultTimeout         = 90 * time.Second
)

// Gemini is a generator that wraps the direct Google Gemini API.
type Gemini struct {
	apiKey  string
	baseURL string
	model   string

	// Configuration parameters
	temperature     float64
	maxOutputTokens int
	topP            float64
	topK            int
	stopSequences   []string

	client *http.Client
}

// NewGemini creates a new Gemini generator from a legacy registry.Config map.
func NewGemini(m registry.Config) (generators.Generator, error) {
	cfg, err := ConfigFromMap(m)
	if err != nil {
		return nil, err
	}
	return NewGeminiTyped(cfg)
}

// NewGeminiTyped creates a new Gemini generator from typed configuration.
func NewGeminiTyped(cfg Config) (*Gemini, error) {
	if cfg.Model == "" {
		return nil, fmt.Errorf("gemini generator requires model")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("gemini generator requires api_key (set GEMINI_API_KEY or pass api_key in config)")
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	return &Gemini{
		model:           cfg.Model,
		apiKey:          cfg.APIKey,
		baseURL:         baseURL,
		temperature:     cfg.Temperature,
		maxOutputTokens: cfg.MaxOutputTokens,
		topP:            cfg.TopP,
		topK:            cfg.TopK,
		stopSequences:   cfg.StopSequences,
		client:          &http.Client{Timeout: defaultTimeout},
	}, nil
}

// NewGeminiWithOptions creates a new Gemini generator using functional options.
func NewGeminiWithOptions(opts ...Option) (*Gemini, error) {
	cfg := ApplyOptions(DefaultConfig(), opts...)
	return NewGeminiTyped(cfg)
}

// inlineData represents a base64-encoded media attachment in a Gemini part.
// Field names are snake_case per the canonical Gemini REST spec
// (https://ai.google.dev/api/generate-content). Proto3 JSON acceptance
// allows camelCase too, but we emit the canonical form.
type inlineData struct {
	MimeType string `json:"mime_type"`
	Data     string `json:"data"`
}

// contentPart represents a single part within a content block.
// Exactly one of Text or InlineData is set per part.
type contentPart struct {
	Text       string      `json:"text,omitempty"`
	InlineData *inlineData `json:"inline_data,omitempty"`
}

// content represents a message turn in the contents array.
type content struct {
	Role  string        `json:"role"`
	Parts []contentPart `json:"parts"`
}

// generationConfig represents Gemini's sampling parameters.
type generationConfig struct {
	Temperature     float64  `json:"temperature,omitempty"`
	MaxOutputTokens int      `json:"maxOutputTokens,omitempty"`
	TopP            float64  `json:"topP,omitempty"`
	TopK            int      `json:"topK,omitempty"`
	StopSequences   []string `json:"stopSequences,omitempty"`
}

// generateRequest represents the :generateContent request body.
type generateRequest struct {
	Contents          []content         `json:"contents"`
	SystemInstruction *content          `json:"systemInstruction,omitempty"`
	GenerationConfig  *generationConfig `json:"generationConfig,omitempty"`
}

// candidate represents one response candidate.
type candidate struct {
	Content      content `json:"content"`
	FinishReason string  `json:"finishReason"`
}

// usageMetadata is Gemini's token-usage block.
type usageMetadata struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

// generateResponse represents the :generateContent response body.
type generateResponse struct {
	Candidates    []candidate   `json:"candidates"`
	UsageMetadata usageMetadata `json:"usageMetadata"`
}

// errorResponse represents a Gemini API error envelope.
type errorResponse struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

// Generate sends the conversation to Gemini and returns n responses.
func (g *Gemini) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
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

func (g *Gemini) generateOne(ctx context.Context, conv *attempt.Conversation) (attempt.Message, error) {
	req := generateRequest{
		Contents: g.conversationToContents(conv),
	}

	if conv.System != nil {
		req.SystemInstruction = &content{
			Parts: []contentPart{{Text: conv.System.Content}},
		}
	}

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

	body, err := json.Marshal(req)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("gemini: failed to marshal request: %w", err)
	}

	// Build URL: {baseURL}/models/{model}:generateContent?key={apiKey}
	endpoint := fmt.Sprintf("%s/models/%s:generateContent?key=%s",
		strings.TrimSuffix(g.baseURL, "/"),
		g.model,
		url.QueryEscape(g.apiKey),
	)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return attempt.Message{}, fmt.Errorf("gemini: failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := g.client.Do(httpReq)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("gemini: request failed: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("gemini: failed to read response: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return attempt.Message{}, g.handleError(httpResp.StatusCode, respBody)
	}

	var resp generateResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return attempt.Message{}, fmt.Errorf("gemini: failed to parse response: %w", err)
	}
	if len(resp.Candidates) == 0 {
		return attempt.Message{}, fmt.Errorf("gemini: no candidates in response")
	}

	var text string
	for _, part := range resp.Candidates[0].Content.Parts {
		text += part.Text
	}
	return attempt.NewAssistantMessage(text), nil
}

// conversationToContents converts an Augustus Conversation to Gemini's
// contents array. Images on user turns are emitted as inlineData parts
// (base64). System prompts are NOT included here — they live in the
// request's systemInstruction field.
func (g *Gemini) conversationToContents(conv *attempt.Conversation) []content {
	contents := make([]content, 0, len(conv.Turns)*2)
	for _, turn := range conv.Turns {
		contents = append(contents, content{
			Role:  "user",
			Parts: buildParts(turn.Prompt.Content, turn.Prompt.Images),
		})
		if turn.Response != nil {
			contents = append(contents, content{
				Role:  "model",
				Parts: []contentPart{{Text: turn.Response.Content}},
			})
		}
	}
	return contents
}

// buildParts assembles a Gemini parts list: text first (if non-empty), then
// one inlineData part per image. Used by user-message construction.
func buildParts(text string, images []attempt.Image) []contentPart {
	parts := make([]contentPart, 0, 1+len(images))
	if text != "" {
		parts = append(parts, contentPart{Text: text})
	}
	for _, img := range images {
		parts = append(parts, contentPart{
			InlineData: &inlineData{
				MimeType: img.MimeType,
				Data:     img.ToBase64(),
			},
		})
	}
	return parts
}

func (g *Gemini) handleError(statusCode int, body []byte) error {
	var errResp errorResponse
	if err := json.Unmarshal(body, &errResp); err != nil {
		return fmt.Errorf("gemini: HTTP %d: %s", statusCode, string(body))
	}
	errCode := errResp.Error.Code
	errMsg := errResp.Error.Message
	errStatus := errResp.Error.Status

	switch statusCode {
	case http.StatusTooManyRequests:
		return fmt.Errorf("gemini: rate limit exceeded: %s", errMsg)
	case http.StatusBadRequest:
		return fmt.Errorf("gemini: bad request (%s): %s", errStatus, errMsg)
	case http.StatusUnauthorized:
		return fmt.Errorf("gemini: authentication error: %s", errMsg)
	case http.StatusForbidden:
		return fmt.Errorf("gemini: permission denied: %s", errMsg)
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return fmt.Errorf("gemini: server error (%d): %s", statusCode, errMsg)
	default:
		return fmt.Errorf("gemini: API error (%d, %s): %s", errCode, errStatus, errMsg)
	}
}

func (g *Gemini) ClearHistory() {}

func (g *Gemini) Name() string {
	return "gemini.Gemini"
}

func (g *Gemini) Description() string {
	return "Google Gemini API generator (direct API, key-auth; multimodal text + image)"
}
