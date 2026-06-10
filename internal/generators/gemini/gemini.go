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
	"strings"
	"time"

	"github.com/praetorian-inc/augustus/internal/generators/googleai"
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
	contents, err := g.conversationToContents(conv)
	if err != nil {
		return attempt.Message{}, err
	}
	req := googleai.GenerateRequest{
		Contents: contents,
	}

	if conv.System != nil {
		req.SystemInstruction = &googleai.Content{
			Parts: []googleai.ContentPart{{Text: conv.System.Content}},
		}
	}

	genConfig := googleai.GenerationConfig{
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

	// Build URL: {baseURL}/models/{model}:generateContent
	// The API key is sent via the x-goog-api-key header rather than a ?key=
	// query parameter so it cannot leak into net/url error strings or logs.
	endpoint := fmt.Sprintf(
		"%s/models/%s:generateContent",
		strings.TrimSuffix(g.baseURL, "/"),
		g.model,
	)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return attempt.Message{}, fmt.Errorf("gemini: failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-goog-api-key", g.apiKey)

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
		return attempt.Message{}, googleai.HandleError("gemini", httpResp.StatusCode, respBody)
	}

	var resp googleai.GenerateResponse
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
func (g *Gemini) conversationToContents(conv *attempt.Conversation) ([]googleai.Content, error) {
	contents := make([]googleai.Content, 0, len(conv.Turns)*2)
	for _, turn := range conv.Turns {
		parts, err := buildParts(turn.Prompt.Content, turn.Prompt.Images)
		if err != nil {
			return nil, err
		}
		contents = append(contents, googleai.Content{
			Role:  "user",
			Parts: parts,
		})
		if turn.Response != nil {
			contents = append(contents, googleai.Content{
				Role:  "model",
				Parts: []googleai.ContentPart{{Text: turn.Response.Content}},
			})
		}
	}
	return contents, nil
}

// buildParts assembles a Gemini parts list: text first (if non-empty), then
// one inlineData part per image. Image parts are built by the shared
// googleai.BuildImageParts helper (also used by vertex) so the two Gemini-schema
// generators cannot diverge on multimodal handling. It returns an error if an
// image has an unset/unsupported MIME type or cannot be resolved to base64.
func buildParts(text string, images []attempt.Image) ([]googleai.ContentPart, error) {
	parts := make([]googleai.ContentPart, 0, 1+len(images))
	if text != "" {
		parts = append(parts, googleai.ContentPart{Text: text})
	}
	imgParts, err := googleai.BuildImageParts(images)
	if err != nil {
		return nil, err
	}
	parts = append(parts, imgParts...)
	return parts, nil
}

func (g *Gemini) ClearHistory() {}

func (g *Gemini) Name() string {
	return "gemini.Gemini"
}

// SupportsVision reports that the Gemini path transmits inlineData image parts.
// See types.VisionCapable.
func (g *Gemini) SupportsVision() bool { return true }

func (g *Gemini) Description() string {
	return "Google Gemini API generator (direct API, key-auth; multimodal text + image)"
}
