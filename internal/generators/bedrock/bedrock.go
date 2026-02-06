// Package bedrock provides an AWS Bedrock generator for Augustus.
//
// This package implements the Generator interface for AWS Bedrock's InvokeModel API.
// It supports Claude (Anthropic), Titan (Amazon), and Llama (Meta) models via Bedrock.
//
// Key features:
//   - Uses AWS SDK v2 for Go
//   - Supports multiple model families (Claude, Titan, Llama)
//   - Handles AWS authentication via default credential chain
//   - Proper error handling for rate limits and auth failures
package bedrock

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("bedrock.Bedrock", NewBedrock)
}

// Default configuration values.
const (
	defaultMaxTokens   = 150
	defaultTemperature = 0.7
)

// Bedrock is a generator that wraps the AWS Bedrock Runtime API.
type Bedrock struct {
	client    *bedrockruntime.Client
	modelID   string
	region    string
	maxTokens int

	// Configuration parameters
	temperature float64
	topP        float64

	// Custom HTTP client for testing
	httpClient *http.Client
}

// NewBedrock creates a new Bedrock generator from configuration.
func NewBedrock(cfg registry.Config) (generators.Generator, error) {
	g := &Bedrock{
		temperature: defaultTemperature,
		maxTokens:   defaultMaxTokens,
		httpClient:  nil, // Will use default if not set
	}

	// Required: model ID
	modelID, err := registry.RequireString(cfg, "model")
	if err != nil {
		return nil, fmt.Errorf("bedrock generator: %w", err)
	}
	g.modelID = modelID

	// Required: AWS region
	region, err := registry.RequireString(cfg, "region")
	if err != nil {
		return nil, fmt.Errorf("bedrock generator: %w", err)
	}
	g.region = region

	// Optional: max_tokens
	g.maxTokens = registry.GetInt(cfg, "max_tokens", defaultMaxTokens)

	// Optional: temperature
	g.temperature = registry.GetFloat64(cfg, "temperature", defaultTemperature)

	// Optional: top_p
	g.topP = registry.GetFloat64(cfg, "top_p", 0)

	// Initialize AWS SDK client
	ctx := context.Background()
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(g.region))
	if err != nil {
		return nil, fmt.Errorf("bedrock: failed to load AWS config: %w", err)
	}

	// Create Bedrock Runtime client
	var clientOpts []func(*bedrockruntime.Options)

	// Custom endpoint for testing
	if endpoint := registry.GetString(cfg, "endpoint", ""); endpoint != "" {
		clientOpts = append(clientOpts, func(o *bedrockruntime.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})
	}

	// Custom HTTP client for testing
	if g.httpClient != nil {
		clientOpts = append(clientOpts, func(o *bedrockruntime.Options) {
			o.HTTPClient = g.httpClient
		})
	}

	g.client = bedrockruntime.NewFromConfig(awsCfg, clientOpts...)

	return g, nil
}

// Generate sends the conversation to Bedrock and returns responses.
// Since Bedrock doesn't support multiple completions in a single call,
// multiple generations require multiple API calls.
func (g *Bedrock) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
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
func (g *Bedrock) generateOne(ctx context.Context, conv *attempt.Conversation) (attempt.Message, error) {
	// Build request body based on model type
	var requestBody []byte
	var err error

	if strings.HasPrefix(g.modelID, "anthropic.claude") {
		requestBody, err = g.buildClaudeRequest(conv)
	} else if strings.HasPrefix(g.modelID, "amazon.titan") {
		requestBody, err = g.buildTitanRequest(conv)
	} else if strings.HasPrefix(g.modelID, "meta.llama") {
		requestBody, err = g.buildLlamaRequest(conv)
	} else {
		return attempt.Message{}, fmt.Errorf("bedrock: unsupported model family: %s", g.modelID)
	}

	if err != nil {
		return attempt.Message{}, fmt.Errorf("bedrock: failed to build request: %w", err)
	}

	// Invoke model
	output, err := g.client.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(g.modelID),
		Body:        requestBody,
		ContentType: aws.String("application/json"),
		Accept:      aws.String("application/json"),
	})

	if err != nil {
		return attempt.Message{}, g.handleError(err)
	}

	// Parse response based on model type
	var text string
	if strings.HasPrefix(g.modelID, "anthropic.claude") {
		text, err = g.parseClaudeResponse(output.Body)
	} else if strings.HasPrefix(g.modelID, "amazon.titan") {
		text, err = g.parseTitanResponse(output.Body)
	} else if strings.HasPrefix(g.modelID, "meta.llama") {
		text, err = g.parseLlamaResponse(output.Body)
	}

	if err != nil {
		return attempt.Message{}, fmt.Errorf("bedrock: failed to parse response: %w", err)
	}

	return attempt.NewAssistantMessage(text), nil
}

// buildClaudeRequest builds a request for Anthropic Claude models on Bedrock.
func (g *Bedrock) buildClaudeRequest(conv *attempt.Conversation) ([]byte, error) {
	messages := make([]map[string]string, 0)

	// Convert conversation to messages (skip system message)
	for _, turn := range conv.Turns {
		messages = append(messages, map[string]string{
			"role":    "user",
			"content": turn.Prompt.Content,
		})
		if turn.Response != nil {
			messages = append(messages, map[string]string{
				"role":    "assistant",
				"content": turn.Response.Content,
			})
		}
	}

	req := map[string]any{
		"anthropic_version": "bedrock-2023-05-31",
		"max_tokens":        g.maxTokens,
		"messages":          messages,
		"temperature":       g.temperature,
	}

	// Add system prompt if present
	if conv.System != nil {
		req["system"] = conv.System.Content
	}

	// Add top_p if set
	if g.topP > 0 {
		req["top_p"] = g.topP
	}

	return json.Marshal(req)
}

// parseClaudeResponse parses a response from Anthropic Claude models on Bedrock.
func (g *Bedrock) parseClaudeResponse(body []byte) (string, error) {
	var resp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}

	var text string
	for _, content := range resp.Content {
		if content.Type == "text" {
			text += content.Text
		}
	}

	return text, nil
}

// buildTitanRequest builds a request for Amazon Titan models on Bedrock.
func (g *Bedrock) buildTitanRequest(conv *attempt.Conversation) ([]byte, error) {
	// Flatten conversation into a single prompt
	var prompt string
	if conv.System != nil {
		prompt += conv.System.Content + "\n\n"
	}
	for _, turn := range conv.Turns {
		prompt += "User: " + turn.Prompt.Content + "\n"
		if turn.Response != nil {
			prompt += "Assistant: " + turn.Response.Content + "\n"
		}
	}
	if !strings.HasSuffix(prompt, "Assistant:") {
		prompt += "Assistant:"
	}

	req := map[string]any{
		"inputText": prompt,
		"textGenerationConfig": map[string]any{
			"maxTokenCount": g.maxTokens,
			"temperature":   g.temperature,
		},
	}

	if g.topP > 0 {
		req["textGenerationConfig"].(map[string]any)["topP"] = g.topP
	}

	return json.Marshal(req)
}

// parseTitanResponse parses a response from Amazon Titan models on Bedrock.
func (g *Bedrock) parseTitanResponse(body []byte) (string, error) {
	var resp struct {
		Results []struct {
			OutputText string `json:"outputText"`
		} `json:"results"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}

	if len(resp.Results) == 0 {
		return "", fmt.Errorf("no results in Titan response")
	}

	return resp.Results[0].OutputText, nil
}

// buildLlamaRequest builds a request for Meta Llama models on Bedrock.
func (g *Bedrock) buildLlamaRequest(conv *attempt.Conversation) ([]byte, error) {
	// Flatten conversation into a single prompt with Llama-specific formatting
	var prompt string
	if conv.System != nil {
		prompt += fmt.Sprintf("<s>[INST] <<SYS>>\n%s\n<</SYS>>\n\n", conv.System.Content)
	} else {
		prompt += "<s>[INST] "
	}

	for i, turn := range conv.Turns {
		if i > 0 && turn.Response != nil {
			prompt += "<s>[INST] "
		}
		prompt += turn.Prompt.Content
		if turn.Response != nil {
			prompt += fmt.Sprintf(" [/INST] %s </s>", turn.Response.Content)
		} else {
			prompt += " [/INST]"
		}
	}

	req := map[string]any{
		"prompt":      prompt,
		"max_gen_len": g.maxTokens,
		"temperature": g.temperature,
	}

	if g.topP > 0 {
		req["top_p"] = g.topP
	}

	return json.Marshal(req)
}

// parseLlamaResponse parses a response from Meta Llama models on Bedrock.
func (g *Bedrock) parseLlamaResponse(body []byte) (string, error) {
	var resp struct {
		Generation string `json:"generation"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}

	return resp.Generation, nil
}

// handleError processes API errors.
func (g *Bedrock) handleError(err error) error {
	errStr := err.Error()

	if strings.Contains(errStr, "ThrottlingException") || strings.Contains(errStr, "TooManyRequestsException") {
		return fmt.Errorf("bedrock: rate limit exceeded: %w", err)
	}

	if strings.Contains(errStr, "AccessDeniedException") || strings.Contains(errStr, "UnauthorizedException") {
		return fmt.Errorf("bedrock: authentication error: %w", err)
	}

	if strings.Contains(errStr, "ValidationException") {
		return fmt.Errorf("bedrock: invalid request: %w", err)
	}

	if strings.Contains(errStr, "ServiceUnavailableException") || strings.Contains(errStr, "InternalServerException") {
		return fmt.Errorf("bedrock: service error: %w", err)
	}

	return fmt.Errorf("bedrock: API error: %w", err)
}

// ClearHistory is a no-op for Bedrock generator (stateless per call).
func (g *Bedrock) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *Bedrock) Name() string {
	return "bedrock.Bedrock"
}

// Description returns a human-readable description.
func (g *Bedrock) Description() string {
	return "AWS Bedrock generator supporting Claude, Titan, and Llama models"
}
