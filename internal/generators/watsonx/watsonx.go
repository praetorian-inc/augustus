// Package watsonx provides an IBM Watson X generator for Augustus.
//
// This package implements the Generator interface for IBM Watson X's text generation API.
// It supports both project-based and deployment-based models with IAM authentication.
//
// Key features:
//   - IAM bearer token authentication
//   - Supports project_id (development) and deployment_id (production)
//   - Handles empty prompt edge cases
//   - Proper error handling for rate limits and auth failures
package watsonx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("watsonx.WatsonX", NewWatsonX)
}

// Default configuration values.
const (
	defaultMaxTokens = 900
	defaultVersion   = "2023-05-29"
)

// WatsonX is a generator that wraps the IBM Watson X API.
type WatsonX struct {
	client       *http.Client
	apiKey       string
	url          string
	iamURL       string
	projectID    string
	deploymentID string
	model        string
	region       string
	version      string
	maxTokens    int
	bearerToken  string
}

// NewWatsonX creates a new Watson X generator from configuration.
func NewWatsonX(cfg registry.Config) (generators.Generator, error) {
	g := &WatsonX{
		client:    &http.Client{},
		version:   defaultVersion,
		maxTokens: defaultMaxTokens,
		iamURL:    "https://iam.cloud.ibm.com/identity/token",
	}

	// Required: API key
	apiKey, ok := cfg["api_key"].(string)
	if !ok || apiKey == "" {
		return nil, fmt.Errorf("watsonx generator requires 'api_key' configuration")
	}
	g.apiKey = apiKey

	// Required: model
	model, ok := cfg["model"].(string)
	if !ok || model == "" {
		return nil, fmt.Errorf("watsonx generator requires 'model' configuration")
	}
	g.model = model

	// Required: region
	region, ok := cfg["region"].(string)
	if !ok || region == "" {
		return nil, fmt.Errorf("watsonx generator requires 'region' configuration")
	}
	g.region = region

	// Required: project_id OR deployment_id (at least one)
	projectID, hasProject := cfg["project_id"].(string)
	deploymentID, hasDeployment := cfg["deployment_id"].(string)

	if !hasProject && !hasDeployment {
		return nil, fmt.Errorf("watsonx generator requires either 'project_id' or 'deployment_id' configuration")
	}

	g.projectID = projectID
	g.deploymentID = deploymentID

	// Optional: max_tokens
	if maxTokens, ok := cfg["max_tokens"].(int); ok {
		g.maxTokens = maxTokens
	} else if maxTokens, ok := cfg["max_tokens"].(float64); ok {
		g.maxTokens = int(maxTokens)
	}

	// Optional: version
	if version, ok := cfg["version"].(string); ok && version != "" {
		g.version = version
	}

	// Optional: custom URL (for testing)
	if customURL, ok := cfg["url"].(string); ok && customURL != "" {
		g.url = customURL
	} else {
		// Build Watson X URL from region
		g.url = fmt.Sprintf("https://%s.ml.cloud.ibm.com", g.region)
	}

	// Optional: custom IAM URL (for testing)
	if iamURL, ok := cfg["iam_url"].(string); ok && iamURL != "" {
		g.iamURL = iamURL
	}

	return g, nil
}

// Generate sends the conversation to Watson X and returns responses.
// Since Watson X doesn't support multiple completions in a single call,
// multiple generations require multiple API calls.
func (g *WatsonX) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
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
func (g *WatsonX) generateOne(ctx context.Context, conv *attempt.Conversation) (attempt.Message, error) {
	// Ensure we have a bearer token
	if g.bearerToken == "" {
		if err := g.setBearerToken(ctx); err != nil {
			return attempt.Message{}, fmt.Errorf("watsonx: failed to get bearer token: %w", err)
		}
	}

	// Get the prompt text (handle empty prompt)
	promptText := conv.LastPrompt()
	if promptText == "" {
		promptText = "\x00" // Null byte for empty prompt
	}

	// Choose generation method based on configuration
	var text string
	var err error

	if g.deploymentID != "" {
		text, err = g.generateWithDeployment(ctx, promptText)
	} else {
		text, err = g.generateWithProject(ctx, promptText)
	}

	if err != nil {
		return attempt.Message{}, err
	}

	return attempt.NewAssistantMessage(text), nil
}

// setBearerToken gets a new IAM bearer token using the API key.
func (g *WatsonX) setBearerToken(ctx context.Context) error {
	data := url.Values{}
	data.Set("grant_type", "urn:ibm:params:oauth:grant-type:apikey")
	data.Set("apikey", g.apiKey)

	req, err := http.NewRequestWithContext(ctx, "POST", g.iamURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("watsonx: failed to create IAM request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("watsonx: failed to get IAM token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("IAM token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("watsonx: failed to decode IAM response: %w", err)
	}

	g.bearerToken = "Bearer " + result.AccessToken
	return nil
}

// generateWithProject generates text using a project ID (development/training models).
func (g *WatsonX) generateWithProject(ctx context.Context, prompt string) (string, error) {
	apiURL := fmt.Sprintf("%s/ml/v1/text/generation?version=%s", g.url, g.version)

	requestBody := map[string]any{
		"input": prompt,
		"parameters": map[string]any{
			"decoding_method": "greedy",
			"max_new_tokens":  g.maxTokens,
			"min_new_tokens":  0,
			"repetition_penalty": 1,
		},
		"model_id":   g.model,
		"project_id": g.projectID,
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("watsonx: failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("watsonx: failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", g.bearerToken)

	resp, err := g.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("watsonx: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", g.handleError(resp.StatusCode, body)
	}

	var result struct {
		Results []struct {
			GeneratedText string `json:"generated_text"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("watsonx: failed to decode response: %w", err)
	}

	if len(result.Results) == 0 {
		return "", fmt.Errorf("watsonx: no results in response")
	}

	return result.Results[0].GeneratedText, nil
}

// generateWithDeployment generates text using a deployment ID (production models).
func (g *WatsonX) generateWithDeployment(ctx context.Context, prompt string) (string, error) {
	apiURL := fmt.Sprintf("%s/ml/v1/deployments/%s/text/generation?version=%s",
		g.url, g.deploymentID, g.version)

	requestBody := map[string]any{
		"parameters": map[string]any{
			"prompt_variables": map[string]string{
				"input": prompt,
			},
		},
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("watsonx: failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("watsonx: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", g.bearerToken)

	resp, err := g.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("watsonx: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", g.handleError(resp.StatusCode, body)
	}

	var result struct {
		Results []struct {
			GeneratedText string `json:"generated_text"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("watsonx: failed to decode response: %w", err)
	}

	if len(result.Results) == 0 {
		return "", fmt.Errorf("watsonx: no results in response")
	}

	return result.Results[0].GeneratedText, nil
}

// handleError processes API errors.
func (g *WatsonX) handleError(statusCode int, body []byte) error {
	bodyStr := string(body)

	switch statusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("watsonx: authentication error (status %d): %s", statusCode, bodyStr)
	case http.StatusTooManyRequests:
		return fmt.Errorf("watsonx: rate limit exceeded (status %d): %s", statusCode, bodyStr)
	case http.StatusBadRequest:
		return fmt.Errorf("watsonx: invalid request (status %d): %s", statusCode, bodyStr)
	case http.StatusServiceUnavailable, http.StatusInternalServerError:
		return fmt.Errorf("watsonx: service error (status %d): %s", statusCode, bodyStr)
	default:
		return fmt.Errorf("watsonx: API error (status %d): %s", statusCode, bodyStr)
	}
}

// ClearHistory is a no-op for Watson X generator (stateless per call).
func (g *WatsonX) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *WatsonX) Name() string {
	return "watsonx.WatsonX"
}

// Description returns a human-readable description.
func (g *WatsonX) Description() string {
	return "IBM Watson X generator supporting project-based and deployment-based models with IAM authentication"
}
