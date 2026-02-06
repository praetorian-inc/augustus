package lrl

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
)

const (
	// DeepL API endpoints
	deepLFreeEndpoint = "https://api-free.deepl.com/v2/translate"
	deepLProEndpoint  = "https://api.deepl.com/v2/translate"
)

// DeepLTranslator implements the Translator interface using the DeepL API.
type DeepLTranslator struct {
	apiKey     string
	endpoint   string
	httpClient *http.Client
}

// NewDeepLTranslator creates a new DeepL translator.
// The API key determines whether to use free or pro endpoint.
// Keys ending in ":fx" use the free API.
func NewDeepLTranslator(apiKey string) *DeepLTranslator {
	endpoint := deepLProEndpoint
	if strings.HasSuffix(apiKey, ":fx") {
		endpoint = deepLFreeEndpoint
	}

	return &DeepLTranslator{
		apiKey:   apiKey,
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// translateRequest represents the DeepL API request body.
type translateRequest struct {
	Text       []string `json:"text"`
	TargetLang string   `json:"target_lang"`
}

// translateResponse represents the DeepL API response.
type translateResponse struct {
	Translations []struct {
		DetectedSourceLanguage string `json:"detected_source_language"`
		Text                   string `json:"text"`
	} `json:"translations"`
}

// errorResponse represents a DeepL API error response.
type errorResponse struct {
	Message string `json:"message"`
}

// Translate translates text to the target language using DeepL API.
func (t *DeepLTranslator) Translate(ctx context.Context, text, targetLang string) (string, error) {
	if text == "" {
		return "", nil
	}

	// Build request body
	reqBody := translateRequest{
		Text:       []string{text},
		TargetLang: targetLang,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "DeepL-Auth-Key "+t.apiKey)
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Handle error responses
	if resp.StatusCode != http.StatusOK {
		var errResp errorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Message != "" {
			return "", fmt.Errorf("DeepL API error (%d): %s", resp.StatusCode, errResp.Message)
		}
		return "", fmt.Errorf("DeepL API error: status %d", resp.StatusCode)
	}

	// Parse successful response
	var result translateResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(result.Translations) == 0 {
		return "", fmt.Errorf("no translations returned")
	}

	return result.Translations[0].Text, nil
}

// TranslateFormEncoded translates using form-encoded request (alternative method).
// Some DeepL SDK implementations use form encoding instead of JSON.
func (t *DeepLTranslator) TranslateFormEncoded(ctx context.Context, text, targetLang string) (string, error) {
	if text == "" {
		return "", nil
	}

	// Build form data
	formData := url.Values{}
	formData.Set("text", text)
	formData.Set("target_lang", targetLang)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "DeepL-Auth-Key "+t.apiKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Execute request
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Handle error responses
	if resp.StatusCode != http.StatusOK {
		var errResp errorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Message != "" {
			return "", fmt.Errorf("DeepL API error (%d): %s", resp.StatusCode, errResp.Message)
		}
		return "", fmt.Errorf("DeepL API error: status %d", resp.StatusCode)
	}

	// Parse successful response
	var result translateResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(result.Translations) == 0 {
		return "", fmt.Errorf("no translations returned")
	}

	return result.Translations[0].Text, nil
}

// SetEndpoint overrides the API endpoint (useful for testing).
func (t *DeepLTranslator) SetEndpoint(endpoint string) {
	t.endpoint = endpoint
}

// SetHTTPClient sets a custom HTTP client (useful for testing).
func (t *DeepLTranslator) SetHTTPClient(client *http.Client) {
	t.httpClient = client
}
