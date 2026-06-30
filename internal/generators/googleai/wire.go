// Package googleai holds the shared wire-format types and error handling for
// Google's Gemini generateContent REST schema.
//
// Google publishes a single Gemini REST schema that is served by two different
// endpoints with different auth and URL conventions:
//   - the direct Gemini API (generativelanguage.googleapis.com), wrapped by the
//     gemini generator (API-key auth), and
//   - Vertex AI (…-aiplatform.googleapis.com), wrapped by the vertex generator
//     (project/location URL, bearer auth).
//
// The request/response bodies and the error envelope are identical across both,
// so they live here to avoid duplicating the types and the status-code mapping
// in each generator. Endpoint construction, auth, and image handling differ per
// generator and stay in the respective packages.
package googleai

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// InlineData is a base64-encoded media attachment within a part.
// Field names are snake_case per the canonical Gemini REST spec
// (https://ai.google.dev/api/generate-content). Proto3 JSON acceptance allows
// camelCase too, but we emit the canonical form.
type InlineData struct {
	MimeType string `json:"mime_type"`
	Data     string `json:"data"`
}

// ContentPart is a single part within a content block. Exactly one of Text,
// InlineData, FunctionCall, or FunctionResponse is set per part.
type ContentPart struct {
	Text             string            `json:"text,omitempty"`
	InlineData       *InlineData       `json:"inline_data,omitempty"`
	FunctionCall     *FunctionCall     `json:"functionCall,omitempty"`
	FunctionResponse *FunctionResponse `json:"functionResponse,omitempty"`
}

// FunctionCall represents a function call made by the model.
type FunctionCall struct {
	Name string         `json:"name"`
	Args map[string]any `json:"args"`
}

// FunctionResponse represents a function (tool) result sent back to the model.
// Gemini matches responses to calls by function name (not by call ID).
type FunctionResponse struct {
	Name     string         `json:"name"`
	Response map[string]any `json:"response"`
}

// ToolDeclaration holds the function declarations for a set of tools.
type ToolDeclaration struct {
	FunctionDeclarations []FunctionDeclaration `json:"functionDeclarations"`
}

// FunctionDeclaration describes a single callable function.
type FunctionDeclaration struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Parameters  any    `json:"parameters,omitempty"`
}

// ToolConfig controls how the model selects tools.
type ToolConfig struct {
	FunctionCallingConfig *FunctionCallingConfig `json:"functionCallingConfig,omitempty"`
}

// FunctionCallingConfig specifies the tool selection mode.
type FunctionCallingConfig struct {
	Mode                 string   `json:"mode"`
	AllowedFunctionNames []string `json:"allowedFunctionNames,omitempty"`
}

// Content is a single message turn in the contents array.
type Content struct {
	Role  string        `json:"role"`
	Parts []ContentPart `json:"parts"`
}

// GenerationConfig holds Gemini's sampling parameters.
type GenerationConfig struct {
	Temperature     float64  `json:"temperature,omitempty"`
	MaxOutputTokens int      `json:"maxOutputTokens,omitempty"`
	TopP            float64  `json:"topP,omitempty"`
	TopK            int      `json:"topK,omitempty"`
	StopSequences   []string `json:"stopSequences,omitempty"`
}

// GenerateRequest is the :generateContent request body.
type GenerateRequest struct {
	Contents          []Content         `json:"contents"`
	SystemInstruction *Content          `json:"systemInstruction,omitempty"`
	GenerationConfig  *GenerationConfig `json:"generationConfig,omitempty"`
	Tools             []ToolDeclaration `json:"tools,omitempty"`
	ToolConfig        *ToolConfig       `json:"toolConfig,omitempty"`
}

// Candidate is one response candidate.
type Candidate struct {
	Content      Content `json:"content"`
	FinishReason string  `json:"finishReason"`
}

// UsageMetadata is Gemini's token-usage block.
type UsageMetadata struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

// GenerateResponse is the :generateContent response body.
type GenerateResponse struct {
	Candidates    []Candidate   `json:"candidates"`
	UsageMetadata UsageMetadata `json:"usageMetadata"`
}

// errorResponse is the Gemini API error envelope.
type errorResponse struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

// HandleError converts a non-200 generateContent response into a descriptive
// error, mapping the HTTP status to a stable, classifiable message. The
// provider prefix (e.g. "gemini", "vertex") identifies the calling generator.
func HandleError(provider string, statusCode int, body []byte) error {
	var errResp errorResponse
	if err := json.Unmarshal(body, &errResp); err != nil {
		return fmt.Errorf("%s: HTTP %d: %s", provider, statusCode, string(body))
	}
	errCode := errResp.Error.Code
	errMsg := errResp.Error.Message
	errStatus := errResp.Error.Status

	switch statusCode {
	case http.StatusTooManyRequests:
		return fmt.Errorf("%s: rate limit exceeded: %s", provider, errMsg)
	case http.StatusBadRequest:
		return fmt.Errorf("%s: bad request (%s): %s", provider, errStatus, errMsg)
	case http.StatusUnauthorized:
		return fmt.Errorf("%s: authentication error: %s", provider, errMsg)
	case http.StatusForbidden:
		return fmt.Errorf("%s: permission denied: %s", provider, errMsg)
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return fmt.Errorf("%s: server error (%d): %s", provider, statusCode, errMsg)
	default:
		return fmt.Errorf("%s: API error (%d, %s): %s", provider, errCode, errStatus, errMsg)
	}
}
