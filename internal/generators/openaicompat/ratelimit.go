package openaicompat

import (
	"errors"

	goopenai "github.com/sashabaranov/go-openai"
)

// RateLimitError wraps an error to indicate it's a rate limit error.
// This is used by OpenAI-compatible generators (groq, anyscale, etc.) to
// preserve rate limit status through error wrapping for retry logic.
// WrapError automatically returns a *RateLimitError for HTTP 429 responses.
type RateLimitError struct {
	Err error
}

func (e *RateLimitError) Error() string {
	return e.Err.Error()
}

func (e *RateLimitError) Unwrap() error {
	return e.Err
}

// IsRateLimitError checks if an error (or any error in its chain) is a rate
// limit error. It returns true if the chain contains a *RateLimitError or an
// OpenAI API error with HTTP status code 429.
func IsRateLimitError(err error) bool {
	// Check for our wrapped RateLimitError type (anywhere in the chain)
	var rateLimitErr *RateLimitError
	if errors.As(err, &rateLimitErr) {
		return true
	}

	// Check for OpenAI API error with 429 status (anywhere in the chain)
	var apiErr *goopenai.APIError
	if errors.As(err, &apiErr) {
		return apiErr.HTTPStatusCode == 429
	}
	return false
}
