// Package paraphrase provides paraphrasing buffs using HuggingFace models.
//
// These buffs create multiple prompt variants by paraphrasing the original,
// testing if different phrasings bypass safety measures.
package paraphrase

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/http"
	"os"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/praetorian-inc/augustus/pkg/ratelimit"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

const (
	// DefaultPegasusModel is the HuggingFace model for Pegasus paraphrasing.
	DefaultPegasusModel = "garak-llm/pegasus_paraphrase"

	// DefaultHuggingFaceAPIURL is the base URL for HuggingFace Inference API.
	DefaultHuggingFaceAPIURL = "https://api-inference.huggingface.co/models"
)

func init() {
	buffs.Register("paraphrase.PegasusT5", func(cfg registry.Config) (buffs.Buff, error) {
		return NewPegasusT5(cfg)
	})
}

// PegasusT5 paraphrases prompts using the Pegasus transformer model.
// It generates 6 paraphrased variants to test if different phrasings
// bypass safety measures.
//
// Python equivalent: garak.buffs.paraphrase.PegasusT5
type PegasusT5 struct {
	// Model is the HuggingFace model name.
	Model string

	// APIURL is the HuggingFace Inference API URL.
	APIURL string

	// APIKey is the HuggingFace API key (from HUGGINGFACE_API_KEY env var).
	APIKey string

	// NumReturnSequences is the number of paraphrases to generate.
	NumReturnSequences int

	// MaxLength is the maximum length of generated text.
	MaxLength int

	// Temperature controls generation randomness.
	Temperature float64

	// HTTPClient is the HTTP client for API requests.
	// Supports both *http.Client and rate-limited clients via HTTPDoer interface.
	HTTPClient ratelimit.HTTPDoer
}

// NewPegasusT5 creates a new PegasusT5 paraphrase buff instance.
//
// Complexity Note: This constructor has elevated cyclomatic complexity (14) due to
// sequential config parameter validation. This is acceptable because:
// - Sequential config validation requires per-field checking (Go idiom)
// - No nested logic or branching complexity (linear flow)
// - High test coverage (≥90%)
// - Config parsing pattern is idiomatic for registry-based factories
//
// Tech debt: Consider extracting to config builder pattern to reduce complexity.
func NewPegasusT5(cfg registry.Config) (*PegasusT5, error) {
	p := &PegasusT5{
		Model:              DefaultPegasusModel,
		APIURL:             DefaultHuggingFaceAPIURL,
		APIKey:             os.Getenv("HUGGINGFACE_API_KEY"),
		NumReturnSequences: 6,
		MaxLength:          60,
		Temperature:        1.5,
		HTTPClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}

	// Override from config
	if v, ok := cfg["model"].(string); ok && v != "" {
		p.Model = v
	}
	if v, ok := cfg["api_url"].(string); ok && v != "" {
		p.APIURL = v
	}
	if v, ok := cfg["api_key"].(string); ok && v != "" {
		p.APIKey = v
	}
	if v, ok := cfg["num_return_sequences"].(int); ok && v > 0 {
		p.NumReturnSequences = v
	}
	if v, ok := cfg["max_length"].(int); ok && v > 0 {
		p.MaxLength = v
	}
	if v, ok := cfg["temperature"].(float64); ok && v > 0 {
		p.Temperature = v
	}

	// Wire rate limiting
	rateLimit := registry.GetFloat64(cfg, "rate_limit", DefaultHuggingFaceRateLimit)
	burstSize := registry.GetFloat64(cfg, "burst_size", DefaultHuggingFaceBurstSize)
	if rateLimit > 0 {
		limiter := ratelimit.NewLimiter(burstSize, rateLimit)
		p.HTTPClient = ratelimit.NewRateLimitedHTTPClient(p.HTTPClient, limiter)
	}

	return p, nil
}

// Name returns the buff's fully qualified name.
func (p *PegasusT5) Name() string {
	return "paraphrase.PegasusT5"
}

// Description returns a human-readable description.
func (p *PegasusT5) Description() string {
	return "Paraphrasing buff using Pegasus model - generates 6 paraphrased variants"
}

// Transform yields transformed attempts from a single input.
// First yields the original, then paraphrased versions.
func (p *PegasusT5) Transform(a *attempt.Attempt) iter.Seq[*attempt.Attempt] {
	return func(yield func(*attempt.Attempt) bool) {
		// First yield the original (matches Python behavior)
		original := a.Copy()
		if !yield(original) {
			return
		}

		// Get paraphrases from API
		paraphrases, err := p.getParaphrases(a.Prompt)
		if err != nil {
			// On error, just return (original already yielded)
			return
		}

		// Deduplicate paraphrases
		seen := map[string]bool{a.Prompt: true}
		for _, para := range paraphrases {
			if para == "" || seen[para] {
				continue
			}
			seen[para] = true

			paraphrased := a.Copy()
			paraphrased.Prompt = para
			paraphrased.Prompts = []string{para}
			if !yield(paraphrased) {
				return
			}
		}
	}
}

// Buff transforms a slice of attempts, returning modified versions.
func (p *PegasusT5) Buff(ctx context.Context, attempts []*attempt.Attempt) ([]*attempt.Attempt, error) {
	return buffs.DefaultBuff(ctx, attempts, p)
}

// getParaphrases calls the HuggingFace API to generate paraphrases.
func (p *PegasusT5) getParaphrases(text string) ([]string, error) {
	// Build request payload
	payload := map[string]any{
		"inputs": text,
		"parameters": map[string]any{
			"max_length":           p.MaxLength,
			"num_return_sequences": p.NumReturnSequences,
			"num_beams":            p.NumReturnSequences,
			"temperature":          p.Temperature,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	// Build URL - handle both full URL and base URL cases
	url := p.APIURL
	if url == DefaultHuggingFaceAPIURL {
		url = fmt.Sprintf("%s/%s", p.APIURL, p.Model)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if p.APIKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", p.APIKey))
	}

	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api error (status %d): %s", resp.StatusCode, string(respBody))
	}

	// Parse response - HuggingFace returns array of strings for text2text-generation
	var paraphrases []string
	if err := json.Unmarshal(respBody, &paraphrases); err != nil {
		// Try alternative format: array of objects with "generated_text"
		var altResp []struct {
			GeneratedText string `json:"generated_text"`
		}
		if err := json.Unmarshal(respBody, &altResp); err != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		for _, r := range altResp {
			paraphrases = append(paraphrases, r.GeneratedText)
		}
	}

	return paraphrases, nil
}

