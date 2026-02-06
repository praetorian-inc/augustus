// Package lrl provides the Low Resource Language buff for prompt translation.
//
// LRLBuff translates prompts into low-resource languages (Estonian, Indonesian,
// Latvian, Slovak, Slovenian) to test LLM robustness against multilingual attacks.
// This exploits the fact that LLM safety training is often weaker in low-resource
// languages. Uses the DeepL API for translation.
//
// Reference: https://arxiv.org/abs/2310.02446
package lrl

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"os"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/praetorian-inc/augustus/pkg/ratelimit"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// LowResourceLanguages supported by DeepL for this buff.
// ET = Estonian, ID = Indonesian, LV = Latvian, SK = Slovak, SL = Slovenian
var LowResourceLanguages = []string{"ET", "ID", "LV", "SK", "SL"}

// Translator defines the interface for translation services.
// This abstraction allows for mocking in tests and different implementations.
type Translator interface {
	// Translate translates text to the target language.
	Translate(ctx context.Context, text, targetLang string) (string, error)
}

// LRLBuff translates prompts into low-resource languages.
// It implements the buffs.Buff interface.
type LRLBuff struct {
	translator Translator
	apiKey     string
}

// Compile-time check that LRLBuff implements buffs.Buff.
var _ buffs.Buff = (*LRLBuff)(nil)

// init registers the LRLBuff with the global registry.
func init() {
	buffs.Register("lrl.LRLBuff", NewLRLBuff)
}

// NewLRLBuff creates a new LRLBuff instance.
// Requires DEEPL_API_KEY environment variable or "api_key" in config.
func NewLRLBuff(cfg registry.Config) (buffs.Buff, error) {
	apiKey := ""

	// Check config first, then environment variable
	if key, ok := cfg["api_key"].(string); ok && key != "" {
		apiKey = key
	} else {
		apiKey = os.Getenv("DEEPL_API_KEY")
	}

	if apiKey == "" {
		return nil, errors.New("DEEPL_API_KEY environment variable or api_key config required")
	}

	// Create translator with optional rate limiting
	var translator Translator = NewDeepLTranslator(apiKey)

	// Parse rate limit config (default: 5 RPS, burst 20)
	rateLimit := registry.GetFloat64(cfg, "rate_limit", DefaultDeepLRateLimit)
	burstSize := registry.GetFloat64(cfg, "burst_size", DefaultDeepLBurstSize)
	if rateLimit > 0 {
		limiter := ratelimit.NewLimiter(burstSize, rateLimit)
		translator = NewRateLimitedTranslator(translator, limiter)
	}

	return &LRLBuff{
		translator: translator,
		apiKey:     apiKey,
	}, nil
}

// Name returns the fully qualified name of the buff.
func (b *LRLBuff) Name() string {
	return "lrl.LRLBuff"
}

// Description returns a human-readable description of the buff.
func (b *LRLBuff) Description() string {
	return "Translates prompts into low-resource languages (ET, ID, LV, SK, SL) using DeepL API to test LLM multilingual robustness"
}

// HasPostBuffHook indicates this buff should process responses after generation.
func (b *LRLBuff) HasPostBuffHook() bool {
	return true
}

// Transform translates a single attempt into multiple attempts, one per language.
// Uses iter.Seq for lazy generation (Go 1.23+).
func (b *LRLBuff) Transform(a *attempt.Attempt) iter.Seq[*attempt.Attempt] {
	return func(yield func(*attempt.Attempt) bool) {
		ctx := context.Background()
		originalPrompt := a.Prompt

		for _, lang := range LowResourceLanguages {
			translated, err := b.translator.Translate(ctx, originalPrompt, lang)
			if err != nil {
				// On translation error, return original attempt with error metadata
				errAttempt := a.Copy()
				errAttempt.WithMetadata("lrl_error", err.Error())
				errAttempt.WithMetadata("lrl_target_lang", lang)
				errAttempt.WithMetadata("original_prompt", originalPrompt)
				yield(errAttempt)
				return // Stop iteration on error
			}

			// Create new attempt with translated prompt
			newAttempt := a.Copy()
			newAttempt.Prompt = translated
			newAttempt.Prompts = []string{translated}
			newAttempt.WithMetadata("original_prompt", originalPrompt)
			newAttempt.WithMetadata("lrl_target_lang", lang)

			if !yield(newAttempt) {
				return
			}
		}
	}
}

// Buff transforms a batch of attempts.
// This is the primary interface method that processes all attempts.
//
// LRL uses a custom Buff loop (rather than buffs.DefaultBuff) because it
// needs to inspect each transformed attempt for lrl_error metadata and
// short-circuit with an error if translation failed.
func (b *LRLBuff) Buff(ctx context.Context, attempts []*attempt.Attempt) ([]*attempt.Attempt, error) {
	var results []*attempt.Attempt

	for _, a := range attempts {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		for transformed := range b.Transform(a) {
			results = append(results, transformed)

			// Check if there was an error during transform
			if errVal, ok := transformed.GetMetadata("lrl_error"); ok {
				return results, fmt.Errorf("transform error: %s", errVal)
			}
		}
	}

	return results, nil
}

// Untransform translates outputs back to English.
// This is called after generation to convert responses back for detection.
func (b *LRLBuff) Untransform(ctx context.Context, a *attempt.Attempt) (*attempt.Attempt, error) {
	if len(a.Outputs) == 0 {
		return a, nil
	}

	// Store original responses
	originalResponses := make([]string, len(a.Outputs))
	copy(originalResponses, a.Outputs)
	a.WithMetadata("original_responses", originalResponses)

	// Translate each output back to English
	translatedOutputs := make([]string, 0, len(a.Outputs))
	for _, output := range a.Outputs {
		translated, err := b.translator.Translate(ctx, output, "EN-US")
		if err != nil {
			return nil, fmt.Errorf("untransform failed: %w", err)
		}
		translatedOutputs = append(translatedOutputs, translated)
	}

	a.Outputs = translatedOutputs
	return a, nil
}


// Get retrieves a buff factory by name from the registry.
func Get(name string) (func(registry.Config) (buffs.Buff, error), bool) {
	return buffs.Get(name)
}
