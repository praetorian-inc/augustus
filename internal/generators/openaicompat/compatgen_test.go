// Package openaicompat provides shared configuration for OpenAI-compatible generators.
package openaicompat

import (
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// TestCompatGenerator_WithRetry verifies that RetryConfig is properly stored in the generator.
func TestCompatGenerator_WithRetry(t *testing.T) {
	pc := ProviderConfig{
		Name:           "test.Retry",
		Provider:       "test",
		DefaultBaseURL: "https://api.test.com/v1",
		EnvVar:         "TEST_API_KEY",
		RetryConfig: &RetryConfig{
			MaxRetries:  3,
			InitialWait: 1 * time.Second,
			MaxWait:     10 * time.Second,
		},
	}

	// Test that retry config is stored
	cfg := registry.Config{
		"model":   "test-model",
		"api_key": "test-key",
	}

	gen, err := NewGenerator(cfg, pc)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify retry config was applied (this will fail until we add the field)
	if gen.retryConfig == nil {
		t.Error("Expected retry config to be set")
	}
	if gen.retryConfig.MaxRetries != 3 {
		t.Errorf("Expected MaxRetries 3, got %d", gen.retryConfig.MaxRetries)
	}
	if gen.retryConfig.InitialWait != 1*time.Second {
		t.Errorf("Expected InitialWait 1s, got %v", gen.retryConfig.InitialWait)
	}
	if gen.retryConfig.MaxWait != 10*time.Second {
		t.Errorf("Expected MaxWait 10s, got %v", gen.retryConfig.MaxWait)
	}
}

// TestCompatGenerator_WithoutRetry verifies that nil RetryConfig is handled correctly.
func TestCompatGenerator_WithoutRetry(t *testing.T) {
	pc := ProviderConfig{
		Name:           "test.NoRetry",
		Provider:       "test",
		DefaultBaseURL: "https://api.test.com/v1",
		EnvVar:         "TEST_API_KEY",
		// No RetryConfig
	}

	cfg := registry.Config{
		"model":   "test-model",
		"api_key": "test-key",
	}

	gen, err := NewGenerator(cfg, pc)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify retry config is nil (no retry)
	if gen.retryConfig != nil {
		t.Error("Expected retry config to be nil when not provided")
	}
}
