// Package openaicompat provides shared configuration for OpenAI-compatible generators.
package openaicompat

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestBaseConfigFromMap_ValidConfig(t *testing.T) {
	m := registry.Config{
		"model":       "gpt-4",
		"api_key":     "test-key",
		"temperature": 0.7,
		"max_tokens":  1000,
		"top_p":       0.9,
		"base_url":    "https://api.test.com",
	}

	cfg, err := BaseConfigFromMap(m, "TEST_API_KEY", "testprovider")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if cfg.Model != "gpt-4" {
		t.Errorf("Expected model 'gpt-4', got '%s'", cfg.Model)
	}
	if cfg.APIKey != "test-key" {
		t.Errorf("Expected api_key 'test-key', got '%s'", cfg.APIKey)
	}
	if cfg.Temperature != 0.7 {
		t.Errorf("Expected temperature 0.7, got %f", cfg.Temperature)
	}
	if cfg.MaxTokens != 1000 {
		t.Errorf("Expected max_tokens 1000, got %d", cfg.MaxTokens)
	}
	if cfg.TopP != 0.9 {
		t.Errorf("Expected top_p 0.9, got %f", cfg.TopP)
	}
	if cfg.BaseURL != "https://api.test.com" {
		t.Errorf("Expected base_url 'https://api.test.com', got '%s'", cfg.BaseURL)
	}
}

func TestBaseConfigFromMap_MissingModel(t *testing.T) {
	m := registry.Config{
		"api_key": "test-key",
	}

	_, err := BaseConfigFromMap(m, "TEST_API_KEY", "testprovider")
	if err == nil {
		t.Fatal("Expected error for missing model, got nil")
	}
}

func TestBaseConfigFromMap_DefaultValues(t *testing.T) {
	m := registry.Config{
		"model":   "gpt-4",
		"api_key": "test-key",
	}

	cfg, err := BaseConfigFromMap(m, "TEST_API_KEY", "testprovider")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify defaults
	if cfg.Temperature != 0.7 {
		t.Errorf("Expected default temperature 0.7, got %f", cfg.Temperature)
	}
	if cfg.MaxTokens != 4096 {
		t.Errorf("Expected default max_tokens 4096, got %d", cfg.MaxTokens)
	}
	if cfg.TopP != 1.0 {
		t.Errorf("Expected default top_p 1.0, got %f", cfg.TopP)
	}
}
