package multiturn

import "testing"

func TestContextTokenLimit(t *testing.T) {
	tests := []struct {
		model    string
		expected int
	}{
		{"", defaultContextTokenLimit},
		{"unknown-model", defaultContextTokenLimit},
		{"gpt-4", 7500},
		{"gpt-4-0613", 7500},
		{"gpt-4o", 125000},
		{"gpt-4o-mini", 125000},
		{"gpt-4-turbo", 125000},
		{"gpt-4-turbo-preview", 125000},
		{"gpt-4-32k", 31000},
		{"gpt-3.5-turbo", 15000},
		{"gpt-3.5-turbo-16k", 15000},
		{"claude-3-5-sonnet-20241022", 195000},
		{"claude-3-opus-20240229", 195000},
		{"claude-opus-4-20250514", 195000},
		{"gemini-2-flash", 1000000},
		{"llama-3.1-70b-versatile", 125000},
		{"llama-2-70b", 3500},
		{"mistral-large-latest", 125000},
		{"deepseek-chat", 125000},
		{"command-r-plus", 125000},
		// Case insensitive
		{"GPT-4", 7500},
		{"Claude-3-5-Sonnet", 195000},
	}
	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			got := contextTokenLimit(tt.model)
			if got != tt.expected {
				t.Errorf("contextTokenLimit(%q) = %d, want %d", tt.model, got, tt.expected)
			}
		})
	}
}

func TestResponseCharBudget(t *testing.T) {
	tests := []struct {
		model    string
		expected int
	}{
		// >= 100K context tokens -> 2000 char budget
		{"gpt-4o", 2000},
		{"claude-3-5-sonnet-20241022", 2000},
		{"gemini-2-flash", 2000},
		{"llama-3.1-70b-versatile", 2000},
		// >= 30K context tokens -> 1000 char budget
		{"gpt-4-32k", 1000},
		// >= 8K context tokens -> 600 char budget
		{"gpt-3.5-turbo", 600},
		// < 8K context tokens -> 300 char budget (gpt-4 = 7500, llama-2 = 3500)
		{"gpt-4", 300},
		{"llama-2-70b", 300},
		// Unknown/empty models default to 7500 tokens (< 8K) -> 300
		{"unknown-model", 300},
		{"", 300},
	}
	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			got := ResponseCharBudget(tt.model)
			if got != tt.expected {
				t.Errorf("ResponseCharBudget(%q) = %d, want %d", tt.model, got, tt.expected)
			}
		})
	}
}
