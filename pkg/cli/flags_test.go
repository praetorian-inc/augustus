package cli

import (
	"reflect"
	"sort"
	"testing"
)

// TestParseGlob tests glob pattern matching against available plugin names.
func TestParseGlob(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		available []string
		want      []string
		wantErr   bool
	}{
		{
			name:      "exact match",
			pattern:   "dan",
			available: []string{"dan", "encoding", "continuation"},
			want:      []string{"dan"},
			wantErr:   false,
		},
		{
			name:      "wildcard suffix",
			pattern:   "dan.*",
			available: []string{"dan.Dan10", "dan.Dan11", "encoding", "continuation"},
			want:      []string{"dan.Dan10", "dan.Dan11"},
			wantErr:   false,
		},
		{
			name:      "wildcard prefix",
			pattern:   "*.Dan10",
			available: []string{"dan.Dan10", "test.Dan10", "encoding"},
			want:      []string{"dan.Dan10", "test.Dan10"},
			wantErr:   false,
		},
		{
			name:      "wildcard both sides",
			pattern:   "*dan*",
			available: []string{"dan.Dan10", "autodan", "encoding", "snowball"},
			want:      []string{"autodan", "dan.Dan10"},
			wantErr:   false,
		},
		{
			name:      "no matches",
			pattern:   "nonexistent",
			available: []string{"dan", "encoding", "continuation"},
			want:      []string{},
			wantErr:   false,
		},
		{
			name:      "empty pattern",
			pattern:   "",
			available: []string{"dan", "encoding"},
			want:      []string{},
			wantErr:   true,
		},
		{
			name:      "case insensitive match",
			pattern:   "Dan.*",
			available: []string{"dan.Dan10", "dan.Dan11"},
			want:      []string{"dan.Dan10", "dan.Dan11"},
			wantErr:   false,
		},
		{
			name:      "multiple wildcard segments",
			pattern:   "encoding.*",
			available: []string{"encoding.Base64", "encoding.Hex", "dan", "continuation"},
			want:      []string{"encoding.Base64", "encoding.Hex"},
			wantErr:   false,
		},
		{
			name:      "all wildcard",
			pattern:   "*",
			available: []string{"dan", "encoding", "continuation"},
			want:      []string{"continuation", "dan", "encoding"},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseGlob(tt.pattern, tt.available)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseGlob() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// Sort both slices for comparison
			sort.Strings(got)
			sort.Strings(tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseGlob() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParseCommaSeparatedGlobs tests parsing comma-separated glob patterns.
func TestParseCommaSeparatedGlobs(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		available []string
		want      []string
		wantErr   bool
	}{
		{
			name:      "single pattern",
			input:     "dan.*",
			available: []string{"dan.Dan10", "dan.Dan11", "encoding"},
			want:      []string{"dan.Dan10", "dan.Dan11"},
			wantErr:   false,
		},
		{
			name:      "multiple patterns",
			input:     "dan.*,encoding.*",
			available: []string{"dan.Dan10", "dan.Dan11", "encoding.Base64", "continuation"},
			want:      []string{"dan.Dan10", "dan.Dan11", "encoding.Base64"},
			wantErr:   false,
		},
		{
			name:      "patterns with spaces",
			input:     "dan.*, encoding.*",
			available: []string{"dan.Dan10", "encoding.Base64", "continuation"},
			want:      []string{"dan.Dan10", "encoding.Base64"},
			wantErr:   false,
		},
		{
			name:      "overlapping patterns",
			input:     "dan.*,dan.Dan10",
			available: []string{"dan.Dan10", "dan.Dan11"},
			want:      []string{"dan.Dan10", "dan.Dan11"}, // Should deduplicate
			wantErr:   false,
		},
		{
			name:      "empty input",
			input:     "",
			available: []string{"dan", "encoding"},
			want:      []string{},
			wantErr:   true,
		},
		{
			name:      "whitespace only",
			input:     "  ,  ",
			available: []string{"dan", "encoding"},
			want:      []string{},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCommaSeparatedGlobs(tt.input, tt.available)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCommaSeparatedGlobs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// Sort both slices for comparison
			sort.Strings(got)
			sort.Strings(tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCommaSeparatedGlobs() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCLIFlags tests the CLIFlags structure.
func TestCLIFlags(t *testing.T) {
	flags := &CLIFlags{
		Probes:     []string{"dan.*", "encoding.*"},
		Detectors:  []string{"dan", "encoding"},
		Generators: []string{"openai"},
		Config:     `{"api_key": "test"}`,
		Output:     "results.jsonl",
	}

	if len(flags.Probes) != 2 {
		t.Errorf("Expected 2 probes, got %d", len(flags.Probes))
	}
	if len(flags.Detectors) != 2 {
		t.Errorf("Expected 2 detectors, got %d", len(flags.Detectors))
	}
	if len(flags.Generators) != 1 {
		t.Errorf("Expected 1 generator, got %d", len(flags.Generators))
	}
}
