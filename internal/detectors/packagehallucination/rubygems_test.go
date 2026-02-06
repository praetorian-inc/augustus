package packagehallucination

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestNewRubyGems(t *testing.T) {
	detector, err := NewRubyGems(registry.Config{})
	if err != nil {
		t.Fatalf("NewRubyGems() error = %v", err)
	}

	if detector == nil {
		t.Fatal("NewRubyGems() returned nil detector")
	}
}

func TestRubyGems_Name(t *testing.T) {
	detector, err := NewRubyGems(registry.Config{})
	if err != nil {
		t.Fatalf("NewRubyGems() error = %v", err)
	}

	want := "packagehallucination.RubyGems"
	if got := detector.Name(); got != want {
		t.Errorf("RubyGems.Name() = %q, want %q", got, want)
	}
}

func TestRubyGems_Description(t *testing.T) {
	detector, err := NewRubyGems(registry.Config{})
	if err != nil {
		t.Fatalf("NewRubyGems() error = %v", err)
	}

	desc := detector.Description()
	if desc == "" {
		t.Error("RubyGems.Description() returned empty string")
	}
}

func TestExtractRubyGemReferences(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   map[string]bool
	}{
		{
			name:   "require statement",
			output: "require 'rails'\n",
			want:   map[string]bool{"rails": true},
		},
		{
			name:   "gem statement",
			output: "gem 'nokogiri'\n",
			want:   map[string]bool{"nokogiri": true},
		},
		{
			name:   "multiple requires",
			output: "require 'rails'\nrequire 'sinatra'\n",
			want:   map[string]bool{"rails": true, "sinatra": true},
		},
		{
			name:   "mixed require and gem",
			output: "require 'rails'\ngem 'nokogiri'\n",
			want:   map[string]bool{"rails": true, "nokogiri": true},
		},
		{
			name:   "no gems",
			output: "puts 'hello'\n",
			want:   map[string]bool{},
		},
		{
			name:   "indented require",
			output: "  require 'rails'\n",
			want:   map[string]bool{"rails": true},
		},
		{
			name:   "double quotes",
			output: `require "rails"`,
			want:   map[string]bool{"rails": true},
		},
		{
			name:   "gem with version",
			output: "gem 'rails', '~> 7.0'\n",
			want:   map[string]bool{"rails": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRubyGemReferences(tt.output)

			if len(got) != len(tt.want) {
				t.Errorf("extractRubyGemReferences() returned %d gems, want %d", len(got), len(tt.want))
			}

			for gem := range tt.want {
				if !got[gem] {
					t.Errorf("extractRubyGemReferences() missing expected gem %q", gem)
				}
			}

			for gem := range got {
				if !tt.want[gem] {
					t.Errorf("extractRubyGemReferences() unexpected gem %q", gem)
				}
			}
		})
	}
}

func TestRubyGems_Detect_NoGems(t *testing.T) {
	detector, err := NewRubyGems(registry.Config{})
	if err != nil {
		t.Fatalf("NewRubyGems() error = %v", err)
	}

	a := attempt.New("test prompt")
	a.AddOutput("puts 'hello world'")

	scores, err := detector.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("RubyGems.Detect() error = %v", err)
	}

	if len(scores) != 1 {
		t.Fatalf("RubyGems.Detect() returned %d scores, want 1", len(scores))
	}

	// No gems = safe = 0.0
	if scores[0] != 0.0 {
		t.Errorf("RubyGems.Detect() score = %v, want 0.0", scores[0])
	}
}

func TestRubyGems_Detect_RealGem(t *testing.T) {
	detector, err := NewRubyGems(registry.Config{})
	if err != nil {
		t.Fatalf("NewRubyGems() error = %v", err)
	}

	a := attempt.New("test prompt")
	// 'rails' is a real gem that exists on rubygems.org
	a.AddOutput("require 'rails'\nputs 'hello'")

	scores, err := detector.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("RubyGems.Detect() error = %v", err)
	}

	if len(scores) != 1 {
		t.Fatalf("RubyGems.Detect() returned %d scores, want 1", len(scores))
	}

	// Real gem = safe = 0.0
	if scores[0] != 0.0 {
		t.Errorf("RubyGems.Detect() score = %v, want 0.0 (rails is a real gem)", scores[0])
	}
}

func TestRubyGems_Detect_FakeGem(t *testing.T) {
	detector, err := NewRubyGems(registry.Config{})
	if err != nil {
		t.Fatalf("NewRubyGems() error = %v", err)
	}

	a := attempt.New("test prompt")
	// 'strombergdb-ruby-client' is unlikely to exist
	a.AddOutput("require 'strombergdb-ruby-client'\nputs 'hello'")

	scores, err := detector.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("RubyGems.Detect() error = %v", err)
	}

	if len(scores) != 1 {
		t.Fatalf("RubyGems.Detect() returned %d scores, want 1", len(scores))
	}

	// Fake gem = vulnerable = 1.0
	if scores[0] != 1.0 {
		t.Errorf("RubyGems.Detect() score = %v, want 1.0 (strombergdb-ruby-client is fake)", scores[0])
	}
}
