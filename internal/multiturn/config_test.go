package multiturn

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.MaxTurns != 10 {
		t.Errorf("MaxTurns = %d, want 10", cfg.MaxTurns)
	}
	if cfg.MaxRefusalRetries != 10 {
		t.Errorf("MaxRefusalRetries = %d, want 10", cfg.MaxRefusalRetries)
	}
	if cfg.SuccessThreshold != 0.8 {
		t.Errorf("SuccessThreshold = %f, want 0.8", cfg.SuccessThreshold)
	}
	if cfg.AttackMaxAttempts != 5 {
		t.Errorf("AttackMaxAttempts = %d, want 5", cfg.AttackMaxAttempts)
	}
	if !cfg.UseSecondaryJudge {
		t.Error("UseSecondaryJudge = false, want true")
	}
}

func TestConfigFromMap(t *testing.T) {
	tests := []struct {
		name     string
		m        registry.Config
		defaults Config
		want     Config
	}{
		{
			name:     "empty map uses defaults",
			m:        registry.Config{},
			defaults: Defaults(),
			want:     Defaults(),
		},
		{
			name: "overrides from map",
			m: registry.Config{
				"goal":                "test goal",
				"max_turns":           5,
				"max_refusal_retries": 3,
				"success_threshold":   0.9,
				"attack_max_attempts": 2,
				"use_secondary_judge": false,
			},
			defaults: Defaults(),
			want: Config{
				Goal:              "test goal",
				MaxTurns:          5,
				MaxRefusalRetries: 3,
				SuccessThreshold:  0.9,
				AttackMaxAttempts: 2,
				UseSecondaryJudge: false,
			},
		},
		{
			name: "partial overrides",
			m: registry.Config{
				"goal":      "partial goal",
				"max_turns": 7,
			},
			defaults: Defaults(),
			want: Config{
				Goal:              "partial goal",
				MaxTurns:          7,
				MaxRefusalRetries: 10,
				SuccessThreshold:  0.8,
				AttackMaxAttempts: 5,
				UseSecondaryJudge: true,
			},
		},
		{
			name: "float64 max_turns from JSON",
			m: registry.Config{
				"max_turns": float64(8),
			},
			defaults: Defaults(),
			want: Config{
				MaxTurns:          8,
				MaxRefusalRetries: 10,
				SuccessThreshold:  0.8,
				AttackMaxAttempts: 5,
				UseSecondaryJudge: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConfigFromMap(tt.m, tt.defaults)
			if got.Goal != tt.want.Goal {
				t.Errorf("Goal = %q, want %q", got.Goal, tt.want.Goal)
			}
			if got.MaxTurns != tt.want.MaxTurns {
				t.Errorf("MaxTurns = %d, want %d", got.MaxTurns, tt.want.MaxTurns)
			}
			if got.MaxRefusalRetries != tt.want.MaxRefusalRetries {
				t.Errorf("MaxRefusalRetries = %d, want %d", got.MaxRefusalRetries, tt.want.MaxRefusalRetries)
			}
			if got.SuccessThreshold != tt.want.SuccessThreshold {
				t.Errorf("SuccessThreshold = %f, want %f", got.SuccessThreshold, tt.want.SuccessThreshold)
			}
			if got.AttackMaxAttempts != tt.want.AttackMaxAttempts {
				t.Errorf("AttackMaxAttempts = %d, want %d", got.AttackMaxAttempts, tt.want.AttackMaxAttempts)
			}
			if got.UseSecondaryJudge != tt.want.UseSecondaryJudge {
				t.Errorf("UseSecondaryJudge = %v, want %v", got.UseSecondaryJudge, tt.want.UseSecondaryJudge)
			}
		})
	}
}
