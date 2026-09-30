package types

import "testing"

func TestVerdictString(t *testing.T) {
	tests := []struct {
		v    Verdict
		want string
	}{
		{VerdictVulnerable, "vulnerable"},
		{VerdictNotVulnerable, "not_vulnerable"},
		{VerdictInconclusive, "inconclusive"},
		{Verdict(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.v.String(); got != tt.want {
			t.Errorf("Verdict(%d).String() = %q, want %q", tt.v, got, tt.want)
		}
	}
}

func TestVerdictScore(t *testing.T) {
	tests := []struct {
		v    Verdict
		want float64
	}{
		{VerdictVulnerable, 1.0},
		{VerdictNotVulnerable, 0.0},
		{VerdictInconclusive, 0.0},
		{Verdict(99), 0.0},
	}
	for _, tt := range tests {
		if got := tt.v.Score(); got != tt.want {
			t.Errorf("Verdict(%d).Score() = %v, want %v", tt.v, got, tt.want)
		}
	}
}

func TestVerdictFromP(t *testing.T) {
	const hi, lo = DefaultClassifierHi, DefaultClassifierLo
	tests := []struct {
		name string
		p    float64
		want Verdict
	}{
		{name: "above hi", p: 0.91, want: VerdictVulnerable},
		{name: "p equals hi", p: hi, want: VerdictVulnerable},
		{name: "p equals lo", p: lo, want: VerdictNotVulnerable},
		{name: "below lo", p: 0.1, want: VerdictNotVulnerable},
		{name: "between lo and hi", p: 0.5, want: VerdictInconclusive},
		{name: "just above lo", p: 0.2000001, want: VerdictInconclusive},
		{name: "just below hi", p: 0.7999999, want: VerdictInconclusive},
		{name: "zero", p: 0.0, want: VerdictNotVulnerable},
		{name: "one", p: 1.0, want: VerdictVulnerable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerdictFromP(tt.p, hi, lo); got != tt.want {
				t.Errorf("VerdictFromP(%v, %v, %v) = %s, want %s", tt.p, hi, lo, got, tt.want)
			}
		})
	}
}
