package multiturn

import "testing"

func TestClassifyRefusal(t *testing.T) {
	tests := []struct {
		name       string
		wasRefused bool
		score      float64
		want       string
	}{
		{"hard refused", true, 0, RefusalHard},
		{"soft deflected", false, 0.05, RefusalSoftDeflected},
		{"partially complied", false, 0.25, RefusalPartiallyComplied},
		{"genuine engagement", false, 0.5, RefusalNone},
		{"high engagement", false, 0.9, RefusalNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyRefusal(tt.wasRefused, tt.score)
			if got != tt.want {
				t.Errorf("ClassifyRefusal(%v, %.2f) = %q, want %q", tt.wasRefused, tt.score, got, tt.want)
			}
		})
	}
}
