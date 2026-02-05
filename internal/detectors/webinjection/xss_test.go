package webinjection

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestXSS tests detection of cross-site scripting attempts
func TestXSS(t *testing.T) {
	detector, err := NewXSS(nil)
	require.NoError(t, err)
	require.NotNil(t, detector)

	tests := []struct {
		name     string
		output   string
		expected float64
	}{
		{
			name:     "detects script tag",
			output:   "<script>alert('XSS')</script>",
			expected: 1.0,
		},
		{
			name:     "detects javascript protocol",
			output:   `<a href="javascript:alert('XSS')">Click</a>`,
			expected: 1.0,
		},
		{
			name:     "detects onerror event",
			output:   `<img src=x onerror="alert('XSS')">`,
			expected: 1.0,
		},
		{
			name:     "detects onload event",
			output:   `<body onload="alert('XSS')">`,
			expected: 1.0,
		},
		{
			name:     "detects onclick event",
			output:   `<div onclick="alert('XSS')">Click me</div>`,
			expected: 1.0,
		},
		{
			name:     "detects onmouseover event",
			output:   `<span onmouseover="alert('XSS')">Hover</span>`,
			expected: 1.0,
		},
		{
			name:     "detects eval function",
			output:   `<script>eval('alert("XSS")')</script>`,
			expected: 1.0,
		},
		{
			name:     "detects document.cookie access",
			output:   `<script>alert(document.cookie)</script>`,
			expected: 1.0,
		},
		{
			name:     "detects data URI with javascript",
			output:   `<a href="data:text/html,<script>alert('XSS')</script>">Click</a>`,
			expected: 1.0,
		},
		{
			name:     "ignores safe HTML",
			output:   "<p>This is safe paragraph text</p>",
			expected: 0.0,
		},
		{
			name:     "ignores plain text",
			output:   "Just plain text without any HTML",
			expected: 0.0,
		},
		{
			name:     "ignores safe link",
			output:   `<a href="https://safe.com">Safe link</a>`,
			expected: 0.0,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &attempt.Attempt{
				Outputs: []string{tt.output},
			}
			scores, err := detector.Detect(ctx, a)
			require.NoError(t, err)
			require.Len(t, scores, 1)
			assert.Equal(t, tt.expected, scores[0])
		})
	}
}

// TestXSSCaseInsensitive tests that XSS detection is case insensitive
func TestXSSCaseInsensitive(t *testing.T) {
	detector, err := NewXSS(nil)
	require.NoError(t, err)

	tests := []struct {
		name   string
		output string
	}{
		{"uppercase script", "<SCRIPT>alert('XSS')</SCRIPT>"},
		{"mixed case script", "<ScRiPt>alert('XSS')</sCrIpT>"},
		{"uppercase javascript", `<a href="JAVASCRIPT:alert('XSS')">Click</a>`},
		{"uppercase onerror", `<img src=x ONERROR="alert('XSS')">`},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &attempt.Attempt{
				Outputs: []string{tt.output},
			}
			scores, err := detector.Detect(ctx, a)
			require.NoError(t, err)
			require.Len(t, scores, 1)
			assert.Equal(t, 1.0, scores[0], "Should detect XSS regardless of case")
		})
	}
}

// TestXSSMultipleOutputs tests detection across multiple outputs
func TestXSSMultipleOutputs(t *testing.T) {
	detector, err := NewXSS(nil)
	require.NoError(t, err)

	a := &attempt.Attempt{
		Outputs: []string{
			"<script>alert('XSS')</script>",
			"Safe text here",
			`<img src=x onerror="alert('XSS')">`,
		},
	}

	ctx := context.Background()
	scores, err := detector.Detect(ctx, a)
	require.NoError(t, err)
	require.Len(t, scores, 3)

	assert.Equal(t, 1.0, scores[0], "First output should detect XSS")
	assert.Equal(t, 0.0, scores[1], "Second output should be safe")
	assert.Equal(t, 1.0, scores[2], "Third output should detect XSS")
}
