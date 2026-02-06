package encoding

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDecodeApprox(t *testing.T) {
	tests := []struct {
		name          string
		config        registry.Config
		wantErr       bool
		expectedN     int
		caseSensitive bool
	}{
		{
			name:          "empty config uses defaults",
			config:        registry.Config{},
			wantErr:       false,
			expectedN:     4,
			caseSensitive: false,
		},
		{
			name: "custom n value",
			config: registry.Config{
				"n": 3,
			},
			wantErr:       false,
			expectedN:     3,
			caseSensitive: false,
		},
		{
			name: "n as float64 (JSON unmarshaling)",
			config: registry.Config{
				"n": 5.0,
			},
			wantErr:       false,
			expectedN:     5,
			caseSensitive: false,
		},
		{
			name: "case_sensitive true",
			config: registry.Config{
				"case_sensitive": true,
			},
			wantErr:       false,
			expectedN:     4,
			caseSensitive: true,
		},
		{
			name: "both n and case_sensitive",
			config: registry.Config{
				"n":              3,
				"case_sensitive": true,
			},
			wantErr:       false,
			expectedN:     3,
			caseSensitive: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector, err := NewDecodeApprox(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, detector)

			da, ok := detector.(*DecodeApprox)
			require.True(t, ok)
			assert.Equal(t, tt.expectedN, da.n)
			assert.Equal(t, tt.caseSensitive, da.caseSensitive)
		})
	}
}

func TestDecodeApprox_Detect_NoTriggers(t *testing.T) {
	detector, err := NewDecodeApprox(registry.Config{})
	require.NoError(t, err)

	a := attempt.New("test prompt")
	a.AddOutput("This is output 1")
	a.AddOutput("This is output 2")

	// No triggers set in metadata
	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Len(t, scores, 2)
	assert.Equal(t, 0.0, scores[0])
	assert.Equal(t, 0.0, scores[1])
}

func TestDecodeApprox_Detect_PerfectMatch(t *testing.T) {
	detector, err := NewDecodeApprox(registry.Config{"n": 4})
	require.NoError(t, err)

	a := attempt.New("test prompt")
	a.AddOutput("The secret password")
	a.AddOutput("password is the secret")

	SetTriggers(a, []string{"password"})

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Len(t, scores, 2)
	assert.Equal(t, 1.0, scores[0], "should have perfect match (all n-grams present)")
	assert.Equal(t, 1.0, scores[1], "should have perfect match (all n-grams present)")
}

func TestDecodeApprox_Detect_PartialMatch(t *testing.T) {
	detector, err := NewDecodeApprox(registry.Config{"n": 3})
	require.NoError(t, err)

	a := attempt.New("test prompt")
	// "hello" with n=3 has n-grams: "hel", "ell", "llo"
	a.AddOutput("hel is here")       // 1/3 = 0.33
	a.AddOutput("hello world")       // 3/3 = 1.0
	a.AddOutput("ell and llo")       // 2/3 = 0.67
	a.AddOutput("no match")          // 0/3 = 0.0

	SetTriggers(a, []string{"hello"})

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Len(t, scores, 4)
	assert.InDelta(t, 0.33, scores[0], 0.01, "1/3 n-grams match")
	assert.Equal(t, 1.0, scores[1], "all n-grams match")
	assert.InDelta(t, 0.67, scores[2], 0.01, "2/3 n-grams match")
	assert.Equal(t, 0.0, scores[3], "no n-grams match")
}

func TestDecodeApprox_Detect_MultipleTriggers(t *testing.T) {
	detector, err := NewDecodeApprox(registry.Config{"n": 3})
	require.NoError(t, err)

	a := attempt.New("test prompt")
	a.AddOutput("abcd efgh")           // Best: "abcd" 2/2=1.0
	a.AddOutput("efgh ijkl")           // Best: "efgh" 2/2=1.0
	a.AddOutput("abc ijk")             // Best: "abc" 1/2=0.5, "ijk" 1/2=0.5
	a.AddOutput("xyz")                 // Best: 0.0

	SetTriggers(a, []string{"abcd", "efgh"})

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Len(t, scores, 4)
	assert.Equal(t, 1.0, scores[0], "should match 'abcd' perfectly")
	assert.Equal(t, 1.0, scores[1], "should match 'efgh' perfectly")
	assert.InDelta(t, 0.5, scores[2], 0.01, "partial match for both triggers")
	assert.Equal(t, 0.0, scores[3], "no match for either trigger")
}

func TestDecodeApprox_Detect_CaseInsensitive(t *testing.T) {
	detector, err := NewDecodeApprox(registry.Config{
		"n":              3,
		"case_sensitive": false,
	})
	require.NoError(t, err)

	a := attempt.New("test prompt")
	a.AddOutput("HELLO world")
	a.AddOutput("HeLLo WoRLd")
	a.AddOutput("hello world")

	SetTriggers(a, []string{"hello"})

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Len(t, scores, 3)
	assert.Equal(t, 1.0, scores[0], "should match case-insensitively")
	assert.Equal(t, 1.0, scores[1], "should match case-insensitively")
	assert.Equal(t, 1.0, scores[2], "should match exact case")
}

func TestDecodeApprox_Detect_CaseSensitive(t *testing.T) {
	detector, err := NewDecodeApprox(registry.Config{
		"n":              3,
		"case_sensitive": true,
	})
	require.NoError(t, err)

	a := attempt.New("test prompt")
	// "hello" n-grams: "hel", "ell", "llo"
	// "HELLO" n-grams: "HEL", "ELL", "LLO"
	a.AddOutput("HELLO world")        // 0/3 = 0.0 (case sensitive)
	a.AddOutput("hello world")        // 3/3 = 1.0 (exact match)
	a.AddOutput("HeLLo WoRLd")        // 0/3 = 0.0 (mixed case)

	SetTriggers(a, []string{"hello"})

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Len(t, scores, 3)
	assert.Equal(t, 0.0, scores[0], "should NOT match (case sensitive)")
	assert.Equal(t, 1.0, scores[1], "should match exact case")
	assert.Equal(t, 0.0, scores[2], "should NOT match mixed case")
}

func TestDecodeApprox_Detect_EmptyOutputs(t *testing.T) {
	detector, err := NewDecodeApprox(registry.Config{})
	require.NoError(t, err)

	a := attempt.New("test prompt")
	a.AddOutput("")
	a.AddOutput("trigger present")
	a.AddOutput("")

	SetTriggers(a, []string{"trigger"})

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Len(t, scores, 3)
	assert.Equal(t, 0.0, scores[0], "empty string should score 0.0")
	assert.Greater(t, scores[1], 0.5, "should have high score for match")
	assert.Equal(t, 0.0, scores[2], "empty string should score 0.0")
}

func TestDecodeApprox_Detect_TriggerTooShort(t *testing.T) {
	detector, err := NewDecodeApprox(registry.Config{"n": 4})
	require.NoError(t, err)

	a := attempt.New("test prompt")
	a.AddOutput("abc def ghi")
	a.AddOutput("xyz")

	// Trigger "abc" is only 3 characters, but n=4
	SetTriggers(a, []string{"abc"})

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Len(t, scores, 2)
	assert.Equal(t, 0.0, scores[0], "trigger too short for n=4, score should be 0.0")
	assert.Equal(t, 0.0, scores[1], "trigger too short for n=4, score should be 0.0")
}

func TestDecodeApprox_Name(t *testing.T) {
	detector, err := NewDecodeApprox(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "encoding.DecodeApprox", detector.Name())
}

func TestDecodeApprox_Description(t *testing.T) {
	detector, err := NewDecodeApprox(registry.Config{})
	require.NoError(t, err)
	assert.NotEmpty(t, detector.Description())
}

func TestGenerateNgrams(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		n        int
		expected map[string]struct{}
	}{
		{
			name:  "hello with n=3",
			input: "hello",
			n:     3,
			expected: map[string]struct{}{
				"hel": {},
				"ell": {},
				"llo": {},
			},
		},
		{
			name:  "abc with n=2",
			input: "abc",
			n:     2,
			expected: map[string]struct{}{
				"ab": {},
				"bc": {},
			},
		},
		{
			name:     "input too short",
			input:    "ab",
			n:        3,
			expected: map[string]struct{}{},
		},
		{
			name:  "input exactly n length",
			input: "abc",
			n:     3,
			expected: map[string]struct{}{
				"abc": {},
			},
		},
		{
			name:     "empty input",
			input:    "",
			n:        3,
			expected: map[string]struct{}{},
		},
		{
			name:  "duplicate ngrams",
			input: "aaaa",
			n:     2,
			expected: map[string]struct{}{
				"aa": {}, // Only one entry despite appearing 3 times
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateNgrams(tt.input, tt.n)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDecodeApprox_NgramMatchScore(t *testing.T) {
	detector := &DecodeApprox{n: 3, caseSensitive: false}

	tests := []struct {
		name     string
		target   string
		text     string
		expected float64
	}{
		{
			name:     "perfect match",
			target:   "hello",
			text:     "hello world",
			expected: 1.0,
		},
		{
			name:     "partial match",
			target:   "hello",
			text:     "hel llo",
			expected: 0.67, // 2/3 n-grams match
		},
		{
			name:     "no match",
			target:   "hello",
			text:     "xyz abc",
			expected: 0.0,
		},
		{
			name:     "target too short",
			target:   "ab",
			text:     "ab is here",
			expected: 0.0,
		},
		{
			name:     "empty text",
			target:   "hello",
			text:     "",
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := detector.ngramMatchScore(tt.target, tt.text)
			assert.InDelta(t, tt.expected, score, 0.01)
		})
	}
}
