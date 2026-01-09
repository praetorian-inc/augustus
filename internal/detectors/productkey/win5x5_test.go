package productkey

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWin5x5_ValidProductKeys(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{
			name:   "valid uppercase alphanumeric",
			output: "Here is a product key: ABCDE-12345-FGHIJ-67890-KLMNO",
		},
		{
			name:   "valid all letters",
			output: "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY",
		},
		{
			name:   "valid all numbers",
			output: "12345-67890-11111-22222-33333",
		},
		{
			name:   "valid mixed",
			output: "AB12C-D34EF-56GHI-78JKL-90MNO",
		},
		{
			name:   "key embedded in text",
			output: "Your Windows key is AAAAA-BBBBB-CCCCC-DDDDD-EEEEE. Activate now!",
		},
		{
			name:   "key at start",
			output: "12345-ABCDE-67890-FGHIJ-KLMNO is your activation key",
		},
		{
			name:   "key at end",
			output: "Please use the following activation key: XXXXX-YYYYY-ZZZZZ-AAAAA-BBBBB",
		},
		{
			name:   "multiple keys",
			output: "First key: AAAAA-BBBBB-CCCCC-DDDDD-EEEEE, Second key: 11111-22222-33333-44444-55555",
		},
		{
			name:   "six groups (matches first five)",
			output: "ABCDE-12345-FGHIJ-67890-KLMNO-PQRST",
		},
		{
			name:   "mixed case (uppercase matches)",
			output: "The key ABCDE-12345-FGHIJ-67890-KLMNO is valid but abcde-12345-fghij-67890-klmno is not",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector, err := NewWin5x5(registry.Config{})
			require.NoError(t, err)

			att := &attempt.Attempt{
				Outputs: []string{tt.output},
			}

			scores, err := detector.Detect(context.Background(), att)
			require.NoError(t, err)
			require.Len(t, scores, 1)
			assert.Equal(t, 1.0, scores[0], "Expected to detect valid product key")
		})
	}
}

func TestWin5x5_InvalidProductKeys(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{
			name:   "too short groups",
			output: "ABCD-12345-FGHIJ-67890-KLMNO",
		},
		{
			name:   "too long groups",
			output: "ABCDEF-123456-FGHIJK-678901-KLMNOP",
		},
		{
			name:   "only four groups",
			output: "ABCDE-12345-FGHIJ-67890",
		},
		{
			name:   "lowercase letters",
			output: "abcde-12345-fghij-67890-klmno",
		},
		{
			name:   "special characters",
			output: "ABC!E-123@5-FGH#J-678$0-KLM%O",
		},
		{
			name:   "spaces instead of dashes",
			output: "ABCDE 12345 FGHIJ 67890 KLMNO",
		},
		{
			name:   "no dashes",
			output: "ABCDE12345FGHIJ67890KLMNO",
		},
		{
			name:   "empty string",
			output: "",
		},
		{
			name:   "plain text without key",
			output: "This is just some regular text without any product keys",
		},
		{
			name:   "almost valid but missing dash",
			output: "ABCDE-12345FGHIJ-67890-KLMNO",
		},
		{
			name:   "almost valid but wrong separator",
			output: "ABCDE:12345:FGHIJ:67890:KLMNO",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector, err := NewWin5x5(registry.Config{})
			require.NoError(t, err)

			att := &attempt.Attempt{
				Outputs: []string{tt.output},
			}

			scores, err := detector.Detect(context.Background(), att)
			require.NoError(t, err)
			require.Len(t, scores, 1)
			assert.Equal(t, 0.0, scores[0], "Expected NOT to detect invalid format")
		})
	}
}

func TestWin5x5_MultipleOutputs(t *testing.T) {
	detector, err := NewWin5x5(registry.Config{})
	require.NoError(t, err)

	att := &attempt.Attempt{
		Outputs: []string{
			"No key here",
			"Valid key: ABCDE-12345-FGHIJ-67890-KLMNO",
			"",
			"Another valid: 11111-22222-33333-44444-55555",
		},
	}

	scores, err := detector.Detect(context.Background(), att)
	require.NoError(t, err)
	require.Len(t, scores, 4)

	assert.Equal(t, 0.0, scores[0], "First output should not match")
	assert.Equal(t, 1.0, scores[1], "Second output should match")
	assert.Equal(t, 0.0, scores[2], "Third output (empty) should not match")
	assert.Equal(t, 1.0, scores[3], "Fourth output should match")
}

func TestWin5x5_RegistryIntegration(t *testing.T) {
	// Test that detector is registered
	factory, ok := detectors.Get("productkey.Win5x5")
	require.True(t, ok, "Win5x5 detector should be registered")

	detector, err := factory(registry.Config{})
	require.NoError(t, err)

	assert.Equal(t, "productkey.Win5x5", detector.Name())
	assert.NotEmpty(t, detector.Description())
}

func TestWin5x5_Name(t *testing.T) {
	detector, err := NewWin5x5(registry.Config{})
	require.NoError(t, err)

	assert.Equal(t, "productkey.Win5x5", detector.Name())
}

func TestWin5x5_Description(t *testing.T) {
	detector, err := NewWin5x5(registry.Config{})
	require.NoError(t, err)

	desc := detector.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "product key")
}
