package encoding

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/internal/detectors/base"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDecodeMatch(t *testing.T) {
	tests := []struct {
		name          string
		config        registry.Config
		wantErr       bool
		caseSensitive bool
	}{
		{
			name:          "empty config uses defaults",
			config:        registry.Config{},
			wantErr:       false,
			caseSensitive: false,
		},
		{
			name: "case_sensitive true",
			config: registry.Config{
				"case_sensitive": true,
			},
			wantErr:       false,
			caseSensitive: true,
		},
		{
			name: "case_sensitive false",
			config: registry.Config{
				"case_sensitive": false,
			},
			wantErr:       false,
			caseSensitive: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector, err := NewDecodeMatch(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, detector)

			dm, ok := detector.(*DecodeMatch)
			require.True(t, ok)
			assert.Equal(t, tt.caseSensitive, dm.CaseSensitive)
		})
	}
}

func TestDecodeMatch_Detect_NoTriggers(t *testing.T) {
	detector, err := NewDecodeMatch(registry.Config{})
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

func TestDecodeMatch_Detect_ExactMatch(t *testing.T) {
	detector, err := NewDecodeMatch(registry.Config{})
	require.NoError(t, err)

	a := attempt.New("test prompt")
	a.AddOutput("The secret password is hunter2")
	a.AddOutput("No match here")
	a.AddOutput("Another hunter2 match")

	// Set triggers in metadata
	SetTriggers(a, []string{"hunter2"})

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Len(t, scores, 3)
	assert.Equal(t, 1.0, scores[0], "should match 'hunter2' in output 0")
	assert.Equal(t, 0.0, scores[1], "should not match in output 1")
	assert.Equal(t, 1.0, scores[2], "should match 'hunter2' in output 2")
}

func TestDecodeMatch_Detect_MultipleTriggers(t *testing.T) {
	detector, err := NewDecodeMatch(registry.Config{})
	require.NoError(t, err)

	a := attempt.New("test prompt")
	a.AddOutput("Found secret1 here")
	a.AddOutput("Found secret2 here")
	a.AddOutput("Found both secret1 and secret2")
	a.AddOutput("No secrets here")

	SetTriggers(a, []string{"secret1", "secret2"})

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Len(t, scores, 4)
	assert.Equal(t, 1.0, scores[0], "should match 'secret1'")
	assert.Equal(t, 1.0, scores[1], "should match 'secret2'")
	assert.Equal(t, 1.0, scores[2], "should match both triggers")
	assert.Equal(t, 0.0, scores[3], "should match neither trigger")
}

func TestDecodeMatch_Detect_CaseInsensitive(t *testing.T) {
	detector, err := NewDecodeMatch(registry.Config{
		"case_sensitive": false,
	})
	require.NoError(t, err)

	a := attempt.New("test prompt")
	a.AddOutput("The PASSWORD is here")
	a.AddOutput("No match")
	a.AddOutput("password in lowercase")

	SetTriggers(a, []string{"password"})

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Len(t, scores, 3)
	assert.Equal(t, 1.0, scores[0], "should match 'PASSWORD' (case insensitive)")
	assert.Equal(t, 0.0, scores[1])
	assert.Equal(t, 1.0, scores[2], "should match 'password' (exact case)")
}

func TestDecodeMatch_Detect_CaseSensitive(t *testing.T) {
	detector, err := NewDecodeMatch(registry.Config{
		"case_sensitive": true,
	})
	require.NoError(t, err)

	a := attempt.New("test prompt")
	a.AddOutput("The PASSWORD is here")
	a.AddOutput("password in lowercase")
	a.AddOutput("PaSsWoRd mixed case")

	SetTriggers(a, []string{"password"})

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Len(t, scores, 3)
	assert.Equal(t, 0.0, scores[0], "should NOT match 'PASSWORD' (case sensitive)")
	assert.Equal(t, 1.0, scores[1], "should match 'password' (exact case)")
	assert.Equal(t, 0.0, scores[2], "should NOT match 'PaSsWoRd' (case sensitive)")
}

func TestDecodeMatch_Detect_EmptyOutputs(t *testing.T) {
	detector, err := NewDecodeMatch(registry.Config{})
	require.NoError(t, err)

	a := attempt.New("test prompt")
	a.AddOutput("")
	a.AddOutput("Contains trigger")
	a.AddOutput("")

	SetTriggers(a, []string{"trigger"})

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Len(t, scores, 3)
	assert.Equal(t, 0.0, scores[0], "empty string should not match")
	assert.Equal(t, 1.0, scores[1], "should match trigger")
	assert.Equal(t, 0.0, scores[2], "empty string should not match")
}

func TestDecodeMatch_Detect_PartialMatch(t *testing.T) {
	detector, err := NewDecodeMatch(registry.Config{})
	require.NoError(t, err)

	a := attempt.New("test prompt")
	a.AddOutput("The trigger is hunter2pass")
	a.AddOutput("hunt is partial")
	a.AddOutput("er2 is also partial")

	SetTriggers(a, []string{"hunter2"})

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Len(t, scores, 3)
	assert.Equal(t, 1.0, scores[0], "should match because 'hunter2' is substring of 'hunter2pass'")
	assert.Equal(t, 0.0, scores[1], "'hunt' alone is not 'hunter2'")
	assert.Equal(t, 0.0, scores[2], "'er2' alone is not 'hunter2'")
}

func TestDecodeMatch_Name(t *testing.T) {
	detector, err := NewDecodeMatch(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "encoding.DecodeMatch", detector.Name())
}

func TestDecodeMatch_Description(t *testing.T) {
	detector, err := NewDecodeMatch(registry.Config{})
	require.NoError(t, err)
	assert.NotEmpty(t, detector.Description())
}

func TestExtractTriggers_StringSlice(t *testing.T) {
	a := attempt.New("test")
	a.Metadata["triggers"] = []string{"trigger1", "trigger2"}

	triggers, err := base.ExtractTriggers(a)
	require.NoError(t, err)
	assert.Equal(t, []string{"trigger1", "trigger2"}, triggers)
}

func TestExtractTriggers_AnySlice(t *testing.T) {
	a := attempt.New("test")
	a.Metadata["triggers"] = []any{"trigger1", "trigger2"}

	triggers, err := base.ExtractTriggers(a)
	require.NoError(t, err)
	assert.Equal(t, []string{"trigger1", "trigger2"}, triggers)
}

func TestExtractTriggers_SingleString(t *testing.T) {
	a := attempt.New("test")
	a.Metadata["triggers"] = "single_trigger"

	triggers, err := base.ExtractTriggers(a)
	require.NoError(t, err)
	assert.Equal(t, []string{"single_trigger"}, triggers)
}

func TestExtractTriggers_NoMetadata(t *testing.T) {
	a := attempt.New("test")

	triggers, err := base.ExtractTriggers(a)
	require.NoError(t, err)
	assert.Empty(t, triggers)
}

func TestExtractTriggers_InvalidType(t *testing.T) {
	a := attempt.New("test")
	a.Metadata["triggers"] = 123 // Invalid type

	triggers, err := base.ExtractTriggers(a)
	assert.Error(t, err)
	assert.Nil(t, triggers)
}

func TestExtractTriggers_MixedAnySlice(t *testing.T) {
	a := attempt.New("test")
	a.Metadata["triggers"] = []any{"trigger1", 123} // Invalid: contains non-string

	triggers, err := base.ExtractTriggers(a)
	assert.Error(t, err)
	assert.Nil(t, triggers)
}
