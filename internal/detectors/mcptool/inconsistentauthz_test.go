package mcptool

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func makeEquivAttempt(toolA, toolB, respA, respB string) *attempt.Attempt {
	a := attempt.New(toolA + " vs " + toolB)
	a.Metadata[mcpprobe.MetaEquivToolA] = toolA
	a.Metadata[mcpprobe.MetaEquivToolB] = toolB
	a.Metadata[mcpprobe.MetaEquivResponseA] = respA
	a.Metadata[mcpprobe.MetaEquivResponseB] = respB
	a.Metadata[mcpprobe.MetaEquivPairingMethod] = "name-heuristic"
	a.Metadata[mcpprobe.MetaEquivArgs] = `{"username":"test"}`
	a.AddOutput(respA)
	a.AddOutput(respB)
	return a
}

func TestInconsistentAuthzDetector_IdenticalResponses(t *testing.T) {
	d, err := NewInconsistentAuthorizationDetector(registry.Config{})
	require.NoError(t, err)

	a := makeEquivAttempt("get_user_role", "get_user_roles",
		`{"role": "viewer"}`, `{"role": "viewer"}`)

	scores, err := d.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Equal(t, []float64{0.0, 0.0}, scores)
}

func TestInconsistentAuthzDetector_DifferentResponses_NoJudge(t *testing.T) {
	d, err := NewInconsistentAuthorizationDetector(registry.Config{})
	require.NoError(t, err)

	a := makeEquivAttempt("get_user_role", "get_user_roles",
		`{"role": "viewer"}`, `{"roles": ["admin", "superuser"]}`)

	scores, err := d.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Equal(t, []float64{InconclusiveScore, InconclusiveScore}, scores)

	pe, _ := a.GetMetadata(attempt.MetadataKeyPartialEvidence)
	assert.Equal(t, true, pe)
}

func TestInconsistentAuthzDetector_MissingMetadata(t *testing.T) {
	d, err := NewInconsistentAuthorizationDetector(registry.Config{})
	require.NoError(t, err)

	a := attempt.New("test")
	a.AddOutput("response")

	scores, err := d.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Equal(t, []float64{0.0}, scores)
}

func TestInconsistentAuthzDetector_EmptyResponse(t *testing.T) {
	d, err := NewInconsistentAuthorizationDetector(registry.Config{})
	require.NoError(t, err)

	a := makeEquivAttempt("tool_a", "tool_b", "", `{"data": "some"}`)

	scores, err := d.Detect(context.Background(), a)
	require.NoError(t, err)
	for _, s := range scores {
		assert.Equal(t, 0.0, s)
	}
}

func TestInconsistentAuthzDetector_NormalizeWhitespace(t *testing.T) {
	d, err := NewInconsistentAuthorizationDetector(registry.Config{})
	require.NoError(t, err)

	a := makeEquivAttempt("tool_a", "tool_b",
		`{"role":  "viewer"}`, `{"role": "viewer"}`)

	scores, err := d.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Equal(t, []float64{0.0, 0.0}, scores)
}

func TestParseEquivVerdict(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  float64
	}{
		{
			name:  "high confidence vulnerable",
			input: `{"vulnerable": true, "confidence": "high", "reason": "tool B returns admin roles"}`,
			want:  1.0,
		},
		{
			name:  "medium confidence vulnerable",
			input: `{"vulnerable": true, "confidence": "medium", "reason": "possibly different auth"}`,
			want:  InconclusiveScore,
		},
		{
			name:  "not vulnerable",
			input: `{"vulnerable": false, "confidence": "high", "reason": "just formatting difference"}`,
			want:  0.0,
		},
		{
			name:  "unparseable",
			input: `I think this is vulnerable maybe`,
			want:  InconclusiveScore,
		},
		{
			name:  "json with surrounding text",
			input: `Here is my analysis: {"vulnerable": true, "confidence": "high", "reason": "clear privilege escalation"} as shown.`,
			want:  1.0,
		},
		{
			name:  "low confidence vulnerable",
			input: `{"vulnerable": true, "confidence": "low", "reason": "unclear"}`,
			want:  InconclusiveScore,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseEquivVerdict(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestInconsistentAuthzDetector_Name(t *testing.T) {
	d, err := NewInconsistentAuthorizationDetector(registry.Config{})
	require.NoError(t, err)
	det := d.(*InconsistentAuthorizationDetector)
	assert.Equal(t, "mcptool.InconsistentAuthorization", det.Name())
	assert.NotEmpty(t, det.Description())
}
