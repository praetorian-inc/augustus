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
	assert.Nil(t, pe, "no-judge inconclusive should not set partial evidence")
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

func TestInconsistentAuthzDetector_OneEmptyResponse(t *testing.T) {
	d, err := NewInconsistentAuthorizationDetector(registry.Config{})
	require.NoError(t, err)

	a := makeEquivAttempt("tool_a", "tool_b", "", `{"data": "some"}`)

	scores, err := d.Detect(context.Background(), a)
	require.NoError(t, err)
	for _, s := range scores {
		assert.Equal(t, InconclusiveScore, s, "one empty + one with data is a differential")
	}
}

func TestInconsistentAuthzDetector_BothEmptyResponses(t *testing.T) {
	d, err := NewInconsistentAuthorizationDetector(registry.Config{})
	require.NoError(t, err)

	a := makeEquivAttempt("tool_a", "tool_b", "", "")

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
		name       string
		input      string
		wantScore  float64
		wantParsed bool
	}{
		{
			name:       "high confidence vulnerable",
			input:      `{"vulnerable": true, "confidence": "high", "reason": "tool B returns admin roles"}`,
			wantScore:  1.0,
			wantParsed: true,
		},
		{
			name:       "medium confidence vulnerable",
			input:      `{"vulnerable": true, "confidence": "medium", "reason": "possibly different auth"}`,
			wantScore:  InconclusiveScore,
			wantParsed: true,
		},
		{
			name:       "not vulnerable",
			input:      `{"vulnerable": false, "confidence": "high", "reason": "just formatting difference"}`,
			wantScore:  0.0,
			wantParsed: true,
		},
		{
			name:       "unparseable — not parsed",
			input:      `I think this is vulnerable maybe`,
			wantScore:  InconclusiveScore,
			wantParsed: false,
		},
		{
			name:       "json with surrounding text",
			input:      `Here is my analysis: {"vulnerable": true, "confidence": "high", "reason": "clear privilege escalation"} as shown.`,
			wantScore:  1.0,
			wantParsed: true,
		},
		{
			name:       "low confidence vulnerable",
			input:      `{"vulnerable": true, "confidence": "low", "reason": "unclear"}`,
			wantScore:  InconclusiveScore,
			wantParsed: true,
		},
		{
			name:       "high in reason does not upgrade score",
			input:      `{"vulnerable": true, "confidence": "low", "reason": "high privilege data returned"}`,
			wantScore:  InconclusiveScore,
			wantParsed: true,
		},
		{
			name:       "missing vulnerable key — not parsed",
			input:      `{"confidence": "high", "reason": "looks bad"}`,
			wantScore:  InconclusiveScore,
			wantParsed: false,
		},
		{
			name:       "tool response quoted in prose — not parsed",
			input:      `Tool B returned {"roles":["admin"]} — vulnerable with high confidence`,
			wantScore:  InconclusiveScore,
			wantParsed: false,
		},
		{
			name:       "judge quotes tool response then gives own verdict — uses last object",
			input:      `Tool B returned {"vulnerable": true, "confidence": "high"} showing elevated privileges. My verdict: {"vulnerable": false, "confidence": "high", "reason": "just format difference"}`,
			wantScore:  0.0,
			wantParsed: true,
		},
		{
			name:       "multiple JSON objects — last verdict wins",
			input:      `{"vulnerable": true, "confidence": "low"} wait let me reconsider: {"vulnerable": true, "confidence": "high", "reason": "clear escalation"}`,
			wantScore:  1.0,
			wantParsed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, parsed := parseEquivVerdict(tt.input)
			assert.Equal(t, tt.wantScore, score)
			assert.Equal(t, tt.wantParsed, parsed)
		})
	}
}

func TestInconsistentAuthzDetector_ToolNameMasking(t *testing.T) {
	d, err := NewInconsistentAuthorizationDetector(registry.Config{})
	require.NoError(t, err)

	// Responses differ only by echoing their own tool name — after masking
	// they should be identical and score 0.0.
	a := makeEquivAttempt("get_user_role", "get_user_roles",
		`tool: get_user_role, result: viewer`, `tool: get_user_roles, result: viewer`)

	scores, err := d.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Equal(t, []float64{0.0, 0.0}, scores)
}

func TestInconsistentAuthzDetector_Name(t *testing.T) {
	d, err := NewInconsistentAuthorizationDetector(registry.Config{})
	require.NoError(t, err)
	det := d.(*InconsistentAuthorizationDetector)
	assert.Equal(t, "mcptool.InconsistentAuthorization", det.Name())
	assert.NotEmpty(t, det.Description())
}
