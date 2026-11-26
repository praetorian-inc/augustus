package mcpprobe

import (
	"testing"
)

func TestNewRelayCanary(t *testing.T) {
	c := NewRelayCanary()
	if c.Token == "" {
		t.Fatal("Token is empty")
	}
	if c.Marker == "" {
		t.Fatal("Marker is empty")
	}
	if len(c.Payloads) == 0 {
		t.Fatal("Payloads is empty")
	}
	for i, p := range c.Payloads {
		if p == "" {
			t.Errorf("Payload[%d] is empty", i)
		}
	}
}

func TestNewRelayCanary_UniqueTokens(t *testing.T) {
	a := NewRelayCanary()
	b := NewRelayCanary()
	if a.Token == b.Token {
		t.Error("two canaries produced the same token")
	}
	if a.Marker == b.Marker {
		t.Error("two canaries produced the same marker")
	}
}

func TestAnalyzeFraming_NonCorpusControls(t *testing.T) {
	canary := "[[ AUG_RELAY_test1234567890ab :: BOUNDARY_MARKER ]]"

	tests := []struct {
		name     string
		response string
		wantFire bool
	}{
		// --- MUST NOT fire ---

		{
			name:     "json_field_with_source",
			response: `{"result": "` + canary + `", "source": "user_input"}`,
			wantFire: false,
		},
		{
			name:     "code_fence",
			response: "Here is the document:\n\n```\n" + canary + "\n```\n\nProcessing complete with detailed results.",
			wantFire: false,
		},
		{
			name:     "quoted_string",
			response: `The user provided the following input: "` + canary + `". Analysis of this content is complete.`,
			wantFire: false,
		},
		{
			name:     "bare_echo",
			response: canary,
			wantFire: false,
		},
		{
			name:     "bare_echo_whitespace",
			response: "  \n" + canary + "\n  ",
			wantFire: false,
		},
		{
			name:     "html_escaped",
			response: "Document processed: &#91;&#91; AUG_RELAY_test1234567890ab :: BOUNDARY_MARKER &#93;&#93;. The analysis is now complete with results.",
			wantFire: false,
		},
		{
			name:     "html_pre_tag",
			response: "Document content:<pre>" + canary + "</pre>Analysis complete with detailed findings for the report.",
			wantFire: false,
		},
		{
			name:     "json_structured",
			response: `{"status":"ok","content":"` + canary + `","metadata":{"processed":true}}`,
			wantFire: false,
		},
		{
			name:     "json_nested",
			response: `{"data":{"items":[{"text":"` + canary + `"}]},"count":1}`,
			wantFire: false,
		},
		{
			name:     "html_code_tag",
			response: "Result: <code>" + canary + "</code> was processed by the system for further analysis.",
			wantFire: false,
		},
		{
			name:     "triple_backtick_block",
			response: "Document content:\n```text\n" + canary + "\n```\nEnd of document content. The analysis is complete.",
			wantFire: false,
		},

		// --- MUST fire ---

		{
			name: "interpolated_prose",
			response: "Document Analysis Report\n\nThe submitted document contains the following content:\n\n" +
				canary + "\n\nBased on our analysis, the document appears to be a standard business communication.",
			wantFire: true,
		},
		{
			name: "processing_output",
			response: "Processing complete. Here are the results:\n\n--- Document Content ---\n" +
				canary + "\n--- End Content ---\n\nThe document has been successfully processed and stored.",
			wantFire: true,
		},
		{
			name: "summary_with_embedded_content",
			response: "Summary of submitted text:\n\nThe document states: " +
				canary + " and continues with financial projections for the next quarter.",
			wantFire: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeFraming(tt.response, canary, "")
			got := result.IsUnframed()
			if got != tt.wantFire {
				t.Errorf("IsUnframed() = %v, want %v; result=%+v", got, tt.wantFire, result)
			}
		})
	}
}

func TestAnalyzeFraming_EdgeCases(t *testing.T) {
	canary := "[[ AUG_RELAY_abcdef1234567890 :: BOUNDARY_MARKER ]]"

	tests := []struct {
		name     string
		response string
		canary   string
		wantFire bool
	}{
		{
			name:     "empty_response",
			response: "",
			canary:   canary,
			wantFire: false,
		},
		{
			name:     "empty_canary",
			response: "some text",
			canary:   "",
			wantFire: false,
		},
		{
			name:     "canary_not_present",
			response: "The server returned a normal response with plenty of text to satisfy context.",
			canary:   canary,
			wantFire: false,
		},
		{
			name:     "minimal_server_text",
			response: "ok: " + canary,
			canary:   canary,
			wantFire: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeFraming(tt.response, tt.canary, "")
			got := result.IsUnframed()
			if got != tt.wantFire {
				t.Errorf("IsUnframed() = %v, want %v; result=%+v", got, tt.wantFire, result)
			}
		})
	}
}

func TestFramingResult_AllFourRequired(t *testing.T) {
	tests := []struct {
		name string
		fr   FramingResult
		want bool
	}{
		{"all_true", FramingResult{true, true, true, true}, true},
		{"missing_verbatim", FramingResult{false, true, true, true}, false},
		{"missing_unescaped", FramingResult{true, false, true, true}, false},
		{"missing_undelimited", FramingResult{true, true, false, true}, false},
		{"missing_context", FramingResult{true, true, true, false}, false},
		{"all_false", FramingResult{false, false, false, false}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fr.IsUnframed(); got != tt.want {
				t.Errorf("IsUnframed() = %v, want %v", got, tt.want)
			}
		})
	}
}
