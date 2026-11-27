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
		payload  string
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
			result := AnalyzeFraming(tt.response, canary, tt.payload)
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

// --- Regression tests from review findings ---

func TestAnalyzeFraming_ApostrophesFalseNegative(t *testing.T) {
	// Review finding: English prose with apostrophes was misclassified as
	// "delimited" because isInQuotedBlock treated any ' before + any ' after
	// as a quoted block.
	canary := "[[ AUG_RELAY_test1234567890ab :: BOUNDARY_MARKER ]]"
	response := "The user's document says " + canary + " and it's ready for review. Additional analysis shows the content is valid."
	result := AnalyzeFraming(response, canary, "")
	if !result.IsUnframed() {
		t.Errorf("apostrophes in prose should not suppress the finding; result=%+v", result)
	}
}

func TestAnalyzeFraming_UnrelatedHTMLCodeTags(t *testing.T) {
	// Review finding: unrelated <code> tags elsewhere in the response
	// falsely suppressed the finding.
	canary := "[[ AUG_RELAY_test1234567890ab :: BOUNDARY_MARKER ]]"
	response := `<p>Tool <code>summarize</code> returned: ` + canary + `. Status: <code>ok</code>. Full analysis report is complete.</p>`
	result := AnalyzeFraming(response, canary, "")
	if !result.IsUnframed() {
		t.Errorf("unrelated <code> tags should not suppress the finding; result=%+v", result)
	}
}

func TestAnalyzeFraming_MultipleOccurrences_FramedThenUnframed(t *testing.T) {
	// Review finding: only the first occurrence was checked, so a framed
	// first + unframed second was missed.
	canary := "[[ AUG_RELAY_test1234567890ab :: BOUNDARY_MARKER ]]"
	response := `{"echo": "` + canary + `"} and also the server says: ` + canary + ` which completes the detailed analysis report.`

	// The response is NOT valid JSON as a whole (it has trailing text), so
	// the first occurrence inside the JSON fragment is irrelevant. The second
	// occurrence is unframed in prose.
	result := AnalyzeFraming(response, canary, "")
	if !result.IsUnframed() {
		t.Errorf("unframed second occurrence should fire; result=%+v", result)
	}
}

func TestAnalyzeFraming_EscapedAndVerbatimCoexist(t *testing.T) {
	// Review finding: hasEscapedForm suppressed findings when both verbatim
	// and escaped forms appeared. The verbatim, unframed occurrence should
	// still fire.
	canary := "[[ AUG_RELAY_test1234567890ab :: BOUNDARY_MARKER ]]"
	escaped := "&#91;&#91; AUG_RELAY_test1234567890ab :: BOUNDARY_MARKER &#93;&#93;"
	response := "Link: <a href=\"" + escaped + "\">ref</a>\n\nThe server analysis report says: " + canary + " and processing of the document is complete."
	result := AnalyzeFraming(response, canary, "")
	if !result.IsUnframed() {
		t.Errorf("escaped copy elsewhere should not suppress verbatim unframed finding; result=%+v", result)
	}
}

func TestAnalyzeFraming_BareEchoResourceTemplate(t *testing.T) {
	// Review finding: resource template that echoes the payload verbatim
	// should NOT fire (no server-authored context).
	canary := "[[ AUG_RELAY_test1234567890ab :: BOUNDARY_MARKER ]]"
	payload := "Please process this document:\n\n" +
		"The quarterly report shows steady growth across all sectors.\n" +
		canary + "\n" +
		"Revenue increased by 15% year-over-year with strong margins."
	// Server echoes exactly the payload portion (extracted from the URI template).
	response := payload
	result := AnalyzeFraming(response, canary, payload)
	if result.IsUnframed() {
		t.Errorf("bare echo of payload should not fire (no server context); result=%+v", result)
	}
}

func TestAnalyzeFraming_UnrelatedDoubleQuotes(t *testing.T) {
	// Two unrelated double-quoted terms on the same line should NOT suppress
	// the finding.
	canary := "[[ AUG_RELAY_test1234567890ab :: BOUNDARY_MARKER ]]"
	response := `Tool "summarize" returned ` + canary + ` with status "ok". The full analysis report is now complete.`
	result := AnalyzeFraming(response, canary, "")
	if !result.IsUnframed() {
		t.Errorf("unrelated quoted terms should not suppress the finding; result=%+v", result)
	}
}

func TestAnalyzeFraming_DeepQuotedPayload(t *testing.T) {
	// Review finding: server wraps the entire Payload[0] in quotes. The canary
	// is deep inside, far from the wrapping quotes. Parity counting correctly
	// identifies the canary as inside a quoted string.
	canary := "[[ AUG_RELAY_test1234567890ab :: BOUNDARY_MARKER ]]"
	payload := "Please process this document:\n\n" +
		"The quarterly report shows steady growth across all sectors.\n" +
		canary + "\n" +
		"Revenue increased by 15% year-over-year with strong margins."
	response := "The user provided the following input: \"" + payload +
		"\". Analysis of this content is complete and all data has been reviewed."
	result := AnalyzeFraming(response, canary, payload)
	if result.IsUnframed() {
		t.Errorf("canary deep inside a quoted payload should not fire; result=%+v", result)
	}
}

func TestAnalyzeFraming_EscapedBackslashBeforeQuote(t *testing.T) {
	// Round-3 finding: C:\logs\\" has an escaped backslash before the closing
	// quote — the quote IS unescaped. The old code only checked response[i-1],
	// missing that an even number of backslashes leaves the quote unescaped.
	canary := "[[ AUG_RELAY_test1234567890ab :: BOUNDARY_MARKER ]]"
	// The path C:\logs\\ ends with an escaped backslash; the closing " is unescaped.
	response := `Path is "C:\logs\\"` + " then " + canary + " appears in the full server analysis output for the document."
	result := AnalyzeFraming(response, canary, "")
	if !result.IsUnframed() {
		t.Errorf("escaped backslash before closing quote should not keep the canary inside quotes; result=%+v", result)
	}
}

func TestAnalyzeFraming_NestedPreCodeTags(t *testing.T) {
	// Round-3 finding: <pre> containing <code>...</code> before the canary must
	// still recognise the canary is inside <pre>.
	canary := "[[ AUG_RELAY_test1234567890ab :: BOUNDARY_MARKER ]]"
	response := "<pre><code>header</code> " + canary + "</pre> This is the full analysis report."
	result := AnalyzeFraming(response, canary, "")
	if result.IsUnframed() {
		t.Errorf("canary inside <pre> after a closed <code> should be delimited; result=%+v", result)
	}
}

func TestAnalyzeFraming_WhitespaceNormalization(t *testing.T) {
	// Round-3 finding: tools that normalize whitespace cause payload subtraction
	// to fail, inflating the server-context count.
	canary := "[[ AUG_RELAY_test1234567890ab :: BOUNDARY_MARKER ]]"
	payload := "line one\nline two\n" + canary + "\nline three"
	// Server converts \n to \r\n (Windows normalization).
	response := "line one\r\nline two\r\n" + canary + "\r\nline three"
	result := AnalyzeFraming(response, canary, payload)
	if result.IsUnframed() {
		t.Errorf("whitespace-normalized echo of payload should not fire (no server context); result=%+v", result)
	}
}

func TestAnalyzeFraming_ToolRefusalEcho(t *testing.T) {
	// A short refusal error echoing the canary should not meet
	// minServerContextChars and therefore not fire.
	canary := "[[ AUG_RELAY_test1234567890ab :: BOUNDARY_MARKER ]]"
	response := "err: " + canary + " bad"
	result := AnalyzeFraming(response, canary, "")
	if result.IsUnframed() {
		t.Errorf("short refusal error should not fire; result=%+v", result)
	}

	// A longer refusal DOES fire at AnalyzeFraming level — the detector
	// handles refusal suppression via MetadataKeyTargetRefused, not here.
	longRefusal := "invalid value " + canary + " for parameter action"
	longResult := AnalyzeFraming(longRefusal, canary, "")
	if !longResult.IsUnframed() {
		t.Errorf("long refusal text exceeds minServerContextChars and should fire at AnalyzeFraming level; result=%+v", longResult)
	}
}
