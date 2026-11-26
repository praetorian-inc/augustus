package mcpprobe

import (
	"encoding/json"
	"regexp"
	"strings"
	"unicode"
)

// RelayCanary holds a unique structural marker for unframed-relay detection.
// Completely separate from Canary (computed-arithmetic, for injection): the
// injection canary is designed so that an echoing tool CANNOT produce its marker,
// whereas this canary is designed so that an echoing tool DOES reproduce it —
// the question here is not "did it evaluate?" but "did it frame?"
type RelayCanary struct {
	Token    string
	Marker   string
	Payloads []string
}

// NewRelayCanary builds a canary with a unique token. The marker contains
// structural characters ([[, ]], ::) that any framing mechanism would need to
// handle — if they appear verbatim in the response, no escaping was applied.
func NewRelayCanary() RelayCanary {
	token := RandToken()
	marker := "[[ AUG_RELAY_" + token + " :: BOUNDARY_MARKER ]]"

	return RelayCanary{
		Token:  token,
		Marker: marker,
		Payloads: []string{
			// Document-like payload: gives a tool something to process and relay.
			"Please process this document:\n\n" +
				"The quarterly report shows steady growth across all sectors.\n" +
				marker + "\n" +
				"Revenue increased by 15% year-over-year with strong margins.",
			// Minimal payload: just the marker, to detect tools that do a simple echo.
			marker,
		},
	}
}

// FramingResult holds the four conditions that together constitute a finding.
type FramingResult struct {
	Verbatim      bool // canary appears as-is in the response
	Unescaped     bool // no entity, backslash, or URL encoding was applied
	Undelimited   bool // not inside a JSON value, code fence, or quoted string
	ServerContext bool // substantial server-authored text around the canary
}

// IsUnframed returns true when ALL four conditions hold — the canary was relayed
// into server prose without any data boundary.
func (f FramingResult) IsUnframed() bool {
	return f.Verbatim && f.Unescaped && f.Undelimited && f.ServerContext
}

// AnalyzeFraming checks whether a canary appears unframed in a response.
// payload is the original text the probe sent — if the response is a verbatim
// echo of the payload, its text is NOT counted as server context (it came from
// the caller, not the server).
func AnalyzeFraming(response, canary, payload string) FramingResult {
	if canary == "" || response == "" {
		return FramingResult{}
	}

	verbatim := strings.Contains(response, canary)
	if !verbatim {
		return FramingResult{}
	}

	return FramingResult{
		Verbatim:      true,
		Unescaped:     !hasEscapedForm(response, canary),
		Undelimited:   !isDelimited(response, canary),
		ServerContext: hasServerContext(response, canary, payload),
	}
}

// hasEscapedForm checks whether the response also contains an escaped version of
// the canary alongside the verbatim one. The canary contains [, ], :, and spaces
// — characters that escape mechanisms would transform. If ONLY the verbatim form
// appears, the server applied no escaping. If an escaped form also appears, the
// server tried to escape but the verbatim slipped through a different path.
func hasEscapedForm(response, canary string) bool {
	escaped := strings.NewReplacer(
		"[", "&#91;", "]", "&#93;", // HTML entity
	).Replace(canary)
	if escaped != canary && strings.Contains(response, escaped) {
		return true
	}

	escaped = strings.NewReplacer(
		"[", "%5B", "]", "%5D", " ", "%20", // URL encoding
	).Replace(canary)
	if escaped != canary && strings.Contains(response, escaped) {
		return true
	}

	escaped = strings.NewReplacer(
		"[", "\\[", "]", "\\]", // backslash escaping
	).Replace(canary)
	return escaped != canary && strings.Contains(response, escaped)
}

// isDelimited reports whether the canary sits inside a recognized data frame:
// a JSON string value, a code fence, a quoted block, or an HTML code/pre tag.
func isDelimited(response, canary string) bool {
	return isInJSONValue(response, canary) ||
		isInCodeFence(response, canary) ||
		isInQuotedBlock(response, canary) ||
		isInHTMLCodeTag(response, canary)
}

// isInJSONValue returns true when the entire response is valid JSON and the
// canary appears only inside string values — structured framing.
func isInJSONValue(response, canary string) bool {
	trimmed := strings.TrimSpace(response)
	if !json.Valid([]byte(trimmed)) {
		return false
	}
	return containsCanaryInJSON(trimmed, canary)
}

// containsCanaryInJSON walks a JSON value and reports whether the canary
// appears only inside string values, never at the structural level.
func containsCanaryInJSON(raw string, canary string) bool {
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return false
	}
	return canaryInJSONValue(v, canary)
}

func canaryInJSONValue(v any, canary string) bool {
	switch val := v.(type) {
	case string:
		return strings.Contains(val, canary)
	case map[string]any:
		for _, child := range val {
			if canaryInJSONValue(child, canary) {
				return true
			}
		}
	case []any:
		for _, child := range val {
			if canaryInJSONValue(child, canary) {
				return true
			}
		}
	}
	return false
}

// isInCodeFence checks whether the canary appears between paired ``` markers.
func isInCodeFence(response, canary string) bool {
	idx := strings.Index(response, canary)
	if idx < 0 {
		return false
	}

	fenceCount := 0
	pos := 0
	for pos < idx {
		next := strings.Index(response[pos:], "```")
		if next < 0 || pos+next >= idx {
			break
		}
		fenceCount++
		pos += next + 3
	}
	return fenceCount%2 == 1
}

// isInQuotedBlock checks whether the canary is immediately surrounded by
// matching quote characters with no intervening newline — a quoted data value.
func isInQuotedBlock(response, canary string) bool {
	idx := strings.Index(response, canary)
	if idx < 0 {
		return false
	}
	end := idx + len(canary)

	for _, q := range []byte{'"', '\''} {
		before := strings.LastIndexByte(response[:idx], q)
		if before < 0 {
			continue
		}
		if strings.ContainsAny(response[before+1:idx], "\n") {
			continue
		}
		if end < len(response) {
			after := strings.IndexByte(response[end:], q)
			if after >= 0 && !strings.ContainsAny(response[end:end+after], "\n") {
				return true
			}
		}
	}
	return false
}

// htmlCodeTagRE matches opening <pre> or <code> tags, case-insensitive.
var htmlCodeTagRE = regexp.MustCompile(`(?i)<\s*(pre|code)\b[^>]*>`)

// htmlCodeCloseRE matches closing </pre> or </code> tags, case-insensitive.
var htmlCodeCloseRE = regexp.MustCompile(`(?i)</\s*(pre|code)\s*>`)

// isInHTMLCodeTag checks whether the canary sits between <pre>/<code> tags.
func isInHTMLCodeTag(response, canary string) bool {
	idx := strings.Index(response, canary)
	if idx < 0 {
		return false
	}
	end := idx + len(canary)

	opens := htmlCodeTagRE.FindAllStringIndex(response, -1)
	closes := htmlCodeCloseRE.FindAllStringIndex(response, -1)

	for _, open := range opens {
		if open[1] > idx {
			continue
		}
		for _, close := range closes {
			if close[0] >= end && open[1] <= idx {
				return true
			}
		}
	}
	return false
}

// minServerContextChars is the minimum number of letter/digit characters in the
// response (excluding the canary) for the server-context condition to hold. A
// bare echo or near-bare wrapper must not fire.
const minServerContextChars = 20

// hasServerContext reports whether the response contains substantial
// server-authored text around the canary. A bare echo (just the canary or the
// full payload) or a trivial wrapper does not qualify — only text the SERVER
// added counts.
func hasServerContext(response, canary, payload string) bool {
	stripped := response
	if payload != "" {
		stripped = strings.ReplaceAll(stripped, payload, "")
	}
	stripped = strings.ReplaceAll(stripped, canary, "")
	stripped = strings.TrimSpace(stripped)

	count := 0
	for _, r := range stripped {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			count++
		}
	}
	return count >= minServerContextChars
}
