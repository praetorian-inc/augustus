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
//
// The analysis checks EVERY occurrence of the canary in the response and returns
// a positive result if ANY occurrence satisfies all four conditions.
func AnalyzeFraming(response, canary, payload string) FramingResult {
	if canary == "" || response == "" {
		return FramingResult{}
	}

	if !strings.Contains(response, canary) {
		return FramingResult{}
	}

	// If the entire response is valid JSON with the canary inside string
	// values, it is structurally framed regardless of individual occurrences.
	if isInJSONValue(response, canary) {
		return FramingResult{Verbatim: true}
	}

	hasContext := hasServerContext(response, canary, payload)

	// Check each occurrence independently. A framed first occurrence must not
	// mask an unframed second one.
	for idx := 0; idx >= 0 && idx <= len(response)-len(canary); {
		pos := strings.Index(response[idx:], canary)
		if pos < 0 {
			break
		}
		absPos := idx + pos

		if !isOccurrenceDelimited(response, absPos, len(canary)) && hasContext {
			return FramingResult{
				Verbatim:      true,
				Unescaped:     true,
				Undelimited:   true,
				ServerContext: true,
			}
		}
		idx = absPos + len(canary)
	}

	// No unframed occurrence found. The verbatim canary exists but is framed.
	return FramingResult{Verbatim: true, Unescaped: true, ServerContext: hasContext}
}

// isOccurrenceDelimited checks whether a specific canary occurrence (at absPos,
// with length canaryLen) sits inside a recognized data frame.
func isOccurrenceDelimited(response string, absPos, canaryLen int) bool {
	return isInCodeFenceAt(response, absPos) ||
		isInQuotedBlockAt(response, absPos, canaryLen) ||
		isInHTMLCodeTagAt(response, absPos, canaryLen)
}

// isInJSONValue returns true when the entire response is valid JSON and the
// canary appears only inside string values — structured framing.
func isInJSONValue(response, canary string) bool {
	trimmed := strings.TrimSpace(response)
	var v any
	if err := json.Unmarshal([]byte(trimmed), &v); err != nil {
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

// isInCodeFenceAt checks whether the canary at absPos is between paired ```
// markers. Counts fence markers before the position; an odd count means inside.
// Also verifies a closing fence exists after.
func isInCodeFenceAt(response string, absPos int) bool {
	const fence = "```"
	fenceCount := 0
	pos := 0
	for pos < absPos {
		next := strings.Index(response[pos:], fence)
		if next < 0 || pos+next >= absPos {
			break
		}
		fenceCount++
		pos += next + len(fence)
	}
	if fenceCount%2 == 0 {
		return false
	}
	// Verify a closing fence exists after the canary.
	return strings.Contains(response[absPos:], fence)
}

// isInQuotedBlockAt checks whether the canary at absPos sits inside a
// double-quoted string. Single quotes (apostrophes) are NOT treated as
// delimiters — they are ubiquitous in English prose and cause false negatives.
//
// Detection uses parity counting: an odd number of unescaped double-quotes
// before the canary means the canary is inside a quoted string. This correctly
// handles canaries deep inside a long quoted block (e.g., the server wrapping
// the entire caller payload in quotes) where a proximity heuristic would fail.
func isInQuotedBlockAt(response string, absPos, canaryLen int) bool {
	count := 0
	for i := 0; i < absPos; i++ {
		if response[i] == '"' && (i == 0 || response[i-1] != '\\') {
			count++
		}
	}
	if count%2 == 0 {
		return false
	}
	end := absPos + canaryLen
	if end >= len(response) {
		return false
	}
	return strings.IndexByte(response[end:], '"') >= 0
}

// isInHTMLCodeTagAt checks whether the canary at absPos sits inside a
// <pre>/<code> tag. Single-pass: finds the last opening tag before the canary,
// then checks whether that tag was already closed before the canary position.
func isInHTMLCodeTagAt(response string, absPos, canaryLen int) bool {
	before := response[:absPos]
	after := response[absPos+canaryLen:]

	// Find the last opening <pre>/<code> before the canary.
	opens := htmlCodeOpenRE.FindAllStringIndex(before, -1)
	if len(opens) == 0 {
		return false
	}
	lastOpen := opens[len(opens)-1]

	// Check the region between that opening tag and the canary for a closing
	// tag of the same element. If found, the tag closed before the canary.
	between := response[lastOpen[1]:absPos]

	// Extract which element the opening tag matched (pre or code).
	openMatch := htmlCodeOpenRE.FindStringSubmatch(response[lastOpen[0]:lastOpen[1]])
	if len(openMatch) < 2 {
		return false
	}
	elem := strings.ToLower(openMatch[1])
	closePattern := "</" + elem
	if strings.Contains(strings.ToLower(between), closePattern) {
		return false
	}

	// The opening tag is still open at the canary. Verify a matching close
	// exists after.
	return strings.Contains(strings.ToLower(after), closePattern)
}

var htmlCodeOpenRE = regexp.MustCompile(`(?i)<\s*(pre|code)\b[^>]*>`)

// minServerContextChars is the minimum number of letter/digit characters in the
// response (excluding the canary and the caller's payload) for the
// server-context condition to hold. A bare echo or near-bare wrapper must not
// fire.
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
