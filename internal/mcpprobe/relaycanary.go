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
	// mask an unframed second one. Cap the number of occurrences to prevent
	// O(n²) CPU on hostile responses that repeat the canary many times.
	checked := 0
	for idx := 0; idx >= 0 && idx <= len(response)-len(canary); {
		if checked >= maxCanaryOccurrences {
			break
		}
		pos := strings.Index(response[idx:], canary)
		if pos < 0 {
			break
		}
		absPos := idx + pos
		checked++

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

// isInCodeFenceAt checks whether the canary at absPos is between paired fence
// markers. Supports both CommonMark fence characters: ``` (backtick) and ~~~
// (tilde). Counts fence markers before the position; an odd count means inside.
func isInCodeFenceAt(response string, absPos int) bool {
	for _, fence := range []string{"```", "~~~"} {
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
		if fenceCount%2 != 0 && strings.Contains(response[absPos:], fence) {
			return true
		}
	}
	return false
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
		if response[i] == '"' {
			// Count consecutive backslashes immediately before this quote.
			// An even number (including zero) means the quote is unescaped.
			bs := 0
			for j := i - 1; j >= 0 && response[j] == '\\'; j-- {
				bs++
			}
			if bs%2 == 0 {
				count++
			}
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
// <pre>/<code> tag. Walks ALL opening tags before the canary (most recent
// first) so that a closed inner tag does not mask a still-open outer one,
// e.g. `<pre>...<code>...</code>...[canary]...</pre>`.
func isInHTMLCodeTagAt(response string, absPos, canaryLen int) bool {
	before := response[:absPos]
	after := response[absPos+canaryLen:]

	opens := htmlCodeOpenRE.FindAllStringIndex(before, -1)
	if len(opens) == 0 {
		return false
	}

	// Walk backwards: a more-recent unclosed tag is the innermost container.
	for i := len(opens) - 1; i >= 0; i-- {
		openSpan := opens[i]
		openMatch := htmlCodeOpenRE.FindStringSubmatch(response[openSpan[0]:openSpan[1]])
		if len(openMatch) < 2 {
			continue
		}
		elem := strings.ToLower(openMatch[1])
		closePattern := "</" + elem

		between := response[openSpan[1]:absPos]
		if strings.Contains(strings.ToLower(between), closePattern) {
			// This tag closed before the canary; try the next outer one.
			continue
		}

		// The tag is still open at the canary. Verify a matching close after.
		if strings.Contains(strings.ToLower(after), closePattern) {
			return true
		}
	}
	return false
}

var htmlCodeOpenRE = regexp.MustCompile(`(?i)<\s*(pre|code)\b[^>]*>`)

// maxCanaryOccurrences caps the number of canary occurrences checked per
// response. Each check rescans prefix state (quote parity, fence count, HTML
// tags), so uncapped repetition on a hostile 10 MiB response is O(n²). Fifty
// is generous: a legitimate response rarely contains more than a handful of
// canary copies, and an unframed one would be found early.
const maxCanaryOccurrences = 50

// minServerContextChars is the minimum number of letter/digit characters in the
// response (excluding the canary and the caller's payload) for the
// server-context condition to hold. A bare echo or near-bare wrapper must not
// fire.
const minServerContextChars = 20

// hasServerContext reports whether the response contains substantial
// server-authored text around the canary. A bare echo (just the canary or the
// full payload) or a trivial wrapper does not qualify — only text the SERVER
// added counts.
//
// Whitespace is normalized before subtraction so that tools that collapse
// or convert whitespace (e.g. \n → \r\n, multiple spaces → single) do not
// cause the payload subtraction to miss and inflate the server-context count.
func hasServerContext(response, canary, payload string) bool {
	stripped := normalizeWhitespace(response)
	normCanary := normalizeWhitespace(canary)

	if payload != "" {
		normPayload := normalizeWhitespace(payload)
		// Strip the full payload BEFORE the canary. The payload contains the
		// canary, so stripping the canary first would break the full-payload
		// match (the canary-less payload no longer appears in the response).
		stripped = strings.ReplaceAll(stripped, normPayload, "")
		// Also strip individual lines of the original payload. A tool that
		// strips the preamble or reformats newlines may partially echo the
		// payload, leaving caller-authored text that the full match misses.
		for _, line := range strings.Split(payload, "\n") {
			norm := strings.TrimSpace(normalizeWhitespace(line))
			if len(norm) >= minPartialEchoFragment {
				stripped = strings.ReplaceAll(stripped, norm, "")
			}
		}
	}

	// Strip the canary AFTER the full payload, so that the payload match
	// (which contains the canary) is not broken by prior canary removal.
	stripped = strings.ReplaceAll(stripped, normCanary, "")
	stripped = strings.TrimSpace(stripped)

	count := 0
	for _, r := range stripped {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			count++
		}
	}
	return count >= minServerContextChars
}

const minPartialEchoFragment = 10

// normalizeWhitespace collapses all runs of whitespace (including \r\n, \t,
// etc.) into a single space, so that trivial whitespace differences between the
// probe payload and the server response do not defeat payload subtraction.
func normalizeWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inWS := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			if !inWS {
				b.WriteByte(' ')
				inWS = true
			}
		} else {
			b.WriteRune(r)
			inWS = false
		}
	}
	return b.String()
}
