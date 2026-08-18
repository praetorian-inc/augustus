package mcpprobe

import (
	"regexp"
	"sort"
	"strings"
)

// refusalVocabularyRE matches CONVENTIONAL refusal wording — words any
// practitioner would read as "the server said no". A generic vocabulary, with
// nothing specific to a server, product, or benchmark.
//
// Word boundaries matter more than they look: without them "invalid" would make
// "valid" match, inverting the verdict on the single most common acceptance
// wording there is.
var refusalVocabularyRE = regexp.MustCompile(
	`(?i)\b(invalid|unauthori[sz]ed|unauthenticated|forbidden|denied|deny|expired|revoked|rejected|reject|refused|malformed|incorrect|illegal|missing|required|failed|failure|error|unknown|not\s+found|no\s+such|does\s+not\s+exist|nonexistent|not\s+permitted|not\s+allowed|access\s+denied|permission\s+denied)\b`)

// ReadsAsRefusal reports whether a tool response reads as the server refusing the
// request.
//
// It has two distinct uses, and the distinction matters:
//
//   - A detector uses it to ADJUDICATE: a probe response that reads as a refusal
//     scores 0.0 (the probe reached nothing), and a control that reads as a refusal
//     where the probe was served scores 1.0. In the UNRECOGNISED direction it only
//     withholds confidence — a control refusal it cannot read degrades to
//     inconclusive rather than to a silent clean pass, so a server refusing in
//     another language is not wrongly cleared. But the RECOGNISED direction is a
//     text match on a shared vocabulary, so it is only as good as that vocabulary: a
//     SERVED response that merely contains a refusal word (a success envelope with
//     `"error": null`, a `"0 failed"` count) can be misread as a refusal, in either
//     the 0.0 or the 1.0 direction. Replacing this text sniff with the structural
//     signal the transport already carries (ToolResult.IsError) is tracked in
//     LAB-5841; the vocabulary cannot be safely narrowed instead, because the same
//     words carry real refusal meaning in a genuine refusal.
//   - A probe uses it to TARGET further calls — a refusal is exactly the response
//     worth retrying with a credential attached, to find out whether the refusal
//     enforces anything. That is a targeting heuristic, not a verdict, in the same
//     spirit as the URL-parameter matching that focuses the SSRF probe.
//
// One definition serves both so the two halves cannot drift apart.
func ReadsAsRefusal(text string) bool {
	return refusalVocabularyRE.MatchString(text)
}

// ResponseClass normalises a response into a comparable equivalence class: the
// submitted values are masked out and whitespace and case are collapsed.
//
// Masking is what makes response comparison possible at all. Servers routinely
// echo the value they were given, so without it every response would differ from
// every other and any comparison would "find" a difference on every target.
//
// Longest values are masked first so that one value which is a substring of
// another cannot partially mask it and leave a fragment behind.
func ResponseClass(resp string, values ...string) string {
	present := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" {
			present = append(present, v)
		}
	}
	sort.Slice(present, func(i, j int) bool { return len(present[i]) > len(present[j]) })
	// Lowercased BEFORE masking, and the masked values with it. A server is free to
	// echo a submitted value in a different case than it was sent ("ALPHA-TOKEN" for
	// "alpha-token"); a case-sensitive replace misses it, the value survives into the
	// compared template, and two responses that differ only by the echoed value are
	// then read as behaving differently.
	resp = strings.ToLower(resp)
	for _, v := range present {
		resp = strings.ReplaceAll(resp, strings.ToLower(v), "<masked>")
	}
	return strings.Join(strings.Fields(resp), " ")
}
