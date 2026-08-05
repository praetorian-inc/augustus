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
	`(?i)\b(invalid|unauthori[sz]ed|unauthenticated|forbidden|denied|deny|expired|revoked|rejected|reject|refused|malformed|incorrect|illegal|missing|required|failed|failure|error|unknown|not\s+found|no\s+such|does\s+not\s+exist|nonexistent|bad|not\s+permitted|not\s+allowed|permission|access\s+denied)\b`)

// ReadsAsRefusal reports whether a tool response reads as the server refusing the
// request.
//
// It has two distinct uses, and the distinction matters:
//
//   - A detector uses it to WITHHOLD confidence, never to clear a finding. A
//     response this vocabulary does not recognise degrades to inconclusive (a
//     reviewer looks) rather than to a silent clean pass, so a server answering in
//     another language cannot be wrongly reported safe.
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
	for _, v := range present {
		resp = strings.ReplaceAll(resp, v, "<masked>")
	}
	return strings.ToLower(strings.Join(strings.Fields(resp), " "))
}
