package mcpprobe

import (
	"regexp"
	"strings"
)

// maxDisclosedValues bounds how many values harvested from one response are
// returned, so a target that lists hundreds of identifiers cannot turn a single
// probe into an unbounded scan.
const maxDisclosedValues = 12

// listAfterColonRE matches an enumeration a server volunteers after a colon —
// "Available systems: database, webserver, admin-console". Requiring at least two
// comma-separated single-token items is what stops it matching ordinary prose:
// "Status: connected" is a statement, not an allow-list.
var listAfterColonRE = regexp.MustCompile(
	`:\s*([A-Za-z0-9][A-Za-z0-9._-]*(?:\s*,\s*[A-Za-z0-9][A-Za-z0-9._-]*)+)`)

// ValuesFromResponse extracts candidate parameter values the TARGET disclosed in
// its own response, excluding any value the probe itself submitted (servers echo
// them, and re-trying our own input discovers nothing).
//
// This is the third and most productive source of target-declared values, after a
// schema enum and the documented description. Servers routinely refuse an
// unrecognised value with a helpful message that enumerates the accepted ones, and
// harvesting that list is a standard technique on any engagement: the values come
// from the target at runtime.
//
// The distinction from overfitting is the point. Reading a value out of a
// particular server's source and shipping it in the probe would score against that
// server and find nothing anywhere else. Reading a value the server VOLUNTEERS is a
// capability that generalises to every target with a talkative error path — and it
// is why this probe can reach a privileged value that appears nowhere in the
// advertised tool catalogue without carrying any knowledge of it.
func ValuesFromResponse(resp string, submitted []string) []string {
	if strings.TrimSpace(resp) == "" {
		return nil
	}
	skip := make(map[string]bool, len(submitted))
	for _, s := range submitted {
		if s != "" {
			skip[strings.ToLower(s)] = true
		}
	}

	var out []string
	seen := map[string]bool{}
	add := func(v string) bool {
		v = strings.TrimSpace(v)
		key := strings.ToLower(v)
		if v == "" || seen[key] || skip[key] {
			return true
		}
		seen[key] = true
		out = append(out, v)
		return len(out) < maxDisclosedValues
	}

	for _, m := range listAfterColonRE.FindAllStringSubmatch(resp, -1) {
		for _, v := range strings.Split(m[1], ",") {
			if !add(v) {
				return out
			}
		}
	}
	// Quoted alternatives ("Use 'grant' or 'revoke'") are the same declaration in
	// a different shape.
	for _, m := range quotedValueRE.FindAllStringSubmatch(resp, -1) {
		if !add(m[1]) {
			return out
		}
	}
	return out
}
