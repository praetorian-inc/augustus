package mcptool

import (
	"regexp"
	"sort"
	"strings"
)

// readVerbRE matches tool names and descriptions that declare a read-only
// operation. Anchored on word boundaries so "download" does not match "load".
// Inflections are matched because English tool descriptions are overwhelmingly
// written in the third person -- "Reads file contents", "Returns user
// information" -- and a stem-only pattern silently fails on all of them.
//
// Measured: `read_file` on an independent lab is described as "Reads file
// contents from the filesystem." A bare `\bread\b` does not match "Reads", so
// readIntent returned false, the tool received write-canary payloads instead of
// read payloads, and a documented path traversal was missed. DVMCP happens to
// use bare imperatives ("Read a file from the system"), which matched -- so the
// corpus hid the defect entirely.
// Inflections are GENERATED rather than expressed as a suffix group, because a
// suffix group cannot describe English. `(s|es|ing|ed)?` produces "geting" and
// "runing" but never "getting" or "running", and Go's regexp is RE2 — it has no
// backreferences, so "double the final consonant" is not expressible as a
// pattern. Measured before this change: "Dropping the table", "Setting the
// value" and "Putting the object" all failed mutationVerbRE, and "Running the
// query" was classified read-only.
var readVerbRE = verbRegexp([]string{
	"read", "get", "fetch", "list", "show", "view", "display", "retrieve",
	"download", "cat", "dump", "inspect", "describe", "search", "find",
	"query", "lookup", "browse", "peek", "count", "preview", "print",
})

// mutationVerbRE matches any hint that a tool changes state. Presence of ONE of
// these disqualifies a tool from read payloads even when read verbs also appear,
// because the cost of being wrong is asymmetric: a misjudged writer handed a
// read payload targets a sensitive path.
// Inflected for the same reason as readVerbRE, and it matters more here: the
// mutation list is the safety half, so a verb this list misses admits a
// write-capable tool to the read-payload path.
//
// The vocabulary deliberately includes verbs that are AMBIGUOUS in a tool
// description — "format" usually means formatting output, not formatting a disk;
// "clean" and "reset" often describe cache maintenance. They are listed anyway
// because the two error directions are not symmetric. Treating a reader as a
// mutator costs one missed finding: the tool falls back to write-canary payloads
// under /tmp. Treating a mutator as a reader points a sensitive absolute path at
// a tool that can destroy it. This list is a safety gate, so it fails toward
// caution and accepts the coverage cost.
var mutationVerbRE = verbRegexp([]string{
	"write", "delete", "remove", "create", "update", "modify", "edit", "put",
	"post", "upload", "rename", "move", "copy", "append", "truncate", "set",
	"save", "store", "patch", "destroy", "drop", "insert", "execute", "run",
	"exec", "chmod", "chown", "chgrp", "mkdir", "unlink", "touch",
	// destructive verbs measured missing from the original list
	"clear", "wipe", "reset", "clean", "flush", "format", "purge", "erase",
	"empty", "overwrite", "prune", "revoke", "rotate", "restore", "replace",
	"unset", "install", "deploy", "publish", "provision", "register",
	"unregister", "migrate", "sync", "archive", "extract", "compress",
	"mount", "unmount", "kill", "terminate", "disable", "enable",
})

// irregularVerbForms supplies the surface forms no suffix rule generates. Only
// the verbs actually present in the two lists above are covered; a verb absent
// from both needs no entry.
var irregularVerbForms = map[string][]string{
	"read":  {"read"}, // read/read/read — the base form covers the past
	"get":   {"got", "gotten"},
	"run":   {"ran"},
	"write": {"wrote", "written"},
	"put":   {"put"},
	"set":   {"set"},
	"find":  {"found"},
	"cut":   {"cut"},
	"make":  {"made"},
	"show":  {"shown"},
	"drop":  {"dropped"},
}

// vowels for the consonant-vowel-consonant test in verbForms.
const vowels = "aeiou"

// verbForms returns the surface forms of one regular English verb stem: the
// stem, its third-person singular, its gerund and its past tense, following the
// spelling rules that actually apply.
//
//	ends in s/x/z/ch/sh  → +es          (fetch → fetches)
//	ends in e            → drop e, +ing; +d   (delete → deleting, deleted)
//	ends in consonant+y  → drop y, +ies/+ied  (query → queries, queried)
//	consonant-vowel-consonant → double the final consonant (drop → dropping)
//	otherwise            → +ing, +ed
//
// The doubled and undoubled gerund/past are BOTH emitted for CVC stems. Only one
// is correct English, but this is a matcher, not a generator: accepting the
// misspelling costs nothing and guards against the rule being misapplied.
func verbForms(stem string) []string {
	forms := []string{stem}
	add := func(f ...string) { forms = append(forms, f...) }

	last := stem[len(stem)-1]
	switch {
	case strings.HasSuffix(stem, "s"), strings.HasSuffix(stem, "x"),
		strings.HasSuffix(stem, "z"), strings.HasSuffix(stem, "ch"),
		strings.HasSuffix(stem, "sh"):
		add(stem + "es")
	case last == 'y' && len(stem) > 1 && !strings.ContainsRune(vowels, rune(stem[len(stem)-2])):
		base := stem[:len(stem)-1]
		add(base+"ies", base+"ied")
	default:
		add(stem + "s")
	}

	switch {
	case last == 'e':
		add(stem[:len(stem)-1]+"ing", stem+"d")
	case last == 'y' && len(stem) > 1 && !strings.ContainsRune(vowels, rune(stem[len(stem)-2])):
		add(stem + "ing")
	default:
		add(stem+"ing", stem+"ed")
		// Consonant-vowel-consonant, final consonant not w/x/y: the final
		// consonant doubles. This is the rule `(s|es|ing|ed)?` could not express.
		if n := len(stem); n >= 3 &&
			!strings.ContainsRune(vowels, rune(last)) && !strings.ContainsRune("wxy", rune(last)) &&
			strings.ContainsRune(vowels, rune(stem[n-2])) &&
			!strings.ContainsRune(vowels, rune(stem[n-3])) {
			doubled := stem + string(last)
			add(doubled+"ing", doubled+"ed")
		}
	}
	return forms
}

// verbRegexp builds a case-insensitive, word-boundary-anchored alternation over
// every stem's inflected forms plus its irregulars. Longest-first so the
// alternation cannot match a short prefix of a longer form.
func verbRegexp(stems []string) *regexp.Regexp {
	seen := map[string]bool{}
	var forms []string
	for _, stem := range stems {
		all := append(verbForms(stem), irregularVerbForms[stem]...)
		for _, f := range all {
			if f != "" && !seen[f] {
				seen[f] = true
				forms = append(forms, f)
			}
		}
	}
	sort.Slice(forms, func(i, j int) bool {
		if len(forms[i]) != len(forms[j]) {
			return len(forms[i]) > len(forms[j])
		}
		return forms[i] < forms[j]
	})
	return regexp.MustCompile(`(?i)\b(` + strings.Join(forms, "|") + `)\b`)
}

// identifierSeparatorRE matches the characters that join words inside an
// identifier. See normaliseIdentifiers.
var identifierSeparatorRE = regexp.MustCompile(`[_\-./]+`)

// normaliseIdentifiers rewrites identifier punctuation and camelCase transitions
// into spaces so a verb buried in a symbol name becomes a standalone word.
//
// This is load-bearing, not cosmetic. A word boundary `\b` sits between a word
// character and a non-word character, and `_` IS a word character — so `\bread\b`
// does not match `read_file`, and `\bdelete\b` does not match `deleteUser` or
// `delete_item`. Measured before this change: EVERY tool name tested contributed
// nothing to the read/mutation decision. `delete_item` carried no mutation
// signal at all, so a tool named for deletion and described with a read verb
// ("Gets rid of the entry") was classified read-only and eligible for a
// sensitive-path payload.
//
// camelCaseBoundaryRE is shared with matchesPathParam in pathtraversal.go.
func normaliseIdentifiers(s string) string {
	s = camelCaseBoundaryRE.ReplaceAllString(s, "${1} ${2}")
	return identifierSeparatorRE.ReplaceAllString(s, " ")
}

// readIntent reports whether the tool's own metadata says THIS call only reads.
//
// Two independent signals, in order of strength:
//
//  1. A gating parameter whose selected value is read-oriented. This is the
//     strongest signal available without annotations: a tool dispatching on
//     action="read" performs a read on this call regardless of the write and
//     delete branches it also carries. DVMCP challenge 3's file_manager is
//     exactly this shape.
//  2. The name and description carry a read verb and NO mutation verb. A tool
//     called get_config whose description is "Get a configuration value" and
//     which never mentions writing is a read. DVMCP challenge 10 is this shape.
//
// Signal 2 deliberately requires the ABSENCE of mutation vocabulary, so a
// "read, write, and delete" file manager is not admitted on its name alone.
func readIntent(tool map[string]any, params []paramInfo) bool {
	for _, prm := range params {
		// REQUIRED only. benignArgs sends required parameters and omits optional
		// ones, so an optional discriminator's preferred value is not what the
		// server acts on — it applies its own default, which may well be a write.
		// Trusting it would select a sensitive-path read payload for a call that
		// actually performs a write to that path.
		if !prm.required {
			continue
		}
		// Any value safeCandidateValue returns qualifies, because that function
		// only returns values classified READ-ONLY — and it is the value the call
		// will actually carry.
		//
		// A second, narrower vocabulary used to gate this, which contradicted the
		// first: 27 values were "safe to send" but not "read intent", among them
		// inspect, search, describe, preview, find, query, head, tail and stat. On
		// `action: (inspect, delete)` the probe therefore SENT inspect, rejected it
		// here, fell through to the metadata check, was disqualified by "delete" in
		// the description, and shipped write-canary payloads — missing the
		// arbitrary read in the read-only branch it had just selected.
		if _, ok := prm.safeCandidateValue(); ok {
			return true
		}
	}

	name, _ := tool["name"].(string)
	desc, _ := tool["description"].(string)
	// Normalised so verbs inside identifiers are visible to the matchers; without
	// it the tool NAME contributes nothing at all. See normaliseIdentifiers.
	metadata := normaliseIdentifiers(name + " " + desc)
	return readVerbRE.MatchString(metadata) && !mutationVerbRE.MatchString(metadata)
}
