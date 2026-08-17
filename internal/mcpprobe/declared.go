package mcpprobe

import (
	"regexp"
	"strings"

	"github.com/praetorian-inc/augustus/internal/toolsig"
)

// quotedValueRE matches a single-token value inside double quotes, single quotes,
// or backticks. Single-token deliberately: quoted prose ("a long sentence") is
// documentation, not a value the target accepts, and submitting prose as a
// discriminator would produce an error the probe would misread as a denial.
var quotedValueRE = regexp.MustCompile("[\"'`]([A-Za-z0-9][A-Za-z0-9._-]*)[\"'`]")

// slashAlternativesRE matches a parenthesised slash-separated alternation such as
// "(grant/revoke)" — a common way to document accepted values without quoting.
var slashAlternativesRE = regexp.MustCompile(`\(([A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+)\)`)

// DeclaredValues returns the values the TARGET ITSELF declares for a parameter,
// in precedence order:
//
//  1. the parameter's JSON-schema "enum" — the most explicit declaration;
//  2. quoted or slash-alternated values in the parameter's own schema description;
//  3. quoted or slash-alternated values on the parameter's line in the TOOL
//     description's "Args:" block.
//
// Source 3 matters more than it looks. Servers built on the common Python MCP
// frameworks put per-parameter documentation in the tool's docstring, not in the
// parameter schema, so the values such a target advertises are ONLY discoverable
// there. A probe reading the schema alone would find nothing to try and would be
// pushed towards guessing — which is the failure mode this function exists to
// avoid.
//
// It returns only what the target advertises. It never invents a value, so an
// empty result honestly means "this target declares nothing here", and the caller
// decides what to do about that.
// Parameters are matched by LEAF name across every call signature, first match
// winning, so a parameter nested inside an object is found by the same name a
// probe and a docstring both refer to it by. Where two signatures declare the
// same leaf name with different values, this returns the first — a lower bound,
// which is why the per-parameter form below exists for callers that already hold
// the parsed parameter and need no name matching at all.
func DeclaredValues(tool map[string]any, param string) []string {
	desc, _ := tool["description"].(string)
	for _, sig := range ToolSignatures(tool) {
		for _, p := range sig.Params {
			if p.Path.Leaf() != param {
				continue
			}
			return DeclaredValuesFor(p, desc)
		}
	}
	return valuesFromText(paramDocLine(desc, param))
}

// DeclaredValuesFor is DeclaredValues for a parameter that has already been
// parsed out of the schema, applying the same three sources in the same order.
//
// A caller iterating a signature's parameters holds the exact parameter, so it
// should use this rather than search by name: a name is ambiguous across
// conditional branches and across nested objects, and the parameter is not.
func DeclaredValuesFor(p toolsig.Param, toolDesc string) []string {
	if len(p.Enum) > 0 {
		return p.Enum
	}
	if vals := valuesFromText(p.Doc); len(vals) > 0 {
		return vals
	}
	// Prose refers to a parameter by its own name, never by its path.
	return valuesFromText(paramDocLine(toolDesc, p.Path.Leaf()))
}

// paramDocLine returns the line of a docstring-style description that documents
// the named parameter ("    system: The remote system ..."), or "" when absent.
//
// Only that one line is returned: values documented for a DIFFERENT parameter
// must not leak into this one, or the probe would submit (say) a command string
// as a system name and misread the resulting error as an authorization denial.
func paramDocLine(desc, param string) string {
	if desc == "" || param == "" {
		return ""
	}
	prefix := param + ":"
	for _, line := range strings.Split(desc, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, prefix) {
			return trimmed
		}
	}
	return ""
}

// valuesFromText extracts declared values from a fragment of documentation,
// preserving document order and dropping duplicates.
func valuesFromText(text string) []string {
	if text == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(v string) {
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	for _, m := range quotedValueRE.FindAllStringSubmatch(text, -1) {
		add(m[1])
	}
	if len(out) > 0 {
		return out
	}
	for _, m := range slashAlternativesRE.FindAllStringSubmatch(text, -1) {
		for _, v := range strings.Split(m[1], "/") {
			add(v)
		}
	}
	return out
}

// ConventionalPrivilegedNames returns the small, conventional set of privileged
// identity and role names a practitioner would try against ANY target.
//
// This list is the deliberate boundary between legitimate testing and
// overfitting. Trying conventional names is what a pentester does on every
// engagement, and a finding built on them generalises. Copying a magic value out
// of a particular server's source would score a point on that server and find
// nothing anywhere else — so no such value appears here, and the list is capped
// by a test to stop it drifting into a corpus-specific wordlist.
//
// The verdict never depends on WHICH name hit, only on the differential: a call
// that succeeded where an equivalent call with a target-declared value was
// refused. A target whose privileged value is not in this list is reported as not
// vulnerable, which is the honest answer — the probe found no authorization
// differential it could demonstrate.
func ConventionalPrivilegedNames() []string {
	return []string{
		"admin", "administrator", "root", "superuser", "superadmin",
		"system", "sudo", "operator", "owner", "master", "supervisor",
		"privileged", "internal", "sa",
	}
}
