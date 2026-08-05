// Package mcptool provides tool-backend security probes for MCP targets.
// Its probes (Injection, SSRF, PathTraversal) invoke REAL tools through
// types.ToolInvoker to test the backend's own behaviour — injection
// sinks, authorization, SSRF, path traversal. This is distinct from the
// model-facing tool probes elsewhere in the tree that only ask whether
// an LLM can be manipulated INTO a tool call: mcptool calls the tools
// itself and observes what actually runs.
//
// Payload construction (computed-arithmetic canaries, shell-command payloads)
// and the out-of-band collector live in internal/mcpprobe, shared with the
// internal/probes/mcpprimitive package that attacks the non-tool primitives.
//
// Sibling package: internal/probes/mcptransport houses transport-layer
// probes (OriginValidation, SSESessionHijack) that bypass the MCP
// protocol entirely and issue raw HTTP. Different attack surface,
// different interface (types.MCPEndpoint), different package.
package mcptool

import (
	"regexp"
	"strconv"
	"strings"
)

// paramInfo describes one tool parameter parsed from its JSON-schema.
type paramInfo struct {
	name     string
	typ      string
	required bool
	// candidates are plausible VALID values for this parameter, in preference
	// order: JSON-schema "enum" first, then values mined from the tool
	// description. They matter because a sink is often gated behind a
	// discriminator argument ("action", "mode", "operation", "system"): filling
	// it with a placeholder makes the server reject the call before the
	// vulnerable code runs, so the probe reports SAFE on a vulnerable target.
	candidates []string
}

// toolParams parses the parameters of a tool in the canonical Conversation.Tools
// wire shape (map with a "parameters" JSON-schema object).
func toolParams(tool map[string]any) []paramInfo {
	schema, ok := tool["parameters"].(map[string]any)
	if !ok {
		return nil
	}
	props, _ := schema["properties"].(map[string]any)
	desc, _ := tool["description"].(string)

	required := map[string]bool{}
	switch req := schema["required"].(type) {
	case []any:
		for _, r := range req {
			if s, ok := r.(string); ok {
				required[s] = true
			}
		}
	case []string:
		for _, s := range req {
			required[s] = true
		}
	}

	out := make([]paramInfo, 0, len(props))
	for name, raw := range props {
		typ := ""
		var candidates []string
		if p, ok := raw.(map[string]any); ok {
			typ, _ = p["type"].(string)
			candidates = schemaEnum(p)
		}
		// The schema is authoritative; only fall back to prose when it declares
		// no enum. Most servers in the wild declare none (every DVMCP tool ships
		// a bare {"title","type"} property), which is why mining exists at all.
		if len(candidates) == 0 {
			candidates = mineCandidateValues(paramDoc(desc, name))
		}
		out = append(out, paramInfo{name: name, typ: typ, required: required[name], candidates: candidates})
	}
	return out
}

// schemaEnum reads a JSON-schema "enum" as strings. Non-string members are
// rendered where they are unambiguous so a mixed enum still yields a usable
// value rather than none.
func schemaEnum(prop map[string]any) []string {
	raw, ok := prop["enum"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		switch s := v.(type) {
		case string:
			if s != "" {
				out = append(out, s)
			}
		case bool:
			out = append(out, strconv.FormatBool(s))
		case float64:
			out = append(out, strconv.FormatFloat(s, 'f', -1, 64))
		}
	}
	return out
}

// paramDoc returns the fragment of a tool description that documents one named
// parameter. Docstring-derived descriptions (what FastMCP and most SDKs publish)
// put one "name: text" line per parameter under an "Args:" heading. Scoping to
// that line is what makes mining safe: mining the whole description would
// attribute one parameter's allowed values to a different parameter.
func paramDoc(desc, name string) string {
	if desc == "" || name == "" {
		return ""
	}
	prefix := name + ":"
	for line := range strings.SplitSeq(desc, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, prefix) {
			return strings.TrimSpace(trimmed[len(prefix):])
		}
	}
	return ""
}

var (
	// quoted values: (only 'ls', 'pwd', 'whoami', 'date' allowed)
	quotedValueRE = regexp.MustCompile(`['"]([^'"\n]{1,32})['"]`)
	// any parenthesised group, to be vetted by the two alternation forms below
	parenGroupRE = regexp.MustCompile(`\(([^)\n]{1,160})\)`)
	// The alternation forms are ANCHORED to the whole parenthetical on purpose.
	// Matching loosely inside prose is how "(only files in /tmp/safe/ allowed)"
	// yields "tmp" and "safe" -- tokens that pass a shape filter but are not
	// values, and would be injected as a gating argument.
	commaAltRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}(\s*,\s*[A-Za-z0-9][A-Za-z0-9_-]{0,31})+$`)
	slashAltRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}(\s*[/|]\s*[A-Za-z0-9][A-Za-z0-9_-]{0,31})+$`)
	// a candidate must look like a bare token, not prose or a path
	valueTokenRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)
)

// nonValueTokens are words that appear in the same shapes as real values but
// never are one, so a naive list split would otherwise pick them up.
var nonValueTokens = map[string]bool{
	"e": true, "eg": true, "ie": true, "etc": true, "optional": true,
	"required": true, "default": true, "none": true, "null": true,
	"or": true, "and": true, "only": true, "allowed": true,
}

// mineCandidateValues extracts plausible valid values from one parameter's
// documentation fragment. Three shapes cover what servers actually write:
//
//	quoted     — "only 'ls', 'pwd', 'whoami' allowed"
//	paren list — "The action to perform (read, write, delete)"
//	slash alts — "The permission to grant or revoke (grant/revoke)"
//
// Quoted values win when present: a parenthesised "(e.g., \"database\", ...)"
// would otherwise contribute the "e.g." prose as if it were a value.
// Everything is filtered through valueTokenRE, so multi-word prose and paths
// ("only files in /tmp/safe/ allowed") yield nothing rather than a bad guess —
// a wrong value is no better than the placeholder it replaces.
func mineCandidateValues(frag string) []string {
	if frag == "" {
		return nil
	}
	var raw []string
	for _, m := range quotedValueRE.FindAllStringSubmatch(frag, -1) {
		raw = append(raw, m[1])
	}
	if len(raw) == 0 {
		for _, m := range parenGroupRE.FindAllStringSubmatch(frag, -1) {
			group := strings.TrimSpace(m[1])
			switch {
			case commaAltRE.MatchString(group), slashAltRE.MatchString(group):
				raw = append(raw, strings.FieldsFunc(group, func(r rune) bool {
					return r == ',' || r == '/' || r == '|'
				})...)
			default:
				// Prose, or a path -- contributes nothing rather than a guess.
			}
		}
	}

	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		v = strings.TrimSpace(v)
		if !valueTokenRE.MatchString(v) || nonValueTokens[strings.ToLower(v)] || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// isStringParam reports whether a param is a viable injection target. An absent
// type is treated as string-injectable (schemas in the wild often omit it).
func isStringParam(typ string) bool {
	return typ == "" || typ == "string"
}

// benignArgs builds a call argument map: the injected payload in injectParam, and
// benign placeholders for every other required param so the call reaches the sink
// instead of failing argument validation.
func benignArgs(params []paramInfo, injectParam, payload string) map[string]any {
	args := map[string]any{injectParam: payload}
	for _, p := range params {
		if p.name == injectParam || !p.required {
			continue
		}
		args[p.name] = benignValue(p)
	}
	return args
}

// benignValue picks a filler for a parameter the probe is not injecting into.
// A declared or documented value is preferred over the generic placeholder:
// where the parameter gates which branch the server takes, the placeholder is
// rejected up front and the call never reaches the sink under test.
func benignValue(p paramInfo) any {
	if v, ok := p.candidateValue(); ok {
		return v
	}
	switch p.typ {
	case "integer", "number":
		return 1
	case "boolean":
		return true
	case "array":
		return []any{}
	case "object":
		return map[string]any{}
	default:
		return "test"
	}
}

// payloadPrefixes returns the leading text to place before a payload for one
// parameter: always the empty prefix (the payload alone), plus a documented
// valid value when one is known.
//
// Why: a common defence validates only the FIRST token of an argument against an
// allowlist and then hands the whole string to a sink. A payload that begins
// with a separator or an expression fails that check and never reaches the sink,
// so a vulnerable target reports clean. Leading with a value the tool itself
// documents as valid satisfies the check and the payload still lands. Measured
// on DVMCP challenge 2, whose command tool allowlists the first token only.
//
// Gated on a derivable value on purpose: prefixing every parameter
// unconditionally would double an attempt count that already reaches 108 on a
// single challenge, buying nothing where no valid value is known.
func payloadPrefixes(p paramInfo) []string {
	if v, ok := p.candidateValue(); ok {
		return []string{"", v + " "}
	}
	return []string{""}
}

// payloadVariants renders one payload under each prefix from payloadPrefixes.
func payloadVariants(p paramInfo, payload string) []string {
	prefixes := payloadPrefixes(p)
	out := make([]string, 0, len(prefixes))
	for _, pre := range prefixes {
		out = append(out, pre+payload)
	}
	return out
}

// candidateValue returns the preferred valid value for this parameter, if one
// was declared or could be mined. Restricted to string-shaped parameters: a
// mined token is text, and coercing it into a numeric or structured parameter
// would break argument validation rather than satisfy it.
func (p paramInfo) candidateValue() (string, bool) {
	if len(p.candidates) == 0 || !isStringParam(p.typ) {
		return "", false
	}
	return p.candidates[0], true
}
