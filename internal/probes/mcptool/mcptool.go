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
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/praetorian-inc/augustus/internal/toolsig"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// paramInfo describes one tool parameter of one call signature.
type paramInfo struct {
	// name is the parameter's own name, without the object path that leads to
	// it. Probes match on it — a URL-ish or path-ish parameter is recognised by
	// what it is called, not by where it sits — and report it in findings.
	name string
	// path addresses the parameter within the argument object: "url" for a
	// top-level parameter, "params.record_id" for one nested inside an
	// object, "filters[0].field" inside an array element. A name alone cannot
	// carry this, and using one as an address is what put payloads beside the
	// object they belonged in rather than inside it.
	path     toolsig.Path
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

// Parameter discovery now lives in toolSignatures (signatures.go), which reads
// the whole schema rather than only its top-level properties. The flat parser
// that stood here could not see a parameter nested inside an object or declared
// in a conditional branch, and the calls it built were rejected during argument
// validation — which the probes recorded as the tool having been tested.

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
	// a colon-introduced list, which is how servers phrase this in prose and in
	// rejection messages alike: "must be one of: read, write, delete".
	// Anchored on an introducing phrase so an arbitrary "word: text" line (every
	// line of a docstring Args: block) cannot be read as a value list.
	colonListRE = regexp.MustCompile(`(?i)(?:must be|has to be|should be|is )?(?:one of|any of|either|from)[^:\n]{0,20}:\s*([^.\n]{1,160})`)
	// The alternation forms are ANCHORED to the whole parenthetical on purpose.
	// Matching loosely inside prose is how "(only files in /tmp/safe/ allowed)"
	// yields "tmp" and "safe" -- tokens that pass a shape filter but are not
	// values, and would be injected as a gating argument.
	// The separator admits the connective an English list ends with, so
	// "(read, write, or delete)" and "(grant or revoke)" are matched rather than
	// rejected wholesale over the space in "or delete". The token shape and the
	// whole-group anchor are UNCHANGED, which is what still rejects prose: in
	// "(only files in /tmp/safe/ allowed)" the path member cannot match the token
	// shape, so the anchored match fails and the group yields nothing.
	commaAltRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}` +
		`((\s*,\s*((or|and)\s+)?|\s+(or|and)\s+)[A-Za-z0-9][A-Za-z0-9_-]{0,31})+$`)
	slashAltRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}(\s*[/|]\s*[A-Za-z0-9][A-Za-z0-9_-]{0,31})+$`)
	// a candidate must look like a bare token, not prose or a path
	valueTokenRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)
	// the connective that separates the last two members of an English list
	listConnectiveRE = regexp.MustCompile(`(?i)\s+(or|and)\s+`)
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
	return mineCandidateValuesExcluding(frag, nil)
}

// mineCandidateValuesExcluding is mineCandidateValues with a set of values to
// discard, matched case-insensitively.
//
// The exclusion set exists for discovery against a REJECTION message. Servers
// commonly quote the value they refused alongside the list they accept — "Invalid
// action 'test'. Must be one of: read, write, delete". The quoted shape matches
// first, so without exclusion the probe adopts `test`: the very placeholder it
// just sent and the server just refused. Every subsequent call is rejected
// identically and the gated sink stays unreached, which is precisely the failure
// discovery exists to fix.
func mineCandidateValuesExcluding(frag string, exclude map[string]bool) []string {
	if frag == "" {
		return nil
	}
	excluded := func(v string) bool {
		return exclude != nil && exclude[strings.ToLower(v)]
	}

	// Shapes are tried in order of how explicitly they announce a value list, and
	// the first shape that yields anything usable wins.
	//
	// The colon-introduced list goes FIRST despite being the loosest matcher,
	// because colonListRE requires an explicit introducing phrase ("one of",
	// "any of", "either", "from") which is the strongest statement a server makes
	// about its accepted values. A description that merely illustrates values
	// parenthetically cannot match it, so it does not steal from the quoted shape.
	shapes := []func() []string{
		func() (raw []string) {
			for _, m := range colonListRE.FindAllStringSubmatch(frag, -1) {
				raw = append(raw, splitAlternation(m[1])...)
			}
			return raw
		},
		func() (raw []string) {
			for _, m := range quotedValueRE.FindAllStringSubmatch(frag, -1) {
				raw = append(raw, m[1])
			}
			return raw
		},
		func() (raw []string) {
			for _, m := range parenGroupRE.FindAllStringSubmatch(frag, -1) {
				group := strings.TrimSpace(m[1])
				if commaAltRE.MatchString(group) || slashAltRE.MatchString(group) {
					raw = append(raw, splitAlternation(group)...)
				}
				// Anything else is prose or a path: contributes nothing rather
				// than a guess.
			}
			return raw
		},
	}

	for _, shape := range shapes {
		seen := make(map[string]bool)
		var out []string
		for _, v := range shape() {
			v = strings.TrimSpace(v)
			if !valueTokenRE.MatchString(v) || nonValueTokens[strings.ToLower(v)] ||
				excluded(v) || seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

// isStringParam reports whether a param is a viable injection target. An absent
// type is treated as string-injectable (schemas in the wild often omit it).
func isStringParam(typ string) bool {
	return typ == "" || typ == "string"
}

// benignValue picks a filler for a parameter the probe is not injecting into.
// A declared value is preferred over the generic placeholder: where the
// parameter gates which branch the server takes, the placeholder is rejected up
// front and the call never reaches the sink under test.
//
// Only a RECOGNISABLY READ-ONLY declared value is used (safeCandidateValue).
// Reaching for the first declared value instead would hand a tool whose enum is
// ["delete", "read"] its destructive branch as a "benign" filler.
func benignValue(p paramInfo) any {
	if v, ok := declaredValue(p); ok {
		return v
	}
	return placeholderValue(p)
}

// declaredValue returns the filler the TARGET itself supplied for a parameter —
// a typed enum member, or a documented value recognised as read-only — and
// reports whether there was one. A call built entirely from these is one the
// server had a reason to accept.
func declaredValue(p paramInfo) (any, bool) {
	if v, ok := p.typedEnumValue(); ok {
		return v, true
	}
	if v, ok := p.safeCandidateValue(); ok {
		return v, true
	}
	return nil, false
}

// placeholderValue invents a filler from the parameter's declared TYPE alone,
// for a parameter the target documents nothing about. It keeps a call
// well-formed, but it is a guess, and a server that rejects it is rejecting the
// guess rather than telling us anything about the parameter under test.
func placeholderValue(p paramInfo) any {
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
		// Fail closed. An unrecognised operation name is likelier to be rejected
		// than to be safe, and a rejection is the cheaper error.
		return "test"
	}
}

// splitAlternation breaks a list on its separators and drops the connective
// words English puts before the final item ("a, b, and c").
func splitAlternation(group string) []string {
	// A trailing connective is a separator too: "read, write and delete" has
	// three members, not two. Normalising it to a comma first means the member
	// splitter below stays a simple rune scan.
	group = listConnectiveRE.ReplaceAllString(group, ",")
	parts := strings.FieldsFunc(group, func(r rune) bool {
		return r == ',' || r == '/' || r == '|'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		for _, lead := range []string{"and ", "or "} {
			if len(p) > len(lead) && strings.EqualFold(p[:len(lead)], lead) {
				p = strings.TrimSpace(p[len(lead):])
			}
		}
		out = append(out, p)
	}
	return out
}

// discoverToolValues fills in candidate values a tool never declared, by making
// ONE deliberately-invalid call and reading what the server says back.
//
// This is the strongest and most portable source of valid values available,
// because it needs no convention at all: a server that rejects an argument very
// often names what it would have accepted ("Invalid action: test. Must be one of:
// read, write, delete"). Schema `enum` and description mining both depend on the
// author having documented the parameter in a shape we recognise; this depends
// only on the server answering.
//
// Cost is one call per tool, made with placeholder arguments, and it runs only
// for parameters that have no candidates already. Failure is silent and total:
// params keep whatever they had, which is the pre-existing behaviour.
func (ts toolSig) discoverValues(ctx context.Context, inv types.ToolInvoker, tool string) toolSig {
	if inv == nil {
		return ts
	}

	// The adoption test runs BEFORE the call, not after it.
	//
	// A response is not attributed per parameter, so a discovered value can only
	// be adopted where exactly one parameter is missing candidates; with several
	// unknowns there is no way to tell which list belongs to which argument, and
	// guessing wrong is worse than not guessing. Deciding that first matters
	// because the call is a REAL invocation of a customer's tool: performing it
	// and then discarding the response — which is what happens whenever two or
	// more parameters are uncandidated — is a side effect with no possible
	// benefit.
	missing := -1
	for i, p := range ts.params {
		if isStringParam(p.typ) && len(p.candidates) == 0 {
			if missing >= 0 {
				return ts
			}
			missing = i
		}
	}
	if missing < 0 {
		return ts
	}

	// Build the benign call, then ensure the parameter being discovered for is
	// present whether or not it is required.
	//
	// Only required parameters carry a value otherwise, so an uncandidated
	// OPTIONAL parameter would be absent from the call entirely: the tool would
	// run with its own defaults, the response would be an ordinary success rather
	// than the deliberately-invalid rejection this call exists to provoke, and
	// candidates would then be mined out of normal output.
	call, _ := ts.sig.Build(ts.chain())
	target := ts.params[missing]
	if _, ok := call.Get(target.path); !ok {
		call.Set(target.path, benignValue(target))
	}

	// Values we are about to send are excluded from mining: a rejection message
	// routinely quotes the value it refused, and adopting it would pin the probe
	// to the placeholder the server has already rejected.
	sent := map[string]bool{}
	for _, p := range ts.params {
		if v, ok := call.Get(p.path); ok {
			if str, ok := v.(string); ok {
				sent[strings.ToLower(str)] = true
			}
		}
	}

	res, err := inv.CallTool(ctx, tool, call.Args())
	if err != nil || res.Text == "" {
		return ts
	}

	if found := mineCandidateValuesExcluding(res.Text, sent); len(found) > 0 {
		out := ts
		out.params = make([]paramInfo, len(ts.params))
		copy(out.params, ts.params)
		out.params[missing].candidates = found
		return out
	}
	return ts
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
// Restricted to a recognisably READ-ONLY value for the same reason benignValue
// is: the prefix is transmitted and acted upon. Leading a payload with a
// destructive branch name — "delete ; <payload>" — executes the deletion on the
// way to testing the sink.
func payloadPrefixes(p paramInfo) []string {
	if v, ok := p.safeCandidateValue(); ok {
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

// safeOperationValues are declared parameter values that name a READ-ONLY
// operation, either as a dispatch keyword ("read", "list") or as a shell command
// a target's allowlist commonly permits ("ls", "pwd").
//
// This set is a SAFETY control, not a coverage aid. A discriminator's declared
// values are the branches a tool can take, and nothing about the order they are
// declared in says which of them is safe: an enum of ["delete", "read"] leads
// with the destructive branch. Since these values are sent as filler for
// parameters the probe is not testing, and as a leading prefix on the parameter
// it IS testing, picking the wrong one executes a destructive operation the
// probe never intended to invoke.
//
// So selection is allowlist-based and fails closed: a parameter whose declared
// values contain nothing recognisably read-only contributes no value at all, and
// the caller falls back to a placeholder the server will reject. A rejected call
// costs one missed finding. A wrong guess costs the customer data.
var safeOperationValues = map[string]bool{
	// dispatch keywords
	"read": true, "get": true, "fetch": true, "list": true, "view": true,
	"show": true, "display": true, "retrieve": true, "download": true,
	"describe": true, "inspect": true, "search": true, "find": true,
	"query": true, "lookup": true, "count": true, "exists": true,
	"info": true, "status": true, "stat": true, "preview": true, "peek": true,
	// read-only shell commands, the usual contents of a first-token allowlist
	"cat": true, "head": true, "tail": true, "ls": true, "dir": true,
	"pwd": true, "whoami": true, "date": true, "uname": true, "hostname": true,
	"id": true, "echo": true, "true": true, "version": true, "help": true,
}

// safeCandidateValue returns the value the probe will actually SEND for this
// parameter: the first declared or mined candidate recognised as a read-only
// operation. It returns false when the parameter declares no candidate that is
// recognisably safe, which is a deliberate fail-closed outcome — see
// safeOperationValues.
//
// Restricted to string-shaped parameters: a mined token is text, and coercing it
// into a structured parameter would break argument validation rather than
// satisfy it. Numeric and boolean enums are handled by typedEnumValue.
func (p paramInfo) safeCandidateValue() (string, bool) {
	if !isStringParam(p.typ) {
		return "", false
	}
	for _, c := range p.candidates {
		if safeOperationValues[strings.ToLower(c)] {
			return c, true
		}
	}
	return "", false
}

// typedEnumValue converts a declared candidate back to this parameter's native
// type. schemaEnum renders every enum member as a string, so a numeric or
// boolean enum would otherwise fall through to the generic 1/true placeholder
// and be rejected by a server that validates against the declared set.
//
// No safety allowlist applies here: a number or a boolean does not name an
// operation, so there is no destructive branch to select by accident.
func (p paramInfo) typedEnumValue() (any, bool) {
	if len(p.candidates) == 0 {
		return nil, false
	}
	switch p.typ {
	case "integer":
		if n, err := strconv.Atoi(p.candidates[0]); err == nil {
			return n, true
		}
	case "number":
		if f, err := strconv.ParseFloat(p.candidates[0], 64); err == nil {
			return f, true
		}
	case "boolean":
		if b, err := strconv.ParseBool(p.candidates[0]); err == nil {
			return b, true
		}
	}
	return nil, false
}
