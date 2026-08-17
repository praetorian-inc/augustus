package mcpprobe

import (
	"encoding/json"
	"strconv"

	"github.com/praetorian-inc/augustus/internal/toolsig"
)

// ToolSignatures parses a tool in the canonical Conversation.Tools wire shape (a
// map with a "parameters" JSON-schema object) into the concrete calls the tool
// accepts.
//
// This replaced a flat reader that looked at top-level "properties" and nothing
// else. That reader was wrong twice over on any schema the MCP specification
// permits but a hand-written parser does not: a parameter nested inside an
// object was invisible, and a parameter declared only under a conditional branch
// did not exist at all. The calls it built were rejected by the server during
// argument validation, and the probes recorded the tool as having been tested.
// See internal/toolsig.
//
// A tool with no "parameters" key takes no arguments, and yields one signature
// with no parameters — a description of the tool, not a failure. A schema that is
// present but unreadable yields nothing, because a surface we could not parse is
// one we cannot honestly claim to have tested.
func ToolSignatures(tool map[string]any) []toolsig.Signature {
	name, _ := tool["name"].(string)
	schema, ok := tool["parameters"].(map[string]any)
	if !ok {
		sigs, _ := toolsig.Signatures(name, nil)
		return sigs
	}
	raw, err := json.Marshal(schema)
	if err != nil {
		return nil
	}
	sigs, err := toolsig.Signatures(name, raw)
	if err != nil {
		return nil
	}
	return sigs
}

// BenignCall builds a call for one signature with a harmless placeholder in
// every REQUIRED parameter, so the call reaches the target's logic instead of
// failing argument validation first.
//
// A call rejected for a missing required argument tells us nothing about
// authorization, which is why the placeholders matter: without them a probe would
// mistake schema validation for an access denial.
//
// The caller gets the Call rather than the arguments so it can Set the value it
// is testing and Unset the one it needs ABSENT — the omitted-versus-forged
// comparison at the heart of the credential-presence check needs both.
func BenignCall(sig toolsig.Signature) *toolsig.Call {
	// The error is deliberately dropped: it reports required parameters no source
	// could fill, and the caller is about to supply the one it cares about. What
	// remains unfilled after that is Call.Unresolved, which reflects the call's
	// actual state rather than a verdict frozen at build time.
	call, _ := sig.Build(toolsig.Chain{benignFiller{}})
	return call
}

// BenignArgs is BenignCall plus overrides, rendered as the argument object to
// send. Overrides are addressed by PATH, so a value destined for a parameter
// nested inside an object lands where the server reads it rather than beside the
// object it belongs in.
func BenignArgs(sig toolsig.Signature, overrides map[toolsig.Path]any) map[string]any {
	call := BenignCall(sig)
	for path, v := range overrides {
		call.Set(path, v)
	}
	return call.Args()
}

// benignFiller supplies a harmless placeholder for every REQUIRED parameter of a
// signature.
//
// It answers for required parameters only. An optional parameter left unset lets
// the tool apply its own default, which is both the long-standing behaviour and
// the smaller intervention: sending a value for something the caller need not
// send changes what the tool does, for no gain to the test.
//
// A value the TARGET declares is preferred over a generic placeholder: it is a
// value the target itself advertises as acceptable, so it is the least likely to
// be rejected out of hand.
//
// That preference is deliberate here and deliberately ABSENT from
// internal/probes/mcptool's own filler, which will only send a declared value it
// recognises as read-only. The two probe families want different things from a
// filler and the difference is not an oversight. Every verdict the authorization
// and credential probes reach is a COMPARISON between two calls, so a filler the
// server rejects destroys the comparison and the finding with it. A
// payload-bearing probe has no such dependency and would rather lose one call
// than have "delete" chosen for it as a benign value.
type benignFiller struct{}

func (benignFiller) Name() string { return "benign" }

func (benignFiller) Value(p toolsig.Param) (any, bool) {
	if !p.Required {
		return nil, false
	}
	return benignValue(p), true
}

// benignValue returns a harmless placeholder for a parameter. A declared enum
// value is preferred: it is a value the target itself advertises as acceptable,
// so it is the least likely to be rejected out of hand.
func benignValue(p toolsig.Param) any {
	if len(p.Enum) > 0 {
		// Enum values are rendered as strings, so a non-string enum
		// ({"type":"integer","enum":[1,2]}) would otherwise be submitted as "1" and
		// rejected by schema validation before the call reaches the parameter under
		// test. Coerce the placeholder back to the declared scalar type.
		return coerceScalar(p.Enum[0], p.Type)
	}
	switch p.Type {
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

// coerceScalar restores a string-stored value to the parameter's declared scalar
// type, falling back to the string when it does not parse (a malformed enum is
// better sent verbatim than dropped).
func coerceScalar(v, typ string) any {
	switch typ {
	case "integer":
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	case "number":
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	case "boolean":
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return v
}
