package mcptool

import (
	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/internal/toolsig"
)

// toolSig pairs one of a tool's call signatures with the probe-side information
// about its parameters.
//
// The split is deliberate. toolsig knows JSON Schema: which calls a tool
// accepts, which parameters each one takes, and where they sit in the argument
// object. It knows nothing about attacks. This package keeps everything that is
// attack policy — mining plausible values out of prose, choosing benign filler,
// deciding which parameters are worth a payload — and hands the results back as
// a value source. Neither side has to know how the other works.
type toolSig struct {
	tool   string
	sig    toolsig.Signature
	params []paramInfo
	// pre holds the value sources consulted before this package's own filler:
	// operator configuration, hook variables, and values observed in earlier
	// responses. Empty when a caller supplies none, in which case the filler
	// alone decides, exactly as before.
	pre toolsig.Chain
}

// toolSignatures parses a tool in the canonical Conversation.Tools wire shape
// into its call signatures.
//
// A tool whose schema declares no conditionals yields exactly one signature
// holding its top-level parameters, which is the same set the previous
// flat parser produced. A tool that varies its parameters by discriminator
// yields one signature per branch, and parameters nested inside objects or
// arrays are reached at their real paths rather than being collapsed into an
// opaque placeholder.
//
// An unparseable schema yields nothing, exactly as the previous parser did for
// a tool with no "parameters" key: a tool we cannot read is a tool we cannot
// honestly test.
func toolSignatures(tool map[string]any, pre toolsig.Chain) []toolSig {
	name, _ := tool["name"].(string)
	if _, ok := tool["parameters"].(map[string]any); !ok {
		// A tool declaring no schema at all has no parameter to place a payload
		// in, and the payload probes have always skipped it. mcpprobe.ToolSignatures
		// describes it as a no-argument tool instead, which is right for the probes
		// that make a plain call; it is not what these probes want.
		return nil
	}
	sigs := mcpprobe.ToolSignatures(tool)
	if len(sigs) == 0 {
		return nil
	}

	desc, _ := tool["description"].(string)
	out := make([]toolSig, 0, len(sigs))
	for _, sig := range sigs {
		ts := toolSig{tool: name, sig: sig, pre: pre, params: make([]paramInfo, 0, len(sig.Params))}
		for _, p := range sig.Params {
			ts.params = append(ts.params, paramInfoFrom(p, desc))
		}
		out = append(out, ts)
	}
	return out
}

// paramInfoFrom converts a schema parameter into the probe's working form,
// attaching candidate values in the same order of authority as before.
//
// The schema's enum is definitive. Then the PARAMETER's own description, which
// is where most SDKs put per-argument docs and which needs no attribution
// guessing — it belongs to this parameter by construction. Only then the
// tool-level description's "Args:" block, where the parameter's line has to be
// located by name.
//
// Most servers in the wild declare no enum at all, which is why mining exists.
func paramInfoFrom(p toolsig.Param, toolDoc string) paramInfo {
	candidates := p.Enum
	if len(candidates) == 0 {
		candidates = mineCandidateValues(p.Doc)
	}
	if len(candidates) == 0 {
		// Prose refers to a parameter by its own name, not by its path.
		candidates = mineCandidateValues(paramDoc(toolDoc, p.Path.Leaf()))
	}
	return paramInfo{
		name:       p.Path.Leaf(),
		path:       p.Path,
		typ:        p.Type,
		required:   p.Required,
		candidates: candidates,
	}
}

// probeFiller supplies this package's benign placeholder for a parameter, so
// that a call reaches the tool instead of failing argument validation.
//
// It answers for REQUIRED parameters only. An optional parameter left unset
// lets the tool apply its own default, which is both the behaviour that has
// always been in place and the smaller intervention: sending a value for
// something the caller need not send changes what the tool does for no gain to
// the test.
//
// benignValue already prefers a declared enum member or a value mined from the
// tool's own documentation over a generic placeholder, so this single source
// covers what the schema declares as well as what the prose reveals.
type probeFiller struct{ byPath map[toolsig.Path]paramInfo }

func newProbeFiller(params []paramInfo) probeFiller {
	m := make(map[toolsig.Path]paramInfo, len(params))
	for _, p := range params {
		m[p.path] = p
	}
	return probeFiller{byPath: m}
}

func (probeFiller) Name() string { return "probe" }

func (f probeFiller) Value(p toolsig.Param) (any, bool) {
	pi, ok := f.byPath[p.Path]
	if !ok || !pi.required {
		return nil, false
	}
	return benignValue(pi), true
}

// chain is the value chain used to prepare a call.
//
// It is deliberately just the probe's own filler. toolsig.FromSchema is not
// included: it would supply values for OPTIONAL parameters that carry a default
// or an enum, and sending those changes the call the probes have always made.
// The discriminator values that select a signature are written by Build itself,
// so a conditional branch is still reached correctly.
func (ts toolSig) chain() toolsig.Chain {
	return append(append(toolsig.Chain{}, ts.pre...), newProbeFiller(ts.params))
}

// args builds the arguments for one attempt: benign values everywhere, and the
// payload in the parameter under test.
//
// The payload is written by PATH, so a parameter nested inside an object lands
// where the server reads it rather than beside the object it belongs in. The
// discriminator values that select this signature are written first and are not
// overwritten, because without them the server takes a different branch and the
// call no longer exercises what the signature describes.
func (ts toolSig) args(inject paramInfo, payload any) map[string]any {
	call, _ := ts.sig.Build(ts.chain())
	call.Set(inject.path, payload)
	return call.Args()
}

// benignArgsFor builds arguments with no payload at all — every parameter
// carrying its benign value. Used where a probe needs a baseline call.
func (ts toolSig) benignArgsFor() map[string]any {
	call, _ := ts.sig.Build(ts.chain())
	return call.Args()
}

// unreachable reports the required parameters of this signature that neither
// the schema nor the probe could supply a value for, given that inject will be
// supplied by the caller.
//
// A non-empty result means any verdict from this signature describes how far
// the scanner got, not whether the tool is safe.
func (ts toolSig) unreachable(inject paramInfo) []toolsig.Param {
	call, _ := ts.sig.Build(ts.chain())
	call.Set(inject.path, "")
	return call.Unresolved()
}
