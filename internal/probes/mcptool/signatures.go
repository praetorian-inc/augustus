package mcptool

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/internal/toolsig"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// metaExpectedRefusal marks a refusal the tool's own schema predicted, so a
// reader can tell "the server enforced a constraint it declared" apart from "the
// server rejected something we expected it to accept". Only the second is a
// surprise, and only the second is worth a reader's attention.
const metaExpectedRefusal = "mcptool.expected_refusal"

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
// It is split into two sources, and the split is not cosmetic. One answers with
// a value the TARGET declared or documented; the other invents a generic
// placeholder because nothing was available. Both fill the argument, but only
// the first produces a call the server had any reason to accept — so when a call
// is refused, which source filled its other arguments is the difference between
// "the target refused our payload" and "the target refused our guess". Naming
// them separately is what lets that be read off the call afterwards instead of
// assumed.
type probeFiller struct {
	byPath   map[toolsig.Path]paramInfo
	invented bool
}

func newProbeFiller(params []paramInfo, invented bool) probeFiller {
	m := make(map[toolsig.Path]paramInfo, len(params))
	for _, p := range params {
		m[p.path] = p
	}
	return probeFiller{byPath: m, invented: invented}
}

// sourcePlaceholder names the source that invents a value nothing supplied. A
// call carrying one was built out of a guess, and a refusal of such a call is
// not evidence about the parameter under test.
const sourcePlaceholder = "placeholder"

func (f probeFiller) Name() string {
	if f.invented {
		return sourcePlaceholder
	}
	return "probe"
}

func (f probeFiller) Value(p toolsig.Param) (any, bool) {
	pi, ok := f.byPath[p.Path]
	if !ok || !pi.required {
		return nil, false
	}
	if v, declared := declaredValue(pi); declared {
		if f.invented {
			return nil, false // the declared half of the pair answers this one
		}
		return v, true
	}
	if !f.invented {
		return nil, false
	}
	return placeholderValue(pi), true
}

// chain is the value chain used to prepare a call.
//
// It is deliberately just the probe's own filler. toolsig.FromSchema is not
// included: it would supply values for OPTIONAL parameters that carry a default
// or an enum, and sending those changes the call the probes have always made.
// The discriminator values that select a signature are written by Build itself,
// so a conditional branch is still reached correctly.
func (ts toolSig) chain() toolsig.Chain {
	return append(append(toolsig.Chain{}, ts.pre...),
		newProbeFiller(ts.params, false),
		newProbeFiller(ts.params, true))
}

// guessedArgs lists the required parameters of a prepared call that hold an
// INVENTED placeholder — a value no schema, no operator rule, no hook and no
// observed response supplied — excluding the parameter under test, which the
// caller sets itself.
//
// It is read from the call's own provenance rather than recomputed, so it
// describes the call that was actually sent.
func (ts toolSig) guessedArgs(inject paramInfo) []string {
	call, _ := ts.sig.Build(ts.chain())
	var out []string
	for path, from := range call.Provenance() {
		if from == sourcePlaceholder && path != inject.path {
			out = append(out, string(path))
		}
	}
	sort.Strings(out)
	return out
}

// recordCallFailure records a failed call, deciding whether the parameter under
// test was actually tested.
//
// A refusal is only evidence about the parameter under test when the rest of the
// call was something the server had a reason to accept. If another required
// argument held an invented placeholder, the refusal may be about that
// placeholder and not about the payload at all — the payload never reached
// anything, and reporting "tested, and the target held" would be a false clean
// manufactured by the very change meant to remove one.
//
// So there are three outcomes, not two:
//
//	refused, call otherwise well-formed  — TESTED, negative result.
//	refused, call built on a guess       — NOT TESTED; say which argument.
//	no answer at all                     — NOT TESTED; the request never arrived.
func (ts toolSig) recordCallFailure(a *attempt.Attempt, inject paramInfo, args map[string]any, err error) {
	if !errors.Is(err, types.ErrCallRefused) {
		mcpprobe.RecordCallFailure(a, err)
		return
	}

	// A refusal the tool's OWN schema predicts is attributable, and to the thing
	// under test: we sent a value the schema forbids for this parameter, and the
	// server enforced what it declared. That is a completed test with a negative
	// result, not a gap.
	//
	// The call is still SENT. Validating locally decides how to describe the
	// answer, never whether to ask the question — a server that does not enforce
	// its own schema is precisely what this would otherwise stop us discovering,
	// and such servers exist.
	if args != nil && ts.sig.Validate(args) != nil {
		a.Metadata[attempt.MetadataKeyTargetRefused] = true
		a.Metadata[metaExpectedRefusal] = true
		a.AddOutput("the target refused the call, as its own schema said it would: " + err.Error())
		a.Complete()
		slog.Debug("mcptool: expected refusal; the payload violates the parameter's declared constraint and the target enforced it",
			"tool", ts.tool, "param", string(inject.path))
		return
	}

	guessed := ts.guessedArgs(inject)
	if len(guessed) == 0 {
		mcpprobe.RecordCallFailure(a, err)
		return
	}
	// Both facts are true and both belong in the record: the target did refuse,
	// and we cannot attribute the refusal to the payload.
	a.Metadata[attempt.MetadataKeyTargetRefused] = true
	mcpprobe.MarkNotTested(a, fmt.Sprintf(
		"the target refused the call, but %s carried an invented placeholder, so the refusal cannot be attributed to %s; supply a value with a values: rule",
		strings.Join(guessed, ", "), inject.path))
	a.Metadata[attempt.MetadataKeyInconclusive] = true
	a.Metadata[attempt.MetadataKeyInconclusiveReason] = a.Metadata[attempt.MetadataKeyNotTestedReason]
	a.SetError(err)
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

// markCallOutcome records WHICH kind of failure a differential leg hit, without
// changing the verdict.
//
// These probes reach every verdict by COMPARING two calls, so a leg that
// produced no response leaves the comparison undrawn either way and the attempt
// is inconclusive either way. But "the target considered this call and would not
// run it" and "the request never arrived" are different facts about the scan,
// and only one of them is a coverage gap. Recording which one lets a reviewer
// tell a strict server from a flaky one without rerunning anything.
func markCallOutcome(a *attempt.Attempt, err error) {
	if errors.Is(err, types.ErrCallRefused) {
		a.Metadata[attempt.MetadataKeyTargetRefused] = true
		return
	}
	mcpprobe.MarkNotTested(a, err.Error())
}
