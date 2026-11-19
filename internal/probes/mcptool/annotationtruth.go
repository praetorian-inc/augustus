package mcptool

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/internal/toolpolicy"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("mcptool.AnnotationTruth", NewAnnotationTruth)
}

var (
	_ types.ProbeMetadata     = (*AnnotationTruth)(nil)
	_ types.RiskDescriber     = (*AnnotationTruth)(nil)
	_ recon.ContextAwareProbe = (*AnnotationTruth)(nil)
)

// The annotation claims this probe can check. openWorldHint is out of scope: a
// tool may legitimately reach external services, so no local state diff can
// prove the hint false.
const (
	claimReadOnly       = "readOnlyHint=true"
	claimNonDestructive = "destructiveHint=false"
	claimIdempotent     = "idempotentHint=true"
)

// ponytail: fixed cap keeps calls per tested tool to about 4 per observer; make
// it a config key if real servers need wider state coverage.
const maxObservers = 5

// AnnotationTruth checks whether a tool's server-declared MCP annotations match
// what the tool actually does. Annotations are untrusted metadata, but
// internal/toolpolicy trusts them: a tool that declares readOnlyHint or
// destructiveHint=false passes the destructive-tool safety gate, and MCP clients
// use the same hints to auto-approve calls.
//
// The oracle is a state diff. Other read-only tools act as observers: a tool
// with a read-only name and no behavioral annotation, or a tool whose own
// readOnlyHint already held in this run. An observer counts only if two
// baseline calls return identical output that is not a tool-level error. The
// probe then calls the tool under test once (string parameters with no known
// value carry a unique canary) and calls each observer again:
//
//	readOnlyHint=true      any change in observer output is a mismatch
//	destructiveHint=false  a line or JSON item that existed and is now gone is
//	                       a mismatch (the spec allows additive updates only)
//	idempotentHint=true    a second identical call that changes observer
//	                       output again is a mismatch
//
// With no stable observer the claim is inconclusive, never clean. A tool with an
// untested readOnlyHint is never called as an observer: it may change the state
// that other observers read while its own output stays constant, which gives
// both false mismatches and false held verdicts. So a server that annotates
// every read tool and has no tool read-only by name alone gives inconclusive.
// Observers come from the tools the policy lets through, so a tool_allowlist
// that names only the tool under test also gives inconclusive.
//
// Tools are tested in turn against shared server state that the probe does not
// restore. A tool that empties the state an observer reads can hide what a
// later tool does, so a held verdict is a lower bound, not proof.
//
// The shared toolpolicy gate runs first. A tool whose only claim is
// idempotentHint is destructive by MCP default, so it is tested only with
// allow_destructive=true.
//
// SIDE EFFECTS: the probe invokes the tools under test, which is the point: a
// tool that lies about being read-only will perform its write. The shared
// tool_allowlist and tool_denylist keys still apply.
type AnnotationTruth struct {
	reconContext
	policy toolpolicy.Policy
}

// NewAnnotationTruth constructs the probe with the shared tool-safety policy.
func NewAnnotationTruth(cfg registry.Config) (probes.Prober, error) {
	probe := &AnnotationTruth{policy: toolpolicy.New(cfg)}
	probe.configure(cfg)
	return probe, nil
}

func (p *AnnotationTruth) Name() string { return "mcptool.AnnotationTruth" }

func (p *AnnotationTruth) Description() string {
	return "Invokes tools that declare readOnlyHint, destructiveHint=false, or idempotentHint and diffs the output of stable read-only observer tools to find annotations the tool's behavior contradicts"
}

func (p *AnnotationTruth) Goal() string {
	return "Determine whether any MCP tool declares behavioral annotations that its actual behavior contradicts"
}

func (p *AnnotationTruth) GetPrimaryDetector() string { return "mcptool.AnnotationMismatch" }

func (p *AnnotationTruth) GetPrompts() []string { return nil }

// RiskInfo is the curated security write-up for this probe's finding.
func (p *AnnotationTruth) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description: "An MCP tool declares a behavioral annotation (readOnlyHint, destructiveHint=false, or idempotentHint) that its actual behavior contradicts. " +
			"Annotations are server-declared hints, and the MCP specification says clients must not trust them for security decisions. " +
			"Augustus itself trusts them: internal/toolpolicy skips only tools annotated destructive, so a destructive tool that declares readOnlyHint passes its safety gate.",
		Impact: "Clients that auto-approve tools declared read-only or non-destructive run a tool that writes or destroys data without asking the user. " +
			"A scanner that gates on the same hints sends adversarial calls to a tool it believes is safe.",
		Recommendation: "Declare annotations that match the tool's real behavior. Clients and scanners should treat annotations as untrusted and require confirmation for state-changing tools regardless of the declared hints.",
		References:     "https://modelcontextprotocol.io/specification/2025-06-18/server/tools\nhttps://cwe.mitre.org/data/definitions/345.html\nhttps://cwe.mitre.org/data/definitions/807.html",
		Taxonomies:     "- cwe: 345\n- cwe: 807",
		CVSSVector:     "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N",
		Verification: "## How this is confirmed\n\n" +
			"Augustus calls stable read-only observer tools before and after it invokes the tool under test. A change in an observer's output after the call proves the tool changed state, which contradicts readOnlyHint. Content that disappeared contradicts destructiveHint=false. A change after a second identical call contradicts idempotentHint.\n\n" +
			"## Reproduce\n\n" +
			"Re-run the `mcptool.AnnotationTruth` probe against the affected endpoint through the `mcp.MCP` generator. The finding names the tool, the false annotation, the observer, and the items added or removed.",
	}
}

// Probe tests every annotation claim the target's tools make.
func (p *AnnotationTruth) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	inv, ok := p.invoker(gen)
	if !ok {
		return nil, fmt.Errorf("mcptool.AnnotationTruth: target %q does not support direct tool invocation; this probe requires a tool-surface generator such as mcp.MCP", gen.Name())
	}
	tools, err := p.resolveTools(ctx, gen)
	if err != nil {
		return nil, fmt.Errorf("mcptool.AnnotationTruth: list tools: %w", err)
	}
	tools = p.policy.Filter(p.Name(), tools)

	run := runState{unstable: map[string]bool{}, verified: map[string]bool{}}
	var attempts []*attempt.Attempt
	for _, tool := range tools {
		claims := annotationClaims(tool)
		if len(claims) == 0 {
			continue
		}
		if err := ctx.Err(); err != nil {
			return attempts, err
		}
		attempts = append(attempts, p.testTool(ctx, inv, tool, claims, p.observers(ctx, tools, tool, run), run)...)
	}
	return attempts, nil
}

// annotationClaims lists the checkable claims a tool's annotations make.
// destructiveHint is meaningful only when readOnlyHint is false (MCP spec).
func annotationClaims(tool map[string]any) []string {
	ann, ok := tool["annotations"].(types.MCPToolAnnotations)
	if !ok {
		return nil
	}
	var claims []string
	switch {
	case ann.ReadOnly:
		claims = append(claims, claimReadOnly)
	case ann.Destructive != nil && !*ann.Destructive:
		claims = append(claims, claimNonDestructive)
	}
	if ann.Idempotent {
		claims = append(claims, claimIdempotent)
	}
	return claims
}

// runState is what one Probe run learns about tools as observers.
type runState struct {
	// unstable holds observers whose output changed between two baseline calls.
	// They are not called again: a lying read-only tool would otherwise mutate
	// state as an observer for every subject.
	unstable map[string]bool
	// verified holds tools whose own readOnlyHint held in this run.
	verified map[string]bool
}

// toolCall is one tool name with the exact arguments it is invoked with.
type toolCall struct {
	name string
	args map[string]any
}

func (c toolCall) run(ctx context.Context, inv types.ToolInvoker) (types.ToolResult, error) {
	return inv.CallTool(ctx, c.name, c.args)
}

// read calls c as an observer and returns the response text. A tool-level
// error result reads no state, so it is an error here.
func (c toolCall) read(ctx context.Context, inv types.ToolInvoker) (string, error) {
	res, err := c.run(ctx, inv)
	if err == nil && res.IsError {
		err = fmt.Errorf("%s returned a tool-level error", c.name)
	}
	return res.Text, err
}

// runSubject calls the tool under test and reports whether it answered with a
// tool-level error result.
func (c toolCall) runSubject(ctx context.Context, inv types.ToolInvoker) (bool, error) {
	res, err := c.run(ctx, inv)
	return res.IsError, err
}

// observers returns up to maxObservers other read-only tools that were not seen
// unstable, each with benign arguments. Read-only means a readOnlyHint that
// already held in this run, or mcpprobe.IsReadOnlyTool with no behavioral
// annotation (a read-only name, because most servers ship no hints). A
// destructiveHint=false or idempotentHint tool may still write, so it is never
// an observer.
// ponytail: a tool read-only by name is taken at its name; a lying unannotated
// list_* tool can still drain state. Seed state per subject if that matters.
func (p *AnnotationTruth) observers(ctx context.Context, tools []map[string]any, subject map[string]any, run runState) []toolCall {
	var out []toolCall
	for _, tm := range tools {
		name, _ := tm["name"].(string)
		if !mcpprobe.IsReadOnlyTool(tm) || name == "" || name == subject["name"] || run.unstable[name] {
			continue
		}
		if ann, ok := tm["annotations"].(types.MCPToolAnnotations); ok {
			untestedReadOnly := ann.ReadOnly && !run.verified[name]
			mayWrite := !ann.ReadOnly && len(annotationClaims(tm)) > 0
			if untestedReadOnly || mayWrite {
				continue
			}
		}
		args := map[string]any{}
		if sigs := toolSignatures(tm, p.valueChain(ctx, name)); len(sigs) > 0 {
			args = sigs[0].withShape(p.shapeMode()).benignArgsFor()
		}
		out = append(out, toolCall{name: name, args: args})
		if len(out) == maxObservers {
			break
		}
	}
	return out
}

// subjectCall builds the call for the tool under test: benign arguments, with
// the canary in every string parameter that would otherwise carry an invented
// placeholder, so a write of our input is attributable.
// ponytail: first call signature only; iterate signatures if multi-branch tools
// hide their write behind a discriminator.
func (p *AnnotationTruth) subjectCall(ctx context.Context, tool map[string]any, canary string) toolCall {
	name, _ := tool["name"].(string)
	sigs := toolSignatures(tool, p.valueChain(ctx, name))
	if len(sigs) == 0 {
		return toolCall{name: name, args: map[string]any{}}
	}
	ts := sigs[0].withShape(p.shapeMode())
	call, _ := ts.sig.Build(ts.chain())
	for path, from := range call.Provenance() {
		if v, ok := call.Get(path); ok && from == sourcePlaceholder {
			if _, isString := v.(string); isString {
				call.Set(path, canary)
			}
		}
	}
	return toolCall{name: name, args: call.Args()}
}

// observation is one observer's output around the calls to the tool under test.
type observation struct {
	call     toolCall
	before   string // identical across two baseline calls
	after    string // after the first call to the subject
	repeat   string // after the second identical call, when repeated is true
	repeated bool
}

// stableObservers calls each observer twice and keeps those with identical
// output. Each one that differs or fails (a tool-level error included) is added
// to unstableSet and returned by name.
func stableObservers(ctx context.Context, inv types.ToolInvoker, observers []toolCall, unstableSet map[string]bool) ([]observation, []string) {
	var obs []observation
	var unstable []string
	for _, o := range observers {
		before, err1 := o.read(ctx, inv)
		again, err2 := o.read(ctx, inv)
		if err1 != nil || err2 != nil || before != again {
			unstable = append(unstable, o.name)
			unstableSet[o.name] = true
			continue
		}
		obs = append(obs, observation{call: o, before: before})
	}
	return obs, unstable
}

// reread calls every observer again and stores the output with set. An observer
// that fails is returned by name, and is dropped when drop is true. Otherwise it
// is kept unchanged, so the evidence of its earlier reads still counts.
func reread(ctx context.Context, inv types.ToolInvoker, obs []observation, drop bool, set func(*observation, string)) ([]observation, []string) {
	kept := make([]observation, 0, len(obs))
	var failed []string
	for _, o := range obs {
		out, err := o.call.read(ctx, inv)
		if err != nil {
			failed = append(failed, o.call.name)
			if !drop {
				kept = append(kept, o)
			}
			continue
		}
		set(&o, out)
		kept = append(kept, o)
	}
	return kept, failed
}

// testTool returns one attempt per claim the tool makes, and adds each observer
// that proved unstable to the shared unstable set. It takes every observer
// baseline, calls the subject once (twice for idempotentHint), and re-reads every
// observer after each call.
func (p *AnnotationTruth) testTool(ctx context.Context, inv types.ToolInvoker, tool map[string]any, claims []string, observers []toolCall, run runState) []*attempt.Attempt {
	canary := "augustus-annotation-" + mcpprobe.RandToken()
	subject := p.subjectCall(ctx, tool, canary)
	wantRepeat := false
	for _, c := range claims {
		wantRepeat = wantRepeat || c == claimIdempotent
	}

	obs, unstable := stableObservers(ctx, inv, observers, run.unstable)
	subjectToolError := false
	callSubject := func() error {
		isErr, err := subject.runSubject(ctx, inv)
		subjectToolError = subjectToolError || isErr
		return err
	}
	// firstErr fails every claim. repeatErr fails only idempotentHint, because
	// the other claims are judged on the first call alone.
	var firstErr, repeatErr error
	if len(obs) > 0 {
		if firstErr = callSubject(); firstErr != nil {
			obs = nil
		} else {
			var failed []string
			obs, failed = reread(ctx, inv, obs, true, func(o *observation, out string) { o.after = out })
			unstable = append(unstable, failed...)
			if wantRepeat && len(obs) > 0 {
				if repeatErr = callSubject(); repeatErr == nil {
					obs, failed = reread(ctx, inv, obs, false, func(o *observation, out string) { o.repeat, o.repeated = out, true })
					unstable = append(unstable, failed...)
				}
			}
		}
	}

	attempts := make([]*attempt.Attempt, 0, len(claims))
	for _, claim := range claims {
		a := attempt.New(fmt.Sprintf("tool=%s annotation=%s", subject.name, claim))
		a.Probe = p.Name()
		a.Detector = p.GetPrimaryDetector()
		a.Metadata[mcpprobe.MetaAnnotationTool] = subject.name
		a.Metadata[mcpprobe.MetaAnnotationClaim] = claim
		subjectErr := firstErr
		if claim == claimIdempotent && subjectErr == nil {
			subjectErr = repeatErr
		}
		// Evidence gathered before a later call failed still stands. Only a claim
		// with no contradiction needs every subject call it depends on to have run
		// cleanly.
		switch {
		case len(obs) > 0 && judge(a, claim, subject.name, canary, obs):
			a.Complete()
		case subjectErr != nil:
			mcpprobe.MarkNotTested(a, "call to the tool under test failed: "+subjectErr.Error())
			a.Metadata[attempt.MetadataKeyInconclusive] = true
			a.Metadata[attempt.MetadataKeyInconclusiveReason] = a.Metadata[attempt.MetadataKeyNotTestedReason]
			a.SetError(subjectErr)
		case claim == claimIdempotent && len(obs) > 0 && !anyRepeated(obs):
			inconclusive(a, claim, "no observer could be read again after the second call to the tool under test")
		case len(obs) == 0:
			inconclusive(a, claim, fmt.Sprintf("no stable read-only observer tool to diff state against (%d candidate(s) changed between baseline calls or failed: %s)",
				len(unstable), strings.Join(unstable, ", ")))
		case subjectToolError:
			inconclusive(a, claim, "the tool under test returned a tool-level error, so it may not have run the code its annotation describes")
		default:
			a.AddOutput(fmt.Sprintf("%s held for %s: no contradicting change in %d stable observer(s): %s",
				claim, subject.name, len(obs), observerNames(obs)))
			a.Complete()
			if claim == claimReadOnly {
				run.verified[subject.name] = true
			}
		}
		attempts = append(attempts, a)
	}
	return attempts
}

// inconclusive records a claim the probe could not check, and why.
func inconclusive(a *attempt.Attempt, claim, reason string) {
	a.Metadata[attempt.MetadataKeyInconclusive] = true
	a.Metadata[attempt.MetadataKeyInconclusiveReason] = reason
	a.AddOutput(claim + " not verified: " + reason)
	a.Complete()
}

func anyRepeated(obs []observation) bool {
	for _, o := range obs {
		if o.repeated {
			return true
		}
	}
	return false
}

func observerNames(obs []observation) string {
	names := make([]string, len(obs))
	for i, o := range obs {
		names[i] = o.call.name
	}
	return strings.Join(names, ", ")
}

// judge records the evidence of every observation that contradicts the claim
// and reports whether there was any.
func judge(a *attempt.Attempt, claim, tool, canary string, obs []observation) bool {
	var evidence []string
	for _, o := range obs {
		switch claim {
		case claimReadOnly:
			if o.after != o.before {
				evidence = append(evidence, fmt.Sprintf("after one call to %s, the output of read-only observer %s changed: %s",
					tool, o.call.name, describeDiff(o.before, o.after, canary)))
			}
		case claimNonDestructive:
			if _, removed := contentDiff(o.before, o.after); len(removed) > 0 {
				evidence = append(evidence, fmt.Sprintf("after one call to %s, existing content in the output of observer %s was modified or deleted: %s",
					tool, o.call.name, describeDiff(o.before, o.after, canary)))
			}
		case claimIdempotent:
			if o.repeated && o.repeat != o.after {
				evidence = append(evidence, fmt.Sprintf("a second identical call to %s changed the output of observer %s again: %s",
					tool, o.call.name, describeDiff(o.after, o.repeat, canary)))
			}
		}
	}
	if len(evidence) == 0 {
		return false
	}
	a.Metadata[mcpprobe.MetaAnnotationMismatch] = true
	for _, e := range evidence {
		a.AddOutput(fmt.Sprintf("%s is false for %s: %s", claim, tool, e))
	}
	return true
}

// describeDiff renders the added and removed items between two outputs.
func describeDiff(before, after, canary string) string {
	added, removed := contentDiff(before, after)
	var parts []string
	for _, l := range added {
		part := fmt.Sprintf("added %q", mcpprobe.TruncateResponse(l))
		if strings.Contains(l, canary) {
			part += " (contains the canary sent to the tool)"
		}
		parts = append(parts, part)
	}
	for _, l := range removed {
		parts = append(parts, fmt.Sprintf("removed %q", mcpprobe.TruncateResponse(l)))
	}
	if len(parts) == 0 {
		return "no item was added or removed (only order or whitespace changed)"
	}
	return strings.Join(parts, "; ")
}

// contentDiff returns the items of after that are not in before, and the items
// of before that are not in after, counting duplicates.
func contentDiff(before, after string) (added, removed []string) {
	beforeItems, afterItems := contentItems(before), contentItems(after)
	left := map[string]int{}
	for _, l := range beforeItems {
		left[l]++
	}
	for _, l := range afterItems {
		if left[l] > 0 {
			left[l]--
			continue
		}
		added = append(added, l)
	}
	for _, l := range beforeItems {
		if left[l] > 0 {
			left[l]--
			removed = append(removed, l)
		}
	}
	return added, removed
}

// contentItems splits s at line breaks and JSON delimiters, so an item added to
// a one-line JSON list does not read as the old line being removed. Blank items
// are dropped: an empty output would otherwise read as content that was removed.
// ponytail: a value changed in place (a counter) still reads as removed; diff
// parsed JSON leaves if real servers report counts beside their items.
func contentItems(s string) []string {
	var out []string
	for _, item := range strings.FieldsFunc(s, func(r rune) bool { return strings.ContainsRune("\n,[]{}", r) }) {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
