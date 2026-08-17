package mcptool

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"

	mcpx "github.com/praetorian-inc/augustus/internal/recon/mcp"
	"github.com/praetorian-inc/augustus/internal/toolpolicy"
	"github.com/praetorian-inc/augustus/internal/toolsig"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("mcptool.BOLA", NewBOLA)
}

// Compile-time assertions: BOLA exposes probe metadata and consumes shared
// reconnaissance (the mcp.identifiers observations).
var (
	_ types.ProbeMetadata     = (*BOLA)(nil)
	_ recon.ContextAwareProbe = (*BOLA)(nil)
)

// BOLA tests a directly-invokable tool surface for broken object-level
// authorization. It consumes the per-identity object identifiers gathered by
// recon.MCPIdentifiers and, under the attacker's identity, replays each OTHER
// identity's confirmed getter/id.
//
// The probe is a payload SENDER only: for each victim object it issues up to
// three calls and records them as evidence — it renders no verdict. Scoring is
// entirely the mcptool.BOLA detector's job (a server-agnostic prune → judge
// chain), so the probe assumes nothing about response format, id format, or
// field names:
//
//	ATTACK   — the getter called with the victim's id (the primary output).
//	NEGATIVE — the same getter with a well-formed-nonexistent id (a not-found
//	           baseline the detector calibrates "denied/empty" against).
//	POSITIVE — the getter with the ATTACKER's OWN id, when the attacker owns an
//	           object for that getter (a served baseline). Omitted otherwise.
//
// The target must implement types.ToolInvoker; other targets are skipped.
type BOLA struct {
	reconContext
	attackerLabel string
	policy        toolpolicy.Policy
}

// NewBOLA constructs the probe.
func NewBOLA(cfg registry.Config) (probes.Prober, error) {
	return &BOLA{
		attackerLabel: registry.GetString(cfg, "attacker_identity_label", "primary"),
		policy:        toolpolicy.New(cfg),
	}, nil
}

func (p *BOLA) Name() string { return "mcptool.BOLA" }

var _ types.RiskDescriber = (*BOLA)(nil)

// RiskInfo is the curated security write-up for this probe's finding.
func (p *BOLA) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description:    "A directly-invokable MCP tool returns an object by identifier without checking that the caller owns it (broken object-level authorization).",
		Impact:         "A caller can read other identities' objects by supplying their identifiers, which are often sequential or enumerable. Where a mutating tool shares the flaw, the same gap allows cross-identity modification.",
		Recommendation: "Check ownership on every access — scope each lookup to the caller's identity (filter by owner/tenant server-side) — and return an identical not-found for objects the caller may not access. Don't rely on identifier unpredictability, and apply the same check to every tool that takes an object identifier.",
		References:     "https://cwe.mitre.org/data/definitions/639.html\nhttps://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
		Taxonomies:     "- cwe: 639\n- cwe: 284\n- cwe: 285",
		CVSSVector:     "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
		Verification: "## How this is confirmed\n\n" +
			"Augustus replays an object identifier confirmed to belong to another identity against the attacker's own session, then compares the attack response to positive and negative controls. When the victim's object is returned to the attacker, the tool is authorizing by identifier alone — broken object-level authorization. Ownership ground truth comes from the `recon.MCPIdentifiers` enumeration (the set-difference of identifiers across identities), not from parsing responses.\n\n" +
			"## Reproduce\n\n" +
			"Re-run the `mcptool.BOLA` probe against the affected endpoint via the `mcp.MCP` generator, with the `recon.MCP` and `recon.MCPIdentifiers` modules enabled. Requires at least two identities (attacker + victim) so the probe can source a victim-owned identifier to replay.",
	}
}

func (p *BOLA) Description() string {
	return "Replays other identities' confirmed object identifiers against the attacker's session, recording attack + positive/negative control responses for the mcptool.BOLA detector to adjudicate a cross-tenant object read (BOLA)"
}

func (p *BOLA) Goal() string {
	return "Determine whether the attacker identity can read objects owned by another identity via a directly-invokable getter tool (BOLA)"
}

func (p *BOLA) GetPrimaryDetector() string { return "mcptool.BOLA" }

func (p *BOLA) GetPrompts() []string {
	return []string{"cross-identity object identifier replayed into a confirmed getter tool"}
}

// Probe reads the mcp.identifiers observations, computes the attacker's own id
// set, and replays every other identity's getter/id under the attacker's session.
// Returns no attempts (no error) when there are no identifiers observations, the
// target is not a ToolInvoker, or the configured attacker_identity_label matches
// none of the discovered identities.
func (p *BOLA) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	identities := mcpx.IdentifiersFrom(p.store)
	if len(identities) == 0 {
		return nil, nil
	}
	attacker, ok := gen.(types.ToolInvoker)
	if !ok {
		slog.Warn("mcptool.BOLA: target is not a ToolInvoker; skipping")
		return nil, nil
	}

	// The attacker label must match a discovered identity, or we would attack EVERY
	// identity's objects — including the attacker's own session — and false-positive.
	attackerKnown := false
	for _, id := range identities {
		if id.Identity == p.attackerLabel {
			attackerKnown = true
			break
		}
	}
	if !attackerKnown {
		slog.Warn("mcptool.BOLA: attacker_identity_label matches no discovered identity; skipping to avoid false positives (it must equal recon's identity_label)", "attacker_identity_label", p.attackerLabel)
		return nil, nil
	}

	// Own objects are keyed by (tool, id): an id value the attacker owns via one
	// getter must not suppress a victim's same-valued id on a DIFFERENT getter
	// (e.g. get_order "1" vs get_ticket "1" are different objects). ownByTool holds
	// one attacker-owned object per getter, the positive-control (served) baseline.
	owned := map[string]bool{}
	ownByTool := map[string]types.MCPObjectRef{}
	for _, id := range identities {
		if id.Identity != p.attackerLabel {
			continue
		}
		for _, obj := range id.Objects {
			owned[ownKey(obj.Tool, obj.ID)] = true
			if _, seen := ownByTool[obj.Tool]; !seen {
				ownByTool[obj.Tool] = obj
			}
		}
	}

	// The values the attacker's OWN calls carried, keyed by argument path. See
	// attackerArgValues: without these the replay is not an attack at all.
	mine := attackerArgValues(identities, p.attackerLabel)
	if len(mine) == 0 {
		slog.Warn("mcptool.BOLA: the attacker identity confirmed no objects of its own, so no argument values are known for it and each replay must inherit the victim's non-identifier arguments. Where identity is carried in an argument rather than in the transport, such a call speaks AS the victim and a served response proves nothing. Attempts are marked with what they inherited.",
			"attacker_identity_label", p.attackerLabel)
	}

	var attempts []*attempt.Attempt
	for _, id := range identities {
		if id.Identity == p.attackerLabel {
			continue
		}
		for _, obj := range id.Objects {
			// Honor the operator's allow/deny lists before replaying a getter. The
			// mcp.identifiers observation carries no tool annotations, so this enforces
			// the by-NAME allow/deny lists only; destructive-annotation gating is
			// applied upstream at recon (recon.MCPIdentifiers filters the catalog through
			// the same toolpolicy before a getter is ever confirmed).
			if skip, _ := p.policy.Skip(obj.Tool, nil); skip {
				continue
			}
			if owned[ownKey(obj.Tool, obj.ID)] {
				continue // attacker owns this exact object; not a cross-identity target
			}
			ownObj, hasOwn := ownByTool[obj.Tool]
			attempts = append(attempts, p.callVictimObject(ctx, attacker, id.Identity, obj, ownObj, hasOwn, mine))
		}
	}
	return attempts, nil
}

// callVictimObject issues the attack call plus its negative (and, when available,
// positive) control and records them as evidence. It renders no verdict.
func (p *BOLA) callVictimObject(ctx context.Context, attacker types.ToolInvoker, victim string, obj, ownObj types.MCPObjectRef, hasOwn bool, mine map[toolsig.Path]any) *attempt.Attempt {
	a := attempt.New(obj.ID)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata["mcptool.tool"] = obj.Tool
	// The PATH, not the bare name. Two arguments of one tool can share a leaf
	// name at different depths, so a name cannot say which one carried the
	// identifier and a reader cannot replay the call from it.
	a.Metadata["mcptool.param"] = string(idPathOf(obj))
	a.Metadata[attempt.MetadataKeyBOLAID] = obj.ID
	a.Metadata[attempt.MetadataKeyBOLAVictimIdentity] = victim
	// Generic ground-truth sentence for the goal-conditioned judge — no server- or
	// format-specific terms.
	a.Metadata[attempt.MetadataKeyGoal] = fmt.Sprintf(
		"Identity %s requested object %s via tool %s; that object belongs to identity %s and %s does not own it.",
		p.attackerLabel, obj.ID, obj.Tool, victim, p.attackerLabel,
	)

	// ATTACK: the victim's IDENTIFIER, in the attacker's OWN call.
	//
	// Only the identifier crosses the identity boundary. Every other argument is
	// restored to the value the attacker's own confirmed calls used, because
	// replaying the victim's whole argument map is not an authorization test: on
	// any surface that carries identity in an argument — a tenant, an account, a
	// workspace — that map contains the victim's identity, so the call speaks as
	// the victim and the server serves it correctly. Measured against a lab server
	// that enforces ownership properly: every replay returned the victim's object,
	// because every replay asked as the victim.
	attackArgs, inherited := p.attackArgs(obj, mine)
	if len(inherited) > 0 {
		// Named, not hidden. These are arguments the attacker has no value of its
		// own for, so if one of them carries identity this call is not purely the
		// attacker's and a served response is not proof of anything.
		a.Metadata[metaBOLAInheritedArgs] = strings.Join(inherited, ",")
	}
	res, err := attacker.CallTool(ctx, obj.Tool, attackArgs)
	if err != nil {
		a.SetError(err)
		return a
	}
	a.AddOutput(cap2k(res.Text))

	// NEGATIVE control: the same call with a well-formed but nonexistent id, so the
	// detector can calibrate what "not found / denied / empty" looks like here. The
	// substituted id is stamped so the detector's prune can mask it (it may be echoed
	// back in the response) without re-deriving it.
	nxID := nonexistentID(obj.ID)
	a.Metadata[attempt.MetadataKeyBOLANonexistentID] = nxID
	negArgs := copyArgs(attackArgs)
	setIDArg(negArgs, obj, nxID)
	if negRes, negErr := attacker.CallTool(ctx, obj.Tool, negArgs); negErr == nil {
		a.Metadata[attempt.MetadataKeyBOLANegativeControl] = cap2k(negRes.Text)
	} else {
		// Record the failure rather than silently dropping the denial baseline: the
		// detector loses only its cheap stage-1 prune (the judge still calibrates on
		// the positive control), but a transient blip must never be invisible.
		a.Metadata[attempt.MetadataKeyBOLANegativeControlError] = negErr.Error()
		slog.Warn("mcptool.BOLA: negative-control call failed; no denial baseline for this attempt",
			"tool", obj.Tool, "id", nxID, "error", negErr)
	}

	// POSITIVE control: the attacker's OWN object via the SAME getter, when it owns
	// one — a served baseline. Omitted when the attacker owns nothing for this getter.
	if hasOwn {
		if posRes, posErr := attacker.CallTool(ctx, ownObj.Tool, callArgs(ownObj)); posErr == nil {
			a.Metadata[attempt.MetadataKeyBOLAPositiveControl] = cap2k(posRes.Text)
		}
	}

	a.Complete()
	return a
}

// metaBOLAInheritedArgs lists the argument paths an attack call had to take from
// the VICTIM's validated call because the attacker had no value of its own for
// them. An identity-bearing argument in that list makes the attempt unsound, so
// it travels with the evidence rather than being decided silently here.
const metaBOLAInheritedArgs = "mcptool.inherited_args"

// attackerArgValues collects, by argument path, the values the ATTACKER's own
// confirmed calls used — the tenant, workspace or account arguments that say who
// is calling, plus any other filler the getter required.
//
// Each reference's own identifier slot is excluded: that value names the
// attacker's object, and writing it into an attack would overwrite the very
// identifier the attack exists to send.
//
// Where two of the attacker's calls disagree about a path the first is kept. A
// value that varies between calls is not an identity value, and identity values
// are what this exists to recover.
func attackerArgValues(identities []*types.MCPIdentifiers, attacker string) map[toolsig.Path]any {
	out := map[toolsig.Path]any{}
	for _, id := range identities {
		if id.Identity != attacker {
			continue
		}
		for _, obj := range id.Objects {
			own := idPathOf(obj)
			for path, v := range toolsig.FlattenArgs(obj.Args) {
				if path == own {
					continue
				}
				if _, seen := out[path]; seen {
					continue
				}
				out[path] = v
			}
		}
	}
	return out
}

// attackArgs builds the attack call: the victim's validated arguments with every
// path the attacker has a value of its own for restored to that value, and the
// victim's identifier written at its own path.
//
// It returns the paths it could NOT restore — arguments inherited from the
// victim's call — so the attempt can carry them as evidence.
func (p *BOLA) attackArgs(obj types.MCPObjectRef, mine map[toolsig.Path]any) (map[string]any, []string) {
	args := callArgs(obj)
	own := idPathOf(obj)

	var inherited []string
	for path := range toolsig.FlattenArgs(args) {
		if path == own {
			continue
		}
		if v, ok := mine[path]; ok {
			toolsig.SetPath(args, path, v)
			continue
		}
		inherited = append(inherited, string(path))
	}
	sort.Strings(inherited)

	// Written last so it survives the restoration above even when the attacker
	// has a value at the same path.
	setIDArg(args, obj, obj.ID)
	return args, inherited
}

// idPathOf returns the path the identifier occupies in an object's call. An
// observation recorded before paths existed carries only a name, which is a top
// level path.
func idPathOf(obj types.MCPObjectRef) toolsig.Path {
	if obj.ParamPath != "" {
		return toolsig.Path(obj.ParamPath)
	}
	return toolsig.Path(obj.Param)
}

// callArgs returns the validated arg map for an object, falling back to just the
// id param for observations that predate Args.
func callArgs(obj types.MCPObjectRef) map[string]any {
	if len(obj.Args) > 0 {
		return copyArgs(obj.Args)
	}
	args := map[string]any{}
	setIDArg(args, obj, obj.ID)
	return args
}

// setIDArg writes an identifier where the getter reads it.
//
// A top-level write is wrong whenever the identifier lives inside a nested
// object, and wrong in the worst way: the real id survives untouched inside the
// object, so the "nonexistent" negative control still addresses the REAL object
// and returns a served response. The detector then reads the attack as matching
// its not-found baseline and scores a genuine authorization flaw safe.
func setIDArg(args map[string]any, obj types.MCPObjectRef, id string) {
	if obj.ParamPath != "" {
		toolsig.SetPath(args, toolsig.Path(obj.ParamPath), id)
		return
	}
	args[obj.Param] = id
}

// copyArgs deep-copies an arg map so per-call mutation (the negative control's
// id swap) never reaches another call's arguments. A shallow copy would share
// every nested object between the two, so swapping the control's id would
// rewrite the attack's as well and both calls would address one object.
func copyArgs(args map[string]any) map[string]any { return toolsig.CopyArgs(args) }

var (
	numericIDRE = regexp.MustCompile(`^[0-9]+$`)
	uuidIDRE    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-([0-9a-fA-F]{12})$`)
)

// nonexistentID derives a well-formed but (best-effort) nonexistent id from a real
// one, format-preserving so the getter accepts the shape and only the object is
// missing. Deterministic (no RNG) for stable tests:
//   - all-numeric      -> a very large same-length numeric sentinel (all 9s);
//   - UUID shape        -> the final hex block replaced with a fixed sentinel;
//   - anything else     -> the id with a "-nonexistent-aug" suffix.
func nonexistentID(id string) string {
	switch {
	case numericIDRE.MatchString(id):
		sentinel := repeatByte('9', len(id))
		if sentinel == id { // the (rare) all-9s id: extend so it differs
			sentinel = "9" + sentinel
		}
		return sentinel
	case uuidIDRE.MatchString(id):
		const sentinel = "ffffffffffff"
		last := uuidIDRE.FindStringSubmatch(id)[1]
		repl := sentinel
		// EqualFold, not ==: UUIDs are case-insensitive (RFC 4122), so an id ending
		// in the UPPERCASE sentinel would otherwise collapse to a case-only variant
		// that a case-insensitive backend treats as the SAME object — aliasing the
		// negative control onto the target and defeating the stage-1 prune.
		if strings.EqualFold(last, sentinel) {
			repl = "000000000000"
		}
		return id[:len(id)-len(last)] + repl
	default:
		return id + "-nonexistent-aug"
	}
}

// repeatByte returns a string of n copies of b.
func repeatByte(b byte, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return string(out)
}

// cap2k caps a recorded tool response to 2048 chars so a large cross-tenant body
// is never stored at rest in full.
func cap2k(text string) string {
	const limit = 2048
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "…(truncated)"
}

// ownKey identifies an object by (tool, id), so an id value the attacker owns via
// one getter does not suppress a victim's same-valued id on a different getter.
func ownKey(tool, id string) string { return tool + "\x00" + id }
