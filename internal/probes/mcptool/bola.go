package mcptool

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	mcpx "github.com/praetorian-inc/augustus/internal/recon/mcp"
	"github.com/praetorian-inc/augustus/internal/toolpolicy"
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
			attempts = append(attempts, p.callVictimObject(ctx, attacker, id.Identity, obj, ownObj, hasOwn))
		}
	}
	return attempts, nil
}

// callVictimObject issues the attack call plus its negative (and, when available,
// positive) control and records them as evidence. It renders no verdict.
func (p *BOLA) callVictimObject(ctx context.Context, attacker types.ToolInvoker, victim string, obj, ownObj types.MCPObjectRef, hasOwn bool) *attempt.Attempt {
	a := attempt.New(obj.ID)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata["mcptool.tool"] = obj.Tool
	a.Metadata["mcptool.param"] = obj.Param
	a.Metadata[attempt.MetadataKeyBOLAID] = obj.ID
	a.Metadata[attempt.MetadataKeyBOLAVictimIdentity] = victim
	// Generic ground-truth sentence for the goal-conditioned judge — no server- or
	// format-specific terms.
	a.Metadata[attempt.MetadataKeyGoal] = fmt.Sprintf(
		"Identity %s requested object %s via tool %s; that object belongs to identity %s and %s does not own it.",
		p.attackerLabel, obj.ID, obj.Tool, victim, p.attackerLabel,
	)

	// ATTACK: replay with the SAME args recon validated the object with (id plus
	// benign placeholders for any other required params); fall back to just the id
	// for older observations that predate Args.
	attackArgs := callArgs(obj)
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
	negArgs[obj.Param] = nxID
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

// callArgs returns the validated arg map for an object, falling back to just the
// id param for observations that predate Args.
func callArgs(obj types.MCPObjectRef) map[string]any {
	if len(obj.Args) > 0 {
		return copyArgs(obj.Args)
	}
	return map[string]any{obj.Param: obj.ID}
}

// copyArgs shallow-copies an arg map so per-call mutation (the negative control's
// id swap) never aliases another call's args.
func copyArgs(args map[string]any) map[string]any {
	out := make(map[string]any, len(args))
	for k, v := range args {
		out[k] = v
	}
	return out
}

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
