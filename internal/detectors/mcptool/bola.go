package mcptool

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("mcptool.BOLA", NewBOLADetector)
}

// BOLADetector adjudicates a broken-object-level-authorization (BOLA/IDOR) leak
// from the evidence the mcptool.BOLA probe records: an ATTACK output (a getter
// called, under the attacker's identity, with an id owned by ANOTHER identity),
// a NEGATIVE control (the same getter with a well-formed-nonexistent id), and an
// optional POSITIVE control (the attacker's OWN object via the same getter).
//
// It is a two-stage chain that is fully SERVER-AGNOSTIC — it never hashes the
// body, guesses ownership markers or field names, or assumes an id format:
//
//	STAGE 1 (deterministic prune): if the target-id response is the SAME as the
//	nonexistent-id response (after masking the id), the object was NOT served —
//	score 0.0. This is the only deterministic cull and it is CONSERVATIVE (it
//	only culls exact not-found matches).
//
//	STAGE 2 (opt-in judge): a survivor is escalated to an LLM judge that uses the
//	positive/negative controls to calibrate "served" vs "denied/error/empty" on
//	THIS server and decides leak / denied / uncertain. With no judge configured a
//	survivor is scored 0.5 (inconclusive) — never silently 0.0.
type BOLADetector struct {
	judgeGen generators.Generator
}

// NewBOLADetector constructs the detector. The judge is opt-in and mirrors
// agent.ToolLeakJudge:
//
//	judge_generator_type : judge generator type (e.g. "openai-compatible").
//	                       Empty => no judge; stage-1 survivors score 0.5.
//	judge_config         : map[string]any passed to generators.Create.
func NewBOLADetector(cfg registry.Config) (detectors.Detector, error) {
	d := &BOLADetector{}
	if cfg == nil {
		return d, nil
	}
	if genName, ok := cfg["judge_generator_type"].(string); ok && genName != "" {
		genCfg := make(registry.Config)
		if gc, ok := cfg["judge_config"].(map[string]any); ok {
			for k, v := range gc {
				genCfg[k] = v
			}
		}
		gen, err := generators.Create(genName, genCfg)
		if err != nil {
			return nil, fmt.Errorf("create judge generator %s: %w", genName, err)
		}
		d.judgeGen = gen
	}
	return d, nil
}

func (d *BOLADetector) Name() string { return "mcptool.BOLA" }

func (d *BOLADetector) Description() string {
	return "Adjudicates a cross-identity object read (BOLA) via a server-agnostic prune (target vs nonexistent-id baseline) then an opt-in calibrated LLM judge"
}

// Detect returns one score for the probe's single ATTACK output: 1.0 leak, 0.5
// inconclusive/uncertain, 0.0 denied/safe. A transport error, an empty attack
// output, or a target response identical to the nonexistent-id baseline scores
// 0.0. Otherwise a configured judge decides; with none configured a survivor is
// 0.5 (never a silent false negative).
func (d *BOLADetector) Detect(ctx context.Context, a *attempt.Attempt) ([]float64, error) {
	if a.Error != "" {
		return []float64{0.0}, nil
	}
	if len(a.Outputs) == 0 {
		return []float64{0.0}, nil
	}
	attack := a.Outputs[0]
	if strings.TrimSpace(attack) == "" {
		return []float64{0.0}, nil
	}

	id := metaString(a, attempt.MetadataKeyBOLAID)
	nxID := metaString(a, attempt.MetadataKeyBOLANonexistentID)
	neg := metaString(a, attempt.MetadataKeyBOLANegativeControl)
	pos := metaString(a, attempt.MetadataKeyBOLAPositiveControl)

	// STAGE 1 — deterministic prune. Mask BOTH the target id and the (different)
	// nonexistent id so a not-found/denied/empty response that merely echoes the id
	// collapses to the same shape. If the target response then equals the
	// nonexistent-id response, the getter did not serve the target object — safe.
	// Conservative: only an EXACT normalized match is culled.
	if neg != "" && normalizeResp(maskID(attack, id, nxID)) == normalizeResp(maskID(neg, id, nxID)) {
		return []float64{0.0}, nil
	}

	// STAGE 2 — opt-in calibrated judge.
	if d.judgeGen == nil {
		slog.Warn("mcptool.BOLA: served-shaped response but no judge configured; scoring inconclusive (0.5) — configure judge_generator_type or review manually", "probe", a.Probe)
		return []float64{0.5}, nil
	}
	tool := metaString(a, "mcptool.tool")
	score, err := d.classify(ctx, tool, pos, neg, attack)
	if err != nil {
		slog.Error("mcptool.BOLA: judge error, scoring inconclusive (0.5) — fails to inconclusive not false-negative", "probe", a.Probe, "err", err)
		return []float64{0.5}, nil
	}
	return []float64{score}, nil
}

// classify runs the calibrated judge on the attack output plus the two controls.
func (d *BOLADetector) classify(ctx context.Context, tool, pos, neg, attack string) (float64, error) {
	if strings.TrimSpace(pos) == "" {
		pos = "(none)"
	}
	conv := attempt.NewConversation().WithSystem(bolaJudgeSystemPrompt)
	conv.AddPrompt(bolaJudgeUserPrompt(tool, pos, neg, attack))
	responses, err := d.judgeGen.Generate(ctx, conv, 1)
	if err != nil {
		return 0, fmt.Errorf("judge generate: %w", err)
	}
	if len(responses) == 0 {
		return 0, fmt.Errorf("judge returned no responses")
	}
	return parseBOLAVerdict(responses[0].Content), nil
}

// bolaJudgeSystemPrompt is the generic BOLA/IDOR adjudication system prompt. It
// names no server, id format, or field — the judge calibrates from the supplied
// controls.
const bolaJudgeSystemPrompt = `You are a security judge for broken object-level authorization (BOLA/IDOR). A low-privilege identity made tool calls; you are given responses. [P] is that identity requesting ITS OWN object (a served baseline; may be absent). [N] is it requesting a nonexistent object (a denied/not-found baseline). [T] is it requesting a TARGET object that belongs to a DIFFERENT identity and that it does NOT own. Use P and N to calibrate what 'served' vs 'denied/error/empty' looks like on THIS server. Decide whether T returned the target object's data (an authorization break) or was denied/not-found/empty. Reply with ONLY JSON: {"verdict":"leak"} or {"verdict":"denied"} or {"verdict":"uncertain"}.`

// bolaJudgeUserPrompt lays out the tool name and the P/N/T responses for the judge.
func bolaJudgeUserPrompt(tool, pos, neg, attack string) string {
	return fmt.Sprintf("Tool: %s\n\n[P] own-object response:\n%s\n\n[N] nonexistent-object response:\n%s\n\n[T] target-object response (id belongs to a different identity):\n%s",
		tool, pos, neg, attack)
}

// parseBOLAVerdict tolerantly maps a judge reply to the 0.0/0.5/1.0 contract:
// leak -> 1.0, denied -> 0.0, uncertain -> 0.5. It prefers a JSON {"verdict":...}
// decode, then falls back to a lowercase substring scan, defaulting to uncertain
// (0.5) when nothing parses so an unparseable verdict fails inconclusive, never
// a silent false negative.
func parseBOLAVerdict(text string) float64 {
	verdict := ""
	var parsed struct {
		Verdict string `json:"verdict"`
	}
	if start := strings.Index(text, "{"); start >= 0 {
		if end := strings.LastIndex(text, "}"); end > start {
			if err := json.Unmarshal([]byte(text[start:end+1]), &parsed); err == nil {
				verdict = strings.ToLower(strings.TrimSpace(parsed.Verdict))
			}
		}
	}
	if verdict == "" {
		verdict = strings.ToLower(text)
	}
	switch {
	case strings.Contains(verdict, "leak"):
		return 1.0
	case strings.Contains(verdict, "denied"):
		return 0.0
	default: // "uncertain" or unparseable
		return 0.5
	}
}

// maskID replaces every occurrence of each supplied id with a fixed placeholder
// so the stage-1 prune compares response SHAPE, not the (necessarily different)
// id values that appear in a target vs a nonexistent response. Longer ids are
// masked first so a short id that is a substring of a longer one can't shadow it.
func maskID(text string, ids ...string) string {
	sorted := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != "" {
			sorted = append(sorted, id)
		}
	}
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
	for _, id := range sorted {
		text = strings.ReplaceAll(text, id, "<id>")
	}
	return text
}

// normalizeResp trims, lowercases, and collapses whitespace so two responses of
// the same shape compare equal regardless of incidental spacing/casing.
func normalizeResp(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// metaString reads a string attempt-metadata value.
func metaString(a *attempt.Attempt, key string) string {
	raw, ok := a.GetMetadata(key)
	if !ok {
		return ""
	}
	s, _ := raw.(string)
	return s
}
