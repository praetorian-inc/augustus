package mcptool

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("mcptool.InconsistentAuthorization", NewInconsistentAuthorizationDetector)
}

// InconsistentAuthorizationDetector scores whether two functionally-equivalent
// tools produced materially different responses — an authorization inconsistency.
//
// Two stages:
//  1. Deterministic prune: if normalized responses are identical (after masking),
//     score 0.0 (no inconsistency).
//  2. Opt-in LLM judge: when configured, ask "does this differential represent a
//     privilege bypass?" to distinguish legitimate response variation from an
//     actual authz gap. Without a judge, survivors score 0.5 (inconclusive).
type InconsistentAuthorizationDetector struct {
	judgeGen generators.Generator
}

func NewInconsistentAuthorizationDetector(cfg registry.Config) (detectors.Detector, error) {
	d := &InconsistentAuthorizationDetector{}
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
			return nil, fmt.Errorf("inconsistent-authz judge generator: %w", err)
		}
		d.judgeGen = gen
	}
	return d, nil
}

func (d *InconsistentAuthorizationDetector) Name() string {
	return "mcptool.InconsistentAuthorization"
}

func (d *InconsistentAuthorizationDetector) Description() string {
	return "Scores whether two equivalent tools produced an authorization-relevant response differential"
}

func (d *InconsistentAuthorizationDetector) Detect(ctx context.Context, a *attempt.Attempt) ([]float64, error) {
	if len(a.Outputs) < 2 {
		return scoresFor(a, 0.0), nil
	}

	respA := a.Outputs[0]
	respB := a.Outputs[1]

	if respA == "" && respB == "" {
		return scoresFor(a, 0.0), nil
	}

	normA := normalizeResp(respA)
	normB := normalizeResp(respB)
	if normA == normB {
		return scoresFor(a, 0.0), nil
	}

	if d.judgeGen == nil {
		slog.Warn("mcptool.InconsistentAuthorization: responses differ but no judge configured; scoring inconclusive (0.5)",
			"tool_a", metaString(a, mcpprobe.MetaEquivToolA),
			"tool_b", metaString(a, mcpprobe.MetaEquivToolB))
		return scoresFor(a, InconclusiveScore), nil
	}

	judgeA, judgeB := respA, respB
	const maxJudgeBytes = 4096
	if len(judgeA) > maxJudgeBytes {
		judgeA = judgeA[:maxJudgeBytes] + "…[truncated]"
	}
	if len(judgeB) > maxJudgeBytes {
		judgeB = judgeB[:maxJudgeBytes] + "…[truncated]"
	}
	return d.judgeEquivDifferential(ctx, a, judgeA, judgeB)
}

func (d *InconsistentAuthorizationDetector) judgeEquivDifferential(
	ctx context.Context,
	a *attempt.Attempt,
	respA, respB string,
) ([]float64, error) {
	toolA := metaString(a, mcpprobe.MetaEquivToolA)
	toolB := metaString(a, mcpprobe.MetaEquivToolB)
	argsJSON := metaString(a, mcpprobe.MetaEquivArgs)

	conv := attempt.NewConversation().WithSystem(equivJudgeSystemPrompt)
	conv.AddPrompt(equivJudgeUserPrompt(toolA, toolB, argsJSON, respA, respB))

	responses, err := d.judgeGen.Generate(ctx, conv, 1)
	if err != nil || len(responses) == 0 {
		slog.Error("mcptool.InconsistentAuthorization: judge error; scoring inconclusive",
			"tool_a", toolA, "tool_b", toolB, "err", err)
		return scoresFor(a, InconclusiveScore), nil
	}

	score := parseEquivVerdict(responses[0].Content)
	if score == InconclusiveScore {
		a.Metadata[attempt.MetadataKeyPartialEvidence] = true
		a.Metadata[attempt.MetadataKeyPartialEvidenceReason] = "judge returned medium/low confidence for equivalent-tool authorization differential"
	}
	return scoresFor(a, score), nil
}

const equivJudgeSystemPrompt = `You are a security analyzer evaluating whether two MCP tools on the same server enforce different authorization levels.

You will be shown:
1. Two tool names from the same MCP server
2. The identical arguments sent to both
3. Each tool's response

Your task: determine if the response DIFFERENCE indicates an AUTHORIZATION INCONSISTENCY — meaning one tool returns privileged/elevated data that the other withholds or restricts.

IMPORTANT distinctions:
- Different FORMAT (JSON vs text, different field names) is NOT a finding — focus on the CONTENT.
- Different AMOUNT of data with the same privilege level is NOT a finding.
- One tool returning ELEVATED PRIVILEGES, ADMIN ROLES, or SENSITIVE DATA that the other does not IS a finding.
- One tool refusing/erroring while the other succeeds IS potentially a finding.

Reply with ONLY a JSON object: {"vulnerable": true/false, "confidence": "high"/"medium"/"low", "reason": "one sentence"}`

func equivJudgeUserPrompt(toolA, toolB, args, respA, respB string) string {
	return fmt.Sprintf(`Tool A: %s
Tool B: %s
Arguments (identical for both): %s

Response from Tool A:
%s

Response from Tool B:
%s

Is this response differential an authorization inconsistency?`, toolA, toolB, args, respA, respB)
}

func parseEquivVerdict(text string) float64 {
	type verdict struct {
		Vulnerable bool   `json:"vulnerable"`
		Confidence string `json:"confidence"`
	}
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start >= 0 && end > start {
		var v verdict
		if err := json.Unmarshal([]byte(text[start:end+1]), &v); err == nil {
			if !v.Vulnerable {
				return 0.0
			}
			if strings.EqualFold(v.Confidence, "high") {
				return 1.0
			}
			return InconclusiveScore
		}
	}

	lower := strings.ToLower(text)
	if strings.Contains(lower, "\"vulnerable\": true") || strings.Contains(lower, "\"vulnerable\":true") {
		if strings.Contains(lower, "\"confidence\": \"high\"") || strings.Contains(lower, "\"confidence\":\"high\"") {
			return 1.0
		}
		return InconclusiveScore
	}
	if strings.Contains(lower, "\"vulnerable\": false") || strings.Contains(lower, "\"vulnerable\":false") {
		return 0.0
	}

	return InconclusiveScore
}
