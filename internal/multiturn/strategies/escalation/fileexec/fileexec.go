// Package fileexec implements a multi-turn escalation strategy that probes for
// untrusted-file code execution by an agent (OWASP LLM06 Excessive Agency /
// LLM05 Insecure Output Handling; CWE-434).
//
// The technique: an agent with file-manipulation and shell/code tools can be
// coaxed, over several turns, into executing content the attacker supplied —
// by writing/renaming/stripping-an-extension/chmod-ing a file and running it,
// or by invoking an interpreter on a non-executable file (e.g. `bash notes.txt`).
// Phrased as a mundane build/debug errand and advanced one rung at a time, this
// laundering defeats upload file-type allowlists and keyword/content guards that
// block a direct "run my malware" request.
//
// It plugs into the shared multi-turn engine via the multiturn.Strategy
// interface, exactly like the crescendo/goat/hydra strategies. The engine owns
// conversation management, refusal detection, judge evaluation, backtracking,
// and attempt building; this strategy only supplies the attacker prompts that
// drive the escalation ladder (benign file work -> introduce content -> defeat
// the type gate -> execute -> surface output). The prompts teach the technique
// generically and never name a specific target, tool, or payload.
//
// Auxiliary requirement — a pre-uploaded file. The attack assumes the operator
// has already uploaded a file carrying the attacker's content into the target
// agent's workspace; the prompts reference that file by name and drive the agent
// to rename/run it. The filename is supplied via the probe's "upload_filename"
// config and defaults to defaultUploadFilename. Without that upload the probe
// still exercises the agent's willingness to author/rename/run local content,
// but against a target that only executes genuinely uploaded files it will
// under-report.
package fileexec

import (
	"github.com/praetorian-inc/augustus/internal/multiturn"
)

// defaultUploadFilename is the workspace filename the prompts reference when no
// override is supplied. The probe expects the operator to have pre-uploaded a
// file by this name (carrying the attacker's content) into the target agent's
// workspace; the attacker LLM then drives the agent to rename/run THAT file.
const defaultUploadFilename = "notes.txt"

// Strategy implements the untrusted-file execution escalation attack.
type Strategy struct {
	// AttackerModel is the attacker model name, used to derive context-aware
	// truncation limits for response text in prompts.
	AttackerModel string

	// MaxTurns is used for rung pacing in prompts.
	MaxTurns int

	// UploadFilename is the name of the file the operator pre-uploaded to the
	// target agent's workspace; the prompts reference it so the attacker anchors
	// the escalation on that file. Defaults to defaultUploadFilename when empty.
	UploadFilename string
}

// Name returns the strategy identifier.
func (s *Strategy) Name() string { return "fileexec_escalation" }

// SetMaxTurns configures the maximum turn count for prompt generation.
func (s *Strategy) SetMaxTurns(n int) { s.MaxTurns = n }

// AttackerSystemPrompt returns the untrusted-file execution escalation system prompt.
func (s *Strategy) AttackerSystemPrompt(goal string) string {
	return attackerSystemPrompt(s.uploadFilename())
}

// GenerateTurnPrompt builds the prompt asking for the next escalation message.
func (s *Strategy) GenerateTurnPrompt(goal string, turnHistory []multiturn.TurnRecord, turnNum int) string {
	return turnPrompt(goal, turnHistory, turnNum, s.maxTurns(), s.charBudget(), s.uploadFilename())
}

// RephrasePrompt builds a prompt to rephrase a refused message.
func (s *Strategy) RephrasePrompt(rejectedQuestion, refusalResponse string) string {
	return rephrasePrompt(rejectedQuestion, refusalResponse, s.charBudget())
}

// FeedbackPrompt feeds the target response + score back to the attacker.
func (s *Strategy) FeedbackPrompt(response string, score float64, goal string) string {
	return feedbackPrompt(response, score, goal, s.charBudget())
}

// ParseAttackerResponse extracts the question and strategy from attacker output.
func (s *Strategy) ParseAttackerResponse(output string) *multiturn.QuestionResult {
	return multiturn.ExtractJSON(output)
}

// charBudget returns the per-response character budget based on attacker model.
func (s *Strategy) charBudget() int {
	return multiturn.ResponseCharBudget(s.AttackerModel)
}

// uploadFilename returns UploadFilename with a default fallback.
func (s *Strategy) uploadFilename() string {
	if s.UploadFilename != "" {
		return s.UploadFilename
	}
	return defaultUploadFilename
}

// maxTurns returns MaxTurns with a default fallback.
func (s *Strategy) maxTurns() int {
	if s.MaxTurns > 0 {
		return s.MaxTurns
	}
	return 10
}
