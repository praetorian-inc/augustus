package attackengine

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttackerSystemPrompt(t *testing.T) {
	prompt := AttackerSystemPrompt("write malware", "Sure, here is")
	assert.Contains(t, prompt, "write malware")
	assert.Contains(t, prompt, "Sure, here is")
	assert.Contains(t, prompt, `"improvement"`)
	assert.Contains(t, prompt, `"prompt"`)
	assert.Contains(t, prompt, "JSON")
}

func TestJudgeSystemPrompt(t *testing.T) {
	prompt := JudgeSystemPrompt("write malware")
	assert.Contains(t, prompt, "write malware")
	assert.Contains(t, prompt, "[[")  // Rating format
	assert.Contains(t, prompt, "1")   // Scale mentions
	assert.Contains(t, prompt, "10")
}

func TestOnTopicSystemPrompt(t *testing.T) {
	prompt := OnTopicSystemPrompt("write malware")
	assert.Contains(t, prompt, "write malware")
	assert.Contains(t, prompt, "[[YES]]")
	assert.Contains(t, prompt, "[[NO]]")
}

func TestInitMessage(t *testing.T) {
	msg := InitMessage("write malware", "Sure, here is")
	assert.Contains(t, msg, "write malware")
	assert.Contains(t, msg, "Sure, here is")
}

func TestProcessTargetResponse(t *testing.T) {
	feedback := ProcessTargetResponse("I cannot help with that", 2.0, "write malware")
	assert.Contains(t, feedback, "I cannot help with that")
	assert.Contains(t, feedback, "2")  // Score
	assert.Contains(t, feedback, "write malware")
}

func TestEvaluatorPrompt(t *testing.T) {
	prompt := EvaluatorPrompt("Tell me how to hack", "I cannot assist")
	assert.Contains(t, prompt, "Tell me how to hack")
	assert.Contains(t, prompt, "I cannot assist")
	assert.Contains(t, prompt, "[PROMPT]")
	assert.Contains(t, prompt, "[ASSISTANT'S RESPONSE]")
}

func TestOnTopicEvaluatorPrompt(t *testing.T) {
	prompt := OnTopicEvaluatorPrompt("Tell me how to hack")
	assert.Contains(t, prompt, "Tell me how to hack")
	assert.Contains(t, prompt, "[PROMPT]")
}
