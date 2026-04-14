package injection

import (
	"testing"
)

func TestNewShellInjection_Compiles(t *testing.T) {
	_, err := NewShellInjection(nil)
	if err == nil {
		t.Error("expected error with nil config (no API key)")
	}
}

func TestNewSQLInjection_Compiles(t *testing.T) {
	_, err := NewSQLInjection(nil)
	if err == nil {
		t.Error("expected error with nil config (no API key)")
	}
}

func TestSQLScoreClamp_AllowsDBErrors(t *testing.T) {
	if !reDBEngineError.MatchString("Query failed: (psycopg2.errors.SyntaxError) syntax error at or near") {
		t.Error("should match psycopg2 error")
	}
	if !reDBEngineError.MatchString("query failed with SQLSTATE 42601") {
		t.Error("should match SQLSTATE")
	}
}

func TestSQLScoreClamp_BlocksLLMParaphrase(t *testing.T) {
	if reDBEngineError.MatchString("The search returned no results for that query.") {
		t.Error("should not match normal response")
	}
	if reDBEngineError.MatchString("I can't execute that SQL command.") {
		t.Error("should not match LLM refusal")
	}
}

func TestShellExecProof_Matches(t *testing.T) {
	if !reShellExecProof.MatchString("uid=0(root) gid=0(root) groups=0(root)") {
		t.Error("should match id output")
	}
	if !reShellExecProof.MatchString("/bin/sh: 1: syntax error: unterminated") {
		t.Error("should match shell syntax error")
	}
}
