package runtimetemplates

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/types"

	// Register test generators (test.Single) so multi-turn factories can build.
	_ "github.com/praetorian-inc/augustus/internal/generators/test"
)

func writeTemplate(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}
}

func contains(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func TestRegisterFromPath_Static(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "static.yaml", `
id: runtimetest.Static
info:
  name: Runtime Static
  severity: low
  detector: judge.Judge
prompts:
  - "first prompt"
  - "second prompt"
`)

	ids, err := RegisterFromPath(dir)
	if err != nil {
		t.Fatalf("RegisterFromPath() error: %v", err)
	}
	if !contains(ids, "runtimetest.Static") {
		t.Fatalf("expected runtimetest.Static in registered ids, got %v", ids)
	}

	probe, err := probes.Create("runtimetest.Static", nil)
	if err != nil {
		t.Fatalf("probes.Create() error: %v", err)
	}
	pm, ok := probe.(types.ProbeMetadata)
	if !ok {
		t.Fatal("static template probe should implement ProbeMetadata")
	}
	prompts := pm.GetPrompts()
	if len(prompts) != 2 || prompts[0] != "first prompt" {
		t.Errorf("GetPrompts() = %v", prompts)
	}
	if pm.GetPrimaryDetector() != "judge.Judge" {
		t.Errorf("GetPrimaryDetector() = %q", pm.GetPrimaryDetector())
	}
}

func TestRegisterFromPath_MultiTurn(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "mt.yaml", `
id: runtimetest.MultiTurn
type: multiturn
info:
  name: Runtime MultiTurn
  severity: high
  detector: judge.Refusal
  goal: "demonstrate escalation"
engine:
  attacker_generator_type: test.Single
  judge_generator_type: test.Single
  max_turns: 4
strategy:
  parser: extended
  attacker_system: "Pursue {{.Goal}}"
  turn: "Turn {{.TurnNum}} of {{.MaxTurns}}: ask about {{.Goal}}"
`)

	ids, err := RegisterFromPath(dir)
	if err != nil {
		t.Fatalf("RegisterFromPath() error: %v", err)
	}
	if !contains(ids, "runtimetest.MultiTurn") {
		t.Fatalf("expected runtimetest.MultiTurn registered, got %v", ids)
	}

	probe, err := probes.Create("runtimetest.MultiTurn", nil)
	if err != nil {
		t.Fatalf("probes.Create() error for multi-turn template: %v", err)
	}
	pm, ok := probe.(types.ProbeMetadata)
	if !ok {
		t.Fatal("multi-turn template probe should implement ProbeMetadata")
	}
	if pm.GetPrimaryDetector() != "judge.Refusal" {
		t.Errorf("GetPrimaryDetector() = %q, want judge.Refusal (from info.detector)", pm.GetPrimaryDetector())
	}
	if probe.Name() != "runtimetest.MultiTurn" {
		t.Errorf("Name() = %q", probe.Name())
	}
}

func TestRegisterFromPath_InvalidTemplateErrors(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "bad.yaml", `
id: runtimetest.Bad
info:
  name: Bad
  severity: high
prompts:
  - "x"
`) // missing detector

	if _, err := RegisterFromPath(dir); err == nil {
		t.Error("RegisterFromPath() should error on invalid template (missing detector)")
	}
}

func TestRegisterFromPath_MissingDirErrors(t *testing.T) {
	if _, err := RegisterFromPath(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("RegisterFromPath() should error for missing directory")
	}
}
