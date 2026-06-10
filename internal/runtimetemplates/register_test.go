package runtimetemplates

import (
	"os"
	"path/filepath"
	"strings"
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

	ids, err := RegisterFromPath(dir, false)
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

	ids, err := RegisterFromPath(dir, false)
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

	if _, err := RegisterFromPath(dir, false); err == nil {
		t.Error("RegisterFromPath() should error on invalid template (missing detector)")
	}
}

func TestRegisterFromPath_MissingDirErrors(t *testing.T) {
	if _, err := RegisterFromPath(filepath.Join(t.TempDir(), "does-not-exist"), false); err == nil {
		t.Error("RegisterFromPath() should error for missing directory")
	}
}

func TestRegisterFromPath_RefusesOverrideWithoutForce(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "first.yaml", `
id: runtimetest.OverrideTarget
info: {name: First, severity: low, detector: judge.Judge}
prompts: ["one"]
`)
	// First registration succeeds (no collision yet).
	if _, err := RegisterFromPath(dir, false); err != nil {
		t.Fatalf("first RegisterFromPath() error: %v", err)
	}

	// Second registration of the same ID must be refused without force.
	dir2 := t.TempDir()
	writeTemplate(t, dir2, "again.yaml", `
id: runtimetest.OverrideTarget
info: {name: Second, severity: low, detector: judge.Judge}
prompts: ["two"]
`)
	_, err := RegisterFromPath(dir2, false)
	if err == nil {
		t.Fatal("RegisterFromPath() should refuse to override an existing probe without force")
	}
	if !strings.Contains(err.Error(), "runtimetest.OverrideTarget") {
		t.Errorf("error should name the colliding ID, got: %v", err)
	}

	// With force, the override succeeds.
	if _, err := RegisterFromPath(dir2, true); err != nil {
		t.Fatalf("RegisterFromPath() with force should override, got: %v", err)
	}
}

func TestRegisterFromPath_AtomicOnRefusedCollision(t *testing.T) {
	// A dir containing one fresh probe and one colliding probe must register
	// NOTHING when the collision is refused (atomic, fail-closed).
	dir := t.TempDir()
	writeTemplate(t, dir, "seed.yaml", `
id: runtimetest.AtomicSeed
info: {name: Seed, severity: low, detector: judge.Judge}
prompts: ["seed"]
`)
	if _, err := RegisterFromPath(dir, false); err != nil {
		t.Fatalf("seed registration: %v", err)
	}

	dir2 := t.TempDir()
	writeTemplate(t, dir2, "fresh.yaml", `
id: runtimetest.AtomicFresh
info: {name: Fresh, severity: low, detector: judge.Judge}
prompts: ["fresh"]
`)
	writeTemplate(t, dir2, "collides.yaml", `
id: runtimetest.AtomicSeed
info: {name: Collides, severity: low, detector: judge.Judge}
prompts: ["collide"]
`)
	if _, err := RegisterFromPath(dir2, false); err == nil {
		t.Fatal("expected refusal due to collision")
	}
	// The non-colliding probe must NOT have been registered.
	if _, exists := probes.Get("runtimetest.AtomicFresh"); exists {
		t.Error("RegisterFromPath() should be atomic: no probe registered when a collision is refused")
	}
}
