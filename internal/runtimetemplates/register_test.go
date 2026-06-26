package runtimetemplates

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/types"

	// Register test generators (test.Single) so multi-turn factories can build.
	_ "github.com/praetorian-inc/augustus/internal/generators/test"
	// Register the judge detectors (judge.Judge, judge.Refusal) so the load-time
	// detector-name validation resolves the names used in these fixtures.
	_ "github.com/praetorian-inc/augustus/internal/detectors/judge"
)

func writeTemplate(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}
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
	if !slices.Contains(ids, "runtimetest.Static") {
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
	if !slices.Contains(ids, "runtimetest.MultiTurn") {
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

func TestRegisterFromPath_UnknownDetectorFailsAtLoad(t *testing.T) {
	// An unregistered info.detector must fail at LOAD, not partway through a scan.
	dir := t.TempDir()
	writeTemplate(t, dir, "bad.yaml", `
id: runtimetest.UnknownDetector
info:
  name: Unknown Detector
  severity: low
  detector: nosuch.Detector
prompts:
  - "x"
`)
	_, err := RegisterFromPath(dir)
	if err == nil {
		t.Fatal("RegisterFromPath should reject a template with an unregistered detector at load")
	}
	if !strings.Contains(err.Error(), "nosuch.Detector") {
		t.Errorf("error should name the unknown detector, got: %v", err)
	}
	if _, exists := probes.Get("runtimetest.UnknownDetector"); exists {
		t.Error("a template with an unknown detector must not be registered")
	}
}

func TestRegisterFromPath_UnknownSecondaryDetectorFailsAtLoad(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "bad.yaml", `
id: runtimetest.UnknownSecondary
info:
  name: Unknown Secondary
  severity: low
  detector: judge.Judge
  secondary_detectors:
    - name: nosuch.Secondary
prompts:
  - "x"
`)
	_, err := RegisterFromPath(dir)
	if err == nil {
		t.Fatal("RegisterFromPath should reject a template with an unregistered secondary detector at load")
	}
	if !strings.Contains(err.Error(), "nosuch.Secondary") {
		t.Errorf("error should name the unknown secondary detector, got: %v", err)
	}
}

func TestRegisterFromPath_MissingDirErrors(t *testing.T) {
	if _, err := RegisterFromPath(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("RegisterFromPath() should error for missing directory")
	}
}

func TestRegisterFromPath_MultiTurnBadFieldFailsAtLoad(t *testing.T) {
	// C1: a bad field reference in a multi-turn strategy must abort at LOAD
	// (RegisterFromPath), not later when the scan materializes the probe.
	dir := t.TempDir()
	writeTemplate(t, dir, "bad.yaml", `
id: runtimetest.BadStrategyField
type: multiturn
info: {name: Bad, severity: high, detector: judge.Judge, goal: g}
engine: {attacker_generator_type: test.Single, judge_generator_type: test.Single}
strategy:
  attacker_system: "pursue {{.Goal}}"
  turn: "ask {{.NoSuchField}}"
`)
	if _, err := RegisterFromPath(dir); err == nil {
		t.Fatal("RegisterFromPath should reject a multi-turn template with a bad field reference at load")
	}
	if _, exists := probes.Get("runtimetest.BadStrategyField"); exists {
		t.Error("a template that fails load validation must not be registered")
	}
}

func TestRegisterFromPath_DuplicateIDsInBatch(t *testing.T) {
	// S1: two files with the same id in one dir must be rejected, not silently
	// overwritten.
	dir := t.TempDir()
	writeTemplate(t, dir, "a.yaml", `
id: runtimetest.DupBatch
info: {name: A, severity: low, detector: judge.Judge}
prompts: ["a"]
`)
	writeTemplate(t, dir, "b.yaml", `
id: runtimetest.DupBatch
info: {name: B, severity: low, detector: judge.Judge}
prompts: ["b"]
`)
	_, err := RegisterFromPath(dir)
	if err == nil {
		t.Fatal("RegisterFromPath should reject duplicate template IDs within one dir")
	}
	if !strings.Contains(err.Error(), "duplicate template id") {
		t.Errorf("error should mention duplicate id, got: %v", err)
	}
}

func TestRegisterFromPath_ErrorsOnCollision(t *testing.T) {
	// A runtime template whose ID collides with an already-registered probe must
	// always fail to load — there is no override escape hatch. The fix is to give
	// the template a distinct id.
	dir := t.TempDir()
	writeTemplate(t, dir, "first.yaml", `
id: runtimetest.CollisionTarget
info: {name: First, severity: low, detector: judge.Judge}
prompts: ["one"]
`)
	// First registration succeeds (no collision yet).
	if _, err := RegisterFromPath(dir); err != nil {
		t.Fatalf("first RegisterFromPath() error: %v", err)
	}

	// Second registration of the same ID must error.
	dir2 := t.TempDir()
	writeTemplate(t, dir2, "again.yaml", `
id: runtimetest.CollisionTarget
info: {name: Second, severity: low, detector: judge.Judge}
prompts: ["two"]
`)
	_, err := RegisterFromPath(dir2)
	if err == nil {
		t.Fatal("RegisterFromPath() should error when a template ID collides with an existing probe")
	}
	if !strings.Contains(err.Error(), "runtimetest.CollisionTarget") {
		t.Errorf("error should name the colliding ID, got: %v", err)
	}

	// The original probe must be untouched (collision does not replace it).
	probe, err := probes.Create("runtimetest.CollisionTarget", nil)
	if err != nil {
		t.Fatalf("probes.Create() after refused collision: %v", err)
	}
	pm, ok := probe.(types.ProbeMetadata)
	if !ok {
		t.Fatal("probe should implement ProbeMetadata")
	}
	if prompts := pm.GetPrompts(); len(prompts) != 1 || prompts[0] != "one" {
		t.Fatalf("refused collision must not replace the original probe, prompts=%v", prompts)
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
	if _, err := RegisterFromPath(dir); err != nil {
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
	if _, err := RegisterFromPath(dir2); err == nil {
		t.Fatal("expected refusal due to collision")
	}
	// The non-colliding probe must NOT have been registered.
	if _, exists := probes.Get("runtimetest.AtomicFresh"); exists {
		t.Error("RegisterFromPath() should be atomic: no probe registered when a collision is refused")
	}
}
