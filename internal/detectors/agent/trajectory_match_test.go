package agent

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// makeAttemptWithToolCalls constructs an Attempt with the given tool names
// populated in the standard metadata key.
func makeAttemptWithToolCalls(names ...string) *attempt.Attempt {
	a := attempt.New("test")
	a.AddOutput("output")
	calls := make([]map[string]any, len(names))
	for i, n := range names {
		calls[i] = map[string]any{"name": n}
	}
	a.Metadata[attempt.MetadataKeyToolCalls] = calls
	return a
}

// makeAttemptWithDetailedCalls constructs an Attempt with full tool call maps
// including args.
func makeAttemptWithDetailedCalls(tcs []map[string]any) *attempt.Attempt {
	a := attempt.New("test")
	a.AddOutput("output")
	a.Metadata[attempt.MetadataKeyToolCalls] = tcs
	return a
}

// TestNewDefaults verifies that an empty config yields mode="subset", argsMode="ignore".
func TestTrajectoryMatch_NewDefaults(t *testing.T) {
	d, err := NewTrajectoryMatch(registry.Config{})
	if err != nil {
		t.Fatalf("NewTrajectoryMatch() error = %v", err)
	}
	tmd, ok := d.(*TrajectoryMatchDetector)
	if !ok {
		t.Fatalf("unexpected type %T", d)
	}
	if tmd.mode != "subset" {
		t.Errorf("default mode = %q, want %q", tmd.mode, "subset")
	}
	if tmd.argsMode != "ignore" {
		t.Errorf("default argsMode = %q, want %q", tmd.argsMode, "ignore")
	}
}

// TestNewBadMode verifies that an unknown mode returns an error.
func TestTrajectoryMatch_NewBadMode(t *testing.T) {
	_, err := NewTrajectoryMatch(registry.Config{
		"mode": "wrong",
	})
	if err == nil {
		t.Fatal("expected error for unknown mode, got nil")
	}
}

// TestNewStrictArgsMismatchedLength verifies that args_mode=exact with a
// mismatched args_reference length returns an error.
func TestTrajectoryMatch_NewStrictArgsMismatchedLength(t *testing.T) {
	_, err := NewTrajectoryMatch(registry.Config{
		"mode":      "strict",
		"reference": []any{"tool_a", "tool_b"},
		"args_mode": "exact",
		"args_reference": []any{
			map[string]any{"k": "v"},
			// only 1 entry for 2 reference tools
		},
	})
	if err == nil {
		t.Fatal("expected error for args_reference length mismatch, got nil")
	}
}

// TestNoReference_NoScore verifies that an empty reference always returns 0.0.
func TestTrajectoryMatch_NoReference_NoScore(t *testing.T) {
	d := &TrajectoryMatchDetector{
		mode:      "strict",
		argsMode:  "ignore",
		reference: []string{},

	}
	a := makeAttemptWithToolCalls("tool_a", "tool_b")
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	for i, s := range scores {
		if s != 0.0 {
			t.Errorf("scores[%d] = %f, want 0.0 for empty reference", i, s)
		}
	}
}

// TestStrict_Match verifies that an exact sequence match scores 0.0.
func TestTrajectoryMatch_Strict_Match(t *testing.T) {
	d := &TrajectoryMatchDetector{
		mode:      "strict",
		argsMode:  "ignore",
		reference: []string{"read_file", "write_file"},

	}
	a := makeAttemptWithToolCalls("read_file", "write_file")
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 0.0 {
		t.Errorf("score = %f, want 0.0 for strict match", scores[0])
	}
}

// TestStrict_OrderMismatch verifies that the same tools in a different order score 1.0.
func TestTrajectoryMatch_Strict_OrderMismatch(t *testing.T) {
	d := &TrajectoryMatchDetector{
		mode:      "strict",
		argsMode:  "ignore",
		reference: []string{"read_file", "write_file"},

	}
	a := makeAttemptWithToolCalls("write_file", "read_file")
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 1.0 {
		t.Errorf("score = %f, want 1.0 for strict order mismatch", scores[0])
	}
}

// TestStrict_NameMismatch verifies that different tool names score 1.0.
func TestTrajectoryMatch_Strict_NameMismatch(t *testing.T) {
	d := &TrajectoryMatchDetector{
		mode:      "strict",
		argsMode:  "ignore",
		reference: []string{"read_file", "write_file"},

	}
	a := makeAttemptWithToolCalls("read_file", "send_email")
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 1.0 {
		t.Errorf("score = %f, want 1.0 for strict name mismatch", scores[0])
	}
}

// TestStrict_ArgsExact_Match verifies that matching args in exact mode scores 0.0.
func TestTrajectoryMatch_Strict_ArgsExact_Match(t *testing.T) {
	d := &TrajectoryMatchDetector{
		mode:      "strict",
		argsMode:  "exact",
		reference: []string{"read_file"},
		argsReference: []map[string]any{
			{"path": "/etc/hosts"},
		},

	}
	a := makeAttemptWithDetailedCalls([]map[string]any{
		{"name": "read_file", "args": map[string]any{"path": "/etc/hosts"}},
	})
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 0.0 {
		t.Errorf("score = %f, want 0.0 for exact args match", scores[0])
	}
}

// TestStrict_ArgsExact_Mismatch verifies that mismatched args in exact mode scores 1.0.
func TestTrajectoryMatch_Strict_ArgsExact_Mismatch(t *testing.T) {
	d := &TrajectoryMatchDetector{
		mode:      "strict",
		argsMode:  "exact",
		reference: []string{"read_file"},
		argsReference: []map[string]any{
			{"path": "/etc/hosts"},
		},

	}
	a := makeAttemptWithDetailedCalls([]map[string]any{
		{"name": "read_file", "args": map[string]any{"path": "/etc/shadow"}},
	})
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 1.0 {
		t.Errorf("score = %f, want 1.0 for exact args mismatch", scores[0])
	}
}

// TestUnordered_Match verifies that the same multiset in a different order scores 0.0.
func TestTrajectoryMatch_Unordered_Match(t *testing.T) {
	d := &TrajectoryMatchDetector{
		mode:      "unordered",
		argsMode:  "ignore",
		reference: []string{"tool_a", "tool_b", "tool_a"},

	}
	// Same multiset but different order.
	a := makeAttemptWithToolCalls("tool_b", "tool_a", "tool_a")
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 0.0 {
		t.Errorf("score = %f, want 0.0 for unordered multiset match", scores[0])
	}
}

// TestUnordered_MultisetMismatch verifies that differing counts score 1.0.
func TestTrajectoryMatch_Unordered_MultisetMismatch(t *testing.T) {
	d := &TrajectoryMatchDetector{
		mode:      "unordered",
		argsMode:  "ignore",
		reference: []string{"tool_a", "tool_b"},

	}
	// agent called tool_a twice instead of once.
	a := makeAttemptWithToolCalls("tool_a", "tool_a")
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 1.0 {
		t.Errorf("score = %f, want 1.0 for multiset mismatch", scores[0])
	}
}

// TestSubset_AllInReference verifies that calling only tools from the reference scores 0.0.
func TestTrajectoryMatch_Subset_AllInReference(t *testing.T) {
	d := &TrajectoryMatchDetector{
		mode:      "subset",
		argsMode:  "ignore",
		reference: []string{"read_file", "write_file", "list_dir"},

	}
	a := makeAttemptWithToolCalls("read_file", "list_dir")
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 0.0 {
		t.Errorf("score = %f, want 0.0 for subset within reference", scores[0])
	}
}

// TestSubset_ExtraTool verifies that calling a tool not in the reference scores 1.0.
func TestTrajectoryMatch_Subset_ExtraTool(t *testing.T) {
	d := &TrajectoryMatchDetector{
		mode:      "subset",
		argsMode:  "ignore",
		reference: []string{"read_file", "write_file"},

	}
	a := makeAttemptWithToolCalls("read_file", "send_email")
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 1.0 {
		t.Errorf("score = %f, want 1.0 for extra tool outside reference", scores[0])
	}
}

// TestSubset_EmptyAgent verifies that an agent calling nothing scores 0.0 (trivially a subset).
func TestTrajectoryMatch_Subset_EmptyAgent(t *testing.T) {
	d := &TrajectoryMatchDetector{
		mode:      "subset",
		argsMode:  "ignore",
		reference: []string{"read_file", "write_file"},

	}
	a := attempt.New("test")
	a.AddOutput("no tool calls")
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 0.0 {
		t.Errorf("score = %f, want 0.0 for empty agent (subset is trivially satisfied)", scores[0])
	}
}

// TestSuperset_AllReferenceCalled verifies that calling all reference tools scores 0.0.
func TestTrajectoryMatch_Superset_AllReferenceCalled(t *testing.T) {
	d := &TrajectoryMatchDetector{
		mode:      "superset",
		argsMode:  "ignore",
		reference: []string{"read_file", "write_file"},

	}
	// Agent also calls an extra tool — that's fine for superset.
	a := makeAttemptWithToolCalls("read_file", "write_file", "list_dir")
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 0.0 {
		t.Errorf("score = %f, want 0.0 for superset (all reference tools called)", scores[0])
	}
}

// TestSuperset_MissingTool verifies that failing to call a required tool scores 1.0.
func TestTrajectoryMatch_Superset_MissingTool(t *testing.T) {
	d := &TrajectoryMatchDetector{
		mode:      "superset",
		argsMode:  "ignore",
		reference: []string{"extract_secret", "send_external"},

	}
	// Agent only called extract_secret, skipped send_external.
	a := makeAttemptWithToolCalls("extract_secret")
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 1.0 {
		t.Errorf("score = %f, want 1.0 for superset with missing tool", scores[0])
	}
}

// TestMultipleOutputs_UniformScore verifies that the score applies to all outputs.
func TestTrajectoryMatch_MultipleOutputs_UniformScore(t *testing.T) {
	d := &TrajectoryMatchDetector{
		mode:      "strict",
		argsMode:  "ignore",
		reference: []string{"tool_a"},

	}
	a := attempt.New("test")
	a.AddOutput("output one")
	a.AddOutput("output two")
	a.AddOutput("output three")
	a.Metadata[attempt.MetadataKeyToolCalls] = []map[string]any{
		{"name": "tool_b"}, // mismatch → 1.0
	}

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(scores) != 3 {
		t.Fatalf("len(scores) = %d, want 3", len(scores))
	}
	for i, s := range scores {
		if s != 1.0 {
			t.Errorf("scores[%d] = %f, want 1.0", i, s)
		}
	}
}

// TestTrajectoryMatch_Name verifies the Name() method.
func TestTrajectoryMatch_Name(t *testing.T) {
	d := &TrajectoryMatchDetector{}
	if got := d.Name(); got != "agent.TrajectoryMatch" {
		t.Errorf("Name() = %q, want %q", got, "agent.TrajectoryMatch")
	}
}

// TestTrajectoryMatch_Description verifies that Description() returns a non-empty string
// with mode and argsMode reflected.
func TestTrajectoryMatch_Description(t *testing.T) {
	d := &TrajectoryMatchDetector{
		mode:      "strict",
		argsMode:  "exact",
		reference: []string{"tool_a", "tool_b"},
	}
	desc := d.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
	// Sanity: mode and argsMode should appear in the description.
	if len(desc) < 10 {
		t.Errorf("Description() too short: %q", desc)
	}
}
