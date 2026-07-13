package toolsec

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	// Blank import registers the real toolsec.BOLA detector so the probe test can
	// exercise it end-to-end via the detector registry (S6).
	_ "github.com/praetorian-inc/augustus/internal/detectors/toolsec"
	mcpx "github.com/praetorian-inc/augustus/internal/recon/mcp"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/output"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// realBOLADetect scores an attempt through the REAL toolsec.BOLA detector obtained
// from the detector registry (with the supplied config), so the probe test
// exercises the shipping detector — not a local re-implementation that could
// diverge (Mauro S6).
func realBOLADetect(t *testing.T, cfg registry.Config, a *attempt.Attempt) []float64 {
	t.Helper()
	factory, ok := detectors.Get("toolsec.BOLA")
	if !ok {
		t.Fatal("toolsec.BOLA detector not registered")
	}
	d, err := factory(cfg)
	if err != nil {
		t.Fatalf("construct detector: %v", err)
	}
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	return scores
}

// stubJudgeGen is a generators.Generator test double returning a canned verdict,
// registered so the probe e2e test can wire the REAL detector to a mock judge.
type stubJudgeGen struct{ verdict string }

func (s *stubJudgeGen) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return []attempt.Message{{Content: s.verdict}}, nil
}
func (s *stubJudgeGen) ClearHistory()       {}
func (s *stubJudgeGen) Name() string        { return "stub.JudgeGen" }
func (s *stubJudgeGen) Description() string { return "stub judge gen" }

var stubJudgeVerdict = "{\"verdict\":\"leak\"}"

func init() {
	generators.Register("test.BOLAJudge", func(registry.Config) (generators.Generator, error) {
		return &stubJudgeGen{verdict: stubJudgeVerdict}, nil
	})
}

// judgeDetectorConfig wires the real detector to the registered mock judge.
func judgeDetectorConfig() registry.Config {
	return registry.Config{"judge_generator_type": "test.BOLAJudge"}
}

// TestBOLA_Registered confirms the probe's init() populated the probe registry.
func TestBOLA_Registered(t *testing.T) {
	if _, ok := probes.Get("toolsec.BOLA"); !ok {
		t.Fatal("toolsec.BOLA not registered in the probe registry")
	}
}

func newBOLAProbe(t *testing.T, cfg registry.Config) *BOLA {
	t.Helper()
	p, err := NewBOLA(cfg)
	if err != nil {
		t.Fatalf("NewBOLA: %v", err)
	}
	return p.(*BOLA)
}

func observeIdentifiers(t *testing.T, store *recon.Store, p types.MCPIdentifiers) {
	t.Helper()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal identifiers: %v", err)
	}
	store.Observe(output.Observation{Type: mcpx.ObservationTypeIdentifiers, Target: p.Identity, Data: data})
}

// seedTwoTenants seeds one object per identity (synthetic ids only — no engagement
// identifiers) with the validated args a replay must reuse.
func seedTwoTenants(t *testing.T, store *recon.Store) {
	t.Helper()
	observeIdentifiers(t, store, types.MCPIdentifiers{
		Identity: "tenant-a",
		Objects: []types.MCPObjectRef{{
			Tool: "get_order", Param: "id", ID: "ord_1", Source: "list_orders",
			Args: map[string]any{"id": "ord_1"},
		}},
	})
	observeIdentifiers(t, store, types.MCPIdentifiers{
		Identity: "tenant-b",
		Objects: []types.MCPObjectRef{{
			Tool: "get_order", Param: "id", ID: "ord_2", Source: "list_orders",
			Args: map[string]any{"id": "ord_2"},
		}},
	})
}

// callRecord captures one CallTool invocation.
type callRecord struct {
	name string
	args map[string]any
}

// recordingTarget records every CallTool and delegates the response to reply.
type recordingTarget struct {
	calls []callRecord
	reply func(name string, args map[string]any) types.ToolResult
}

func (m *recordingTarget) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (m *recordingTarget) ClearHistory()       {}
func (m *recordingTarget) Name() string        { return "recording" }
func (m *recordingTarget) Description() string { return "recording" }
func (m *recordingTarget) ListTools(context.Context) ([]map[string]any, error) {
	return nil, nil
}

func (m *recordingTarget) CallTool(_ context.Context, name string, args map[string]any) (types.ToolResult, error) {
	m.calls = append(m.calls, callRecord{name: name, args: args})
	return m.reply(name, args), nil
}

// TestBOLA_IssuesThreeCallsAndStampsControls: for a victim object the probe must
// issue THREE calls — attack, negative control (nonexistent id), positive control
// (attacker's own object) — record the attack output and stamp both controls plus
// the goal. The probe renders NO verdict.
func TestBOLA_IssuesThreeCallsAndStampsControls(t *testing.T) {
	store := recon.NewStore()
	seedTwoTenants(t, store)

	p := newBOLAProbe(t, registry.Config{"attacker_identity_label": "tenant-a"})
	p.SetContext(recon.ProbeContext{Recon: store})

	target := &recordingTarget{reply: func(name string, args map[string]any) types.ToolResult {
		id, _ := args["id"].(string)
		switch id {
		case "ord_2":
			return types.ToolResult{Text: `{"id":"ord_2","item":"gadget","owner":"tenant-b"}`}
		case "ord_1":
			return types.ToolResult{Text: `{"id":"ord_1","item":"widget","owner":"tenant-a"}`}
		default: // nonexistent id
			return types.ToolResult{Text: `{"error":"not found","id":"` + id + `"}`, IsError: true}
		}
	}}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("expected exactly 1 attempt (victim ord_2 only), got %d", len(attempts))
	}
	a := attempts[0]

	// Exactly three calls: attack(ord_2), negative(nonexistent), positive(ord_1).
	if len(target.calls) != 3 {
		t.Fatalf("expected 3 CallTool invocations, got %d: %+v", len(target.calls), target.calls)
	}
	var attackID, negID, posSeen string
	for _, c := range target.calls {
		id, _ := c.args["id"].(string)
		switch id {
		case "ord_2":
			attackID = id
		case "ord_1":
			posSeen = id
		default:
			negID = id
		}
	}
	if attackID != "ord_2" {
		t.Errorf("attack call did not use victim id ord_2: %+v", target.calls)
	}
	if posSeen != "ord_1" {
		t.Errorf("positive control did not use attacker's own id ord_1: %+v", target.calls)
	}
	if negID == "" || negID == "ord_2" {
		t.Errorf("negative control did not use a distinct nonexistent id: %q", negID)
	}

	// Metadata stamps.
	if v, _ := a.GetMetadata("toolsec.tool"); v != "get_order" {
		t.Errorf("toolsec.tool = %v, want get_order", v)
	}
	if v, _ := a.GetMetadata("toolsec.param"); v != "id" {
		t.Errorf("toolsec.param = %v, want id", v)
	}
	if v, _ := a.GetMetadata(attempt.MetadataKeyBOLAID); v != "ord_2" {
		t.Errorf("bola.id = %v, want ord_2", v)
	}
	if v, _ := a.GetMetadata(attempt.MetadataKeyBOLAVictimIdentity); v != "tenant-b" {
		t.Errorf("bola.victim_identity = %v, want tenant-b", v)
	}
	if v, ok := a.GetMetadata(attempt.MetadataKeyBOLANegativeControl); !ok || !strings.Contains(v.(string), "not found") {
		t.Errorf("negative control not stamped: %v", v)
	}
	if v, ok := a.GetMetadata(attempt.MetadataKeyBOLAPositiveControl); !ok || !strings.Contains(v.(string), "ord_1") {
		t.Errorf("positive control not stamped: %v", v)
	}
	if v, ok := a.GetMetadata(attempt.MetadataKeyBOLANonexistentID); !ok || v == "" {
		t.Errorf("nonexistent id not stamped: %v", v)
	}
	goal, ok := a.GetMetadata(attempt.MetadataKeyGoal)
	if !ok {
		t.Fatal("goal not stamped")
	}
	gs := goal.(string)
	for _, want := range []string{"tenant-a", "tenant-b", "ord_2", "get_order"} {
		if !strings.Contains(gs, want) {
			t.Errorf("goal missing %q: %q", want, gs)
		}
	}
	// The attack output is present.
	if len(a.Outputs) != 1 || !strings.Contains(a.Outputs[0], "gadget") {
		t.Errorf("attack output missing/wrong: %v", a.Outputs)
	}
	// The probe renders no verdict — it does not score.
	if len(a.Scores) != 0 {
		t.Errorf("probe must not score; got scores %v", a.Scores)
	}
}

// TestBOLA_OmitsPositiveControlWhenNoOwnObject: when the attacker owns no object
// for the getter, the probe issues only TWO calls (attack + negative) and does not
// stamp a positive control.
func TestBOLA_OmitsPositiveControlWhenNoOwnObject(t *testing.T) {
	store := recon.NewStore()
	// Attacker owns an object for a DIFFERENT getter; nothing for get_ticket.
	observeIdentifiers(t, store, types.MCPIdentifiers{
		Identity: "tenant-a",
		Objects: []types.MCPObjectRef{{
			Tool: "get_order", Param: "id", ID: "ord_1", Args: map[string]any{"id": "ord_1"},
		}},
	})
	observeIdentifiers(t, store, types.MCPIdentifiers{
		Identity: "tenant-b",
		Objects: []types.MCPObjectRef{{
			Tool: "get_ticket", Param: "id", ID: "tkt_2", Args: map[string]any{"id": "tkt_2"},
		}},
	})

	p := newBOLAProbe(t, registry.Config{"attacker_identity_label": "tenant-a"})
	p.SetContext(recon.ProbeContext{Recon: store})
	target := &recordingTarget{reply: func(_ string, args map[string]any) types.ToolResult {
		id, _ := args["id"].(string)
		if id == "tkt_2" {
			return types.ToolResult{Text: `{"id":"tkt_2","kind":"ticket"}`}
		}
		return types.ToolResult{Text: `{"error":"not found"}`, IsError: true}
	}}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("expected 1 attempt, got %d", len(attempts))
	}
	// Only get_ticket is called (attack + negative); get_order is never called since
	// the attacker owns no get_ticket object.
	if len(target.calls) != 2 {
		t.Fatalf("expected 2 calls (attack+negative, no positive), got %d: %+v", len(target.calls), target.calls)
	}
	if _, ok := attempts[0].GetMetadata(attempt.MetadataKeyBOLAPositiveControl); ok {
		t.Errorf("positive control must be omitted when the attacker owns no object for the getter")
	}
}

// TestBOLA_EndToEndLeak: full probe -> REAL detector (mock judge). The leaky
// getter serves the victim object; the negative control differs, so stage-1 does
// not cull and the judge (mock: leak) scores 1.0.
func TestBOLA_EndToEndLeak(t *testing.T) {
	store := recon.NewStore()
	seedTwoTenants(t, store)

	p := newBOLAProbe(t, registry.Config{"attacker_identity_label": "tenant-a"})
	p.SetContext(recon.ProbeContext{Recon: store})
	target := &recordingTarget{reply: func(_ string, args map[string]any) types.ToolResult {
		id, _ := args["id"].(string)
		switch id {
		case "ord_2":
			return types.ToolResult{Text: `{"id":"ord_2","item":"gadget","owner":"tenant-b"}`}
		case "ord_1":
			return types.ToolResult{Text: `{"id":"ord_1","item":"widget","owner":"tenant-a"}`}
		default:
			return types.ToolResult{Text: `{"error":"not found","id":"` + id + `"}`, IsError: true}
		}
	}}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("expected 1 attempt, got %d", len(attempts))
	}
	if scores := realBOLADetect(t, judgeDetectorConfig(), attempts[0]); len(scores) != 1 || scores[0] != 1.0 {
		t.Errorf("leak should score 1.0 via the real detector + mock judge, got %v", scores)
	}
}

// TestBOLA_EndToEndScopedNoLeak: a properly scoped getter returns the SAME
// not-found for the victim id as for the nonexistent id; the real detector's
// stage-1 prune scores 0.0 with NO judge call.
func TestBOLA_EndToEndScopedNoLeak(t *testing.T) {
	store := recon.NewStore()
	seedTwoTenants(t, store)

	p := newBOLAProbe(t, registry.Config{"attacker_identity_label": "tenant-a"})
	p.SetContext(recon.ProbeContext{Recon: store})
	target := &recordingTarget{reply: func(_ string, args map[string]any) types.ToolResult {
		id, _ := args["id"].(string)
		if id == "ord_1" { // attacker's own object is served (positive control)
			return types.ToolResult{Text: `{"id":"ord_1","item":"widget","owner":"tenant-a"}`}
		}
		// The victim id and the nonexistent id both get an identical (masked) denial.
		return types.ToolResult{Text: `{"error":"access denied","id":"` + id + `"}`, IsError: true}
	}}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("expected 1 attempt, got %d", len(attempts))
	}
	// Even with a leak-happy judge configured, stage-1 must prune this to 0.0.
	if scores := realBOLADetect(t, judgeDetectorConfig(), attempts[0]); len(scores) != 1 || scores[0] != 0.0 {
		t.Errorf("scoped getter (target==nonexistent) must prune to 0.0, got %v", scores)
	}
}

// TestBOLA_EndToEndNumericIDs (S6): full probe -> REAL detector with NUMERIC ids.
// The leaky getter serves the victim's numeric-id object; the real detector +
// mock judge scores the leak 1.0.
func TestBOLA_EndToEndNumericIDs(t *testing.T) {
	store := recon.NewStore()
	observeIdentifiers(t, store, types.MCPIdentifiers{
		Identity: "tenant-a",
		Objects:  []types.MCPObjectRef{{Tool: "get_order", Param: "id", ID: "1", Args: map[string]any{"id": "1"}}},
	})
	observeIdentifiers(t, store, types.MCPIdentifiers{
		Identity: "tenant-b",
		Objects:  []types.MCPObjectRef{{Tool: "get_order", Param: "id", ID: "2", Args: map[string]any{"id": "2"}}},
	})

	p := newBOLAProbe(t, registry.Config{"attacker_identity_label": "tenant-a"})
	p.SetContext(recon.ProbeContext{Recon: store})
	target := &recordingTarget{reply: func(_ string, args map[string]any) types.ToolResult {
		id, _ := args["id"].(string)
		switch id {
		case "2":
			return types.ToolResult{Text: `{"id":"2","item":"gadget","owner":"tenant-b"}`}
		case "1":
			return types.ToolResult{Text: `{"id":"1","item":"widget","owner":"tenant-a"}`}
		default:
			return types.ToolResult{Text: `{"error":"not found","id":"` + id + `"}`, IsError: true}
		}
	}}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("expected 1 attempt (victim id 2 only), got %d", len(attempts))
	}
	// The nonexistent id for a numeric id must itself be numeric (format-preserving).
	nx, _ := attempts[0].GetMetadata(attempt.MetadataKeyBOLANonexistentID)
	if s, _ := nx.(string); !numericIDRE.MatchString(s) {
		t.Errorf("nonexistent id for a numeric id must be numeric, got %q", nx)
	}
	if scores := realBOLADetect(t, judgeDetectorConfig(), attempts[0]); len(scores) != 1 || scores[0] != 1.0 {
		t.Errorf("numeric-id leak should score 1.0, got %v", scores)
	}
}

// TestBOLA_TransportErrorSetsError: an attack transport error sets the attempt
// error and stamps no controls.
func TestBOLA_TransportErrorSetsError(t *testing.T) {
	store := recon.NewStore()
	seedTwoTenants(t, store)
	p := newBOLAProbe(t, registry.Config{"attacker_identity_label": "tenant-a"})
	p.SetContext(recon.ProbeContext{Recon: store})
	target := &erroringTarget{}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("expected 1 attempt, got %d", len(attempts))
	}
	if attempts[0].Error == "" {
		t.Errorf("attack transport error must set the attempt error")
	}
	if scores := realBOLADetect(t, registry.Config{}, attempts[0]); len(scores) != 1 || scores[0] != 0.0 {
		t.Errorf("errored attempt must score 0.0, got %v", scores)
	}
}

// erroringTarget fails every CallTool.
type erroringTarget struct{}

func (erroringTarget) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (erroringTarget) ClearHistory()       {}
func (erroringTarget) Name() string        { return "erroring" }
func (erroringTarget) Description() string { return "erroring" }
func (erroringTarget) ListTools(context.Context) ([]map[string]any, error) {
	return nil, nil
}

func (erroringTarget) CallTool(context.Context, string, map[string]any) (types.ToolResult, error) {
	return types.ToolResult{}, context.DeadlineExceeded
}

// TestBOLA_UnknownAttackerLabel (S5): when attacker_identity_label matches no
// discovered identity, the probe must skip entirely (no attempts) rather than
// replay every identity's objects against its own session.
func TestBOLA_UnknownAttackerLabel(t *testing.T) {
	store := recon.NewStore()
	seedTwoTenants(t, store)

	p := newBOLAProbe(t, registry.Config{"attacker_identity_label": "primary"})
	p.SetContext(recon.ProbeContext{Recon: store})
	target := &recordingTarget{reply: func(string, map[string]any) types.ToolResult {
		return types.ToolResult{Text: "would leak if the probe ran"}
	}}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if attempts != nil {
		t.Errorf("expected nil attempts for unknown attacker label, got %d", len(attempts))
	}
	if len(target.calls) != 0 {
		t.Errorf("probe must not call the target when the attacker label is unknown")
	}
}

// TestBOLA_NoObjectsForVictim (S6): a victim identity with no harvested objects
// yields no attempts (the no-objects path), and no panic.
func TestBOLA_NoObjectsForVictim(t *testing.T) {
	store := recon.NewStore()
	observeIdentifiers(t, store, types.MCPIdentifiers{
		Identity: "tenant-a",
		Objects:  []types.MCPObjectRef{{Tool: "get_order", Param: "id", ID: "ord_1"}},
	})
	observeIdentifiers(t, store, types.MCPIdentifiers{Identity: "tenant-b", Objects: nil})

	p := newBOLAProbe(t, registry.Config{"attacker_identity_label": "tenant-a"})
	p.SetContext(recon.ProbeContext{Recon: store})
	target := &recordingTarget{reply: func(string, map[string]any) types.ToolResult {
		return types.ToolResult{Text: "denied", IsError: true}
	}}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if attempts != nil {
		t.Errorf("expected nil attempts when the victim has no objects, got %d", len(attempts))
	}
}

// TestBOLA_NoIdentifiers: with no mcp.identifiers observations (harvest failure),
// the probe produces no attempts and no error.
func TestBOLA_NoIdentifiers(t *testing.T) {
	p := newBOLAProbe(t, registry.Config{})
	p.SetContext(recon.ProbeContext{Recon: recon.NewStore()})
	target := &recordingTarget{reply: func(string, map[string]any) types.ToolResult {
		return types.ToolResult{Text: "x"}
	}}
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if attempts != nil {
		t.Errorf("expected nil attempts without identifiers, got %d", len(attempts))
	}
}

// TestBOLA_SkipsNonToolInvoker: a plain generator yields no attempts.
func TestBOLA_SkipsNonToolInvoker(t *testing.T) {
	store := recon.NewStore()
	seedTwoTenants(t, store)
	p := newBOLAProbe(t, registry.Config{"attacker_identity_label": "tenant-a"})
	p.SetContext(recon.ProbeContext{Recon: store})

	attempts, err := p.Probe(context.Background(), plainGen{})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if attempts != nil {
		t.Errorf("expected nil attempts for non-ToolInvoker, got %d", len(attempts))
	}
}

// TestBOLA_OwnIDSuppressionScopedToGetter: own-id suppression must be scoped to
// the getter. The attacker owns get_order id "1"; the victim owns get_ticket id
// "1" — a DIFFERENT object class. The victim's object must still be attacked.
func TestBOLA_OwnIDSuppressionScopedToGetter(t *testing.T) {
	store := recon.NewStore()
	observeIdentifiers(t, store, types.MCPIdentifiers{
		Identity: "tenant-a",
		Objects:  []types.MCPObjectRef{{Tool: "get_order", Param: "id", ID: "1", Args: map[string]any{"id": "1"}}},
	})
	observeIdentifiers(t, store, types.MCPIdentifiers{
		Identity: "tenant-b",
		Objects:  []types.MCPObjectRef{{Tool: "get_ticket", Param: "id", ID: "1", Args: map[string]any{"id": "1"}}},
	})

	p := newBOLAProbe(t, registry.Config{"attacker_identity_label": "tenant-a"})
	p.SetContext(recon.ProbeContext{Recon: store})
	target := &recordingTarget{reply: func(name string, args map[string]any) types.ToolResult {
		if name == "get_ticket" && args["id"] == "1" {
			return types.ToolResult{Text: `{"id":"1","kind":"ticket","owner":"tenant-b"}`}
		}
		return types.ToolResult{Text: `{"error":"not found"}`, IsError: true}
	}}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("expected 1 attempt on the victim's get_ticket(1) (id collision is cross-getter), got %d", len(attempts))
	}
	if v, _ := attempts[0].GetMetadata("toolsec.tool"); v != "get_ticket" {
		t.Errorf("attacked tool = %v, want get_ticket", v)
	}
}

// TestBOLA_ReplaysWithRequiredArgs: the replay must reuse the full validated arg
// map (MCPObjectRef.Args), not just the id, so getters with another required param
// aren't rejected (false negative). Both the attack and the negative control must
// carry the extra required arg.
func TestBOLA_ReplaysWithRequiredArgs(t *testing.T) {
	store := recon.NewStore()
	observeIdentifiers(t, store, types.MCPIdentifiers{
		Identity: "tenant-a",
		Objects:  []types.MCPObjectRef{{Tool: "get_order", Param: "id", ID: "ord_1", Args: map[string]any{"id": "ord_1", "format": "full"}}},
	})
	observeIdentifiers(t, store, types.MCPIdentifiers{
		Identity: "tenant-b",
		Objects:  []types.MCPObjectRef{{Tool: "get_order", Param: "id", ID: "ord_2", Args: map[string]any{"id": "ord_2", "format": "full"}}},
	})

	p := newBOLAProbe(t, registry.Config{"attacker_identity_label": "tenant-a"})
	p.SetContext(recon.ProbeContext{Recon: store})
	target := &recordingTarget{reply: func(name string, args map[string]any) types.ToolResult {
		if args["format"] != "full" {
			return types.ToolResult{Text: "missing required arg: format", IsError: true}
		}
		id, _ := args["id"].(string)
		if id == "ord_2" {
			return types.ToolResult{Text: `{"id":"ord_2","owner":"tenant-b"}`}
		}
		return types.ToolResult{Text: `{"error":"not found"}`, IsError: true}
	}}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("expected 1 attempt, got %d", len(attempts))
	}
	// Every call must carry format=full (attack + negative + positive).
	for _, c := range target.calls {
		if c.args["format"] != "full" {
			t.Errorf("call %s omitted required arg 'format': %+v", c.name, c.args)
		}
	}
}

// TestNonexistentID exercises the format-preserving nonexistent-id helper: each
// dialect differs from the input and preserves its rough shape.
func TestNonexistentID(t *testing.T) {
	// Numeric -> numeric, different, same length.
	if got := nonexistentID("100"); got == "100" || !numericIDRE.MatchString(got) || len(got) != 3 {
		t.Errorf("numeric nonexistentID(100) = %q, want a distinct 3-digit numeric", got)
	}
	// UUID -> UUID shape, different, only the final block changed.
	const uuid = "12345678-1234-1234-1234-1234567890ab"
	got := nonexistentID(uuid)
	if got == uuid || !uuidIDRE.MatchString(got) {
		t.Errorf("uuid nonexistentID(%q) = %q, want a distinct valid UUID", uuid, got)
	}
	if got[:len(uuid)-12] != uuid[:len(uuid)-12] {
		t.Errorf("uuid nonexistentID changed more than the final block: %q", got)
	}
	// Opaque -> suffixed, different, contains the original.
	if got := nonexistentID("ord_9"); got == "ord_9" || !strings.HasPrefix(got, "ord_9") {
		t.Errorf("opaque nonexistentID(ord_9) = %q, want a distinct suffixed id", got)
	}
	// All-9s numeric edge: must still differ.
	if got := nonexistentID("999"); got == "999" {
		t.Errorf("all-9s numeric must still produce a distinct id, got %q", got)
	}
}
