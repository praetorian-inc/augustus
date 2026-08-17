package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/internal/toolsig"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/output"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// tenantServer models one authenticated session against a two-tenant MCP server.
// list_orders returns only the caller's own object ids; get_order returns the
// full object only to its owner and IsError otherwise. This is the ground truth
// the identifiers module must round-trip validate against.
type tenantServer struct {
	owned map[string]string // id -> object body owned by this identity
}

func newTenantServer(owned map[string]string) *tenantServer {
	return &tenantServer{owned: owned}
}

func (s *tenantServer) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (s *tenantServer) ClearHistory()       {}
func (s *tenantServer) Name() string        { return "tenant-server" }
func (s *tenantServer) Description() string { return "tenant-server" }

func (s *tenantServer) ListTools(context.Context) ([]map[string]any, error) {
	return []map[string]any{
		{
			"name":        "list_orders",
			"description": "list the caller's orders",
			"parameters":  map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "get_order",
			"description": "get one order by id",
			"parameters": map[string]any{
				"type":       "object",
				"properties": map[string]any{"id": map[string]any{"type": "string"}},
				"required":   []any{"id"},
			},
		},
	}, nil
}

func (s *tenantServer) CallTool(_ context.Context, name string, args map[string]any) (types.ToolResult, error) {
	switch name {
	case "list_orders":
		items := make([]map[string]any, 0, len(s.owned))
		// deterministic order for the test.
		for _, id := range sortedKeys(s.owned) {
			items = append(items, map[string]any{"id": id})
		}
		raw, _ := json.Marshal(map[string]any{"orders": items})
		return types.ToolResult{Text: string(raw), Raw: raw}, nil
	case "get_order":
		id, _ := args["id"].(string)
		body, ok := s.owned[id]
		if !ok {
			return types.ToolResult{Text: "access denied", IsError: true}, nil
		}
		return types.ToolResult{Text: body}, nil
	}
	return types.ToolResult{Text: "unknown tool", IsError: true}, nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// small n; simple insertion sort keeps the test dependency-free.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// plainReconGen implements only types.Generator (no ToolInvoker).
type plainReconGen struct{}

func (plainReconGen) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (plainReconGen) ClearHistory()       {}
func (plainReconGen) Name() string        { return "plain" }
func (plainReconGen) Description() string { return "plain" }

func init() {
	// navigator stub so NewIdentifiers can build the embedded llm.Base without a
	// real LLM; the deterministic path never calls it.
	generators.Register("test.ReconNav", func(registry.Config) (generators.Generator, error) {
		return &navStub{}, nil
	})
	// victim session factory: tenant-b owns ord_2.
	generators.Register("test.TenantB", func(registry.Config) (generators.Generator, error) {
		return newTenantServer(map[string]string{"ord_2": `{"id":"ord_2","item":"gadget","owner":"tenant-b"}`}), nil
	})
}

// navStub is a canned navigator; content is set per-test where needed.
type navStub struct{ content string }

func (n *navStub) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return []attempt.Message{attempt.NewAssistantMessage(n.content)}, nil
}
func (n *navStub) ClearHistory()       {}
func (n *navStub) Name() string        { return "navStub" }
func (n *navStub) Description() string { return "navStub" }

func newIdentifiersModule(t *testing.T, cfg registry.Config) *MCPIdentifiers {
	t.Helper()
	if _, ok := cfg["navigator_generator_type"]; !ok {
		cfg["navigator_generator_type"] = "test.ReconNav"
	}
	m, err := NewIdentifiers(cfg)
	if err != nil {
		t.Fatalf("NewIdentifiers: %v", err)
	}
	return m.(*MCPIdentifiers)
}

// TestIdentifiers_HarvestValidateEmitPerIdentity is the core deterministic path:
// each identity enumerates its own ids, round-trip validates them against the
// getter, and the module emits one observation per identity carrying the
// confirmed (tool, param, id) triple plus the validated args — server-agnostic
// evidence only (no fingerprint, no distinguishers).
func TestIdentifiers_HarvestValidateEmitPerIdentity(t *testing.T) {
	m := newIdentifiersModule(t, registry.Config{
		"identity_label": "tenant-a",
		"victims": []map[string]any{{
			"label":            "tenant-b",
			"generator_type":   "test.TenantB",
			"generator_config": map[string]any{},
		}},
	})

	primary := newTenantServer(map[string]string{"ord_1": `{"id":"ord_1","item":"widget","owner":"tenant-a"}`})

	obs, err := m.Recon(context.Background(), primary)
	if err != nil {
		t.Fatalf("Recon: %v", err)
	}
	if len(obs) != 2 {
		t.Fatalf("expected one observation per identity, got %d: %+v", len(obs), obs)
	}

	byIdentity := map[string]types.MCPIdentifiers{}
	for _, o := range obs {
		if o.Type != ObservationTypeIdentifiers {
			t.Errorf("observation type = %q, want %q", o.Type, ObservationTypeIdentifiers)
		}
		if o.Source != m.Name() {
			t.Errorf("observation source = %q, want %q", o.Source, m.Name())
		}
		var p types.MCPIdentifiers
		if err := json.Unmarshal(o.Data, &p); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if o.Target != p.Identity {
			t.Errorf("target %q != payload identity %q", o.Target, p.Identity)
		}
		byIdentity[p.Identity] = p
	}

	a, ok := byIdentity["tenant-a"]
	if !ok || len(a.Objects) != 1 {
		t.Fatalf("tenant-a objects = %+v, want exactly ord_1", a.Objects)
	}
	ref := a.Objects[0]
	if ref.Tool != "get_order" || ref.Param != "id" || ref.ID != "ord_1" {
		t.Errorf("tenant-a ref triple wrong: %+v", ref)
	}
	if ref.Source != "list_orders" {
		t.Errorf("tenant-a ref source = %q, want list_orders", ref.Source)
	}
	// The validated args must be carried so a BOLA replay can reuse them; the ref
	// carries no fingerprint or distinguisher (server-agnostic evidence only).
	if ref.Args["id"] != "ord_1" {
		t.Errorf("tenant-a ref args missing validated id: %+v", ref.Args)
	}

	b, ok := byIdentity["tenant-b"]
	if !ok || len(b.Objects) != 1 || b.Objects[0].ID != "ord_2" {
		t.Fatalf("tenant-b objects = %+v, want exactly ord_2", b.Objects)
	}

	// IdentifiersFrom must round-trip what Recon emitted.
	store := recon.NewStore()
	for _, o := range obs {
		store.Observe(o)
	}
	read := IdentifiersFrom(store)
	if len(read) != 2 {
		t.Fatalf("IdentifiersFrom len = %d, want 2", len(read))
	}
}

// TestIdentifiers_NoObservationWhenNothingHarvested (S6): when an identity owns
// nothing, its enumerator returns no ids, so no object round-trip validates and
// the module emits no observation for it (the harvest-failure / no-objects path).
func TestIdentifiers_NoObservationWhenNothingHarvested(t *testing.T) {
	m := newIdentifiersModule(t, registry.Config{"identity_label": "tenant-a"})
	primary := newTenantServer(map[string]string{}) // owns nothing
	obs, err := m.Recon(context.Background(), primary)
	if err != nil {
		t.Fatalf("Recon: %v", err)
	}
	if obs != nil {
		t.Errorf("expected no observations when nothing is harvested, got %+v", obs)
	}
}

// TestIdentifiers_SkipsNonToolInvoker: a plain generator (no ToolInvoker) yields
// no observations.
func TestIdentifiers_SkipsNonToolInvoker(t *testing.T) {
	m := newIdentifiersModule(t, registry.Config{"identity_label": "tenant-a"})
	obs, err := m.Recon(context.Background(), plainReconGen{})
	if err != nil {
		t.Fatalf("Recon: %v", err)
	}
	if obs != nil {
		t.Errorf("expected nil observations for non-ToolInvoker target, got %+v", obs)
	}
}

// TestIdentifiers_UsesPriorInventory: the module reuses a shared MCP inventory
// for the tool catalog instead of re-enumerating, and still validates against
// the live session.
func TestIdentifiers_UsesPriorInventory(t *testing.T) {
	m := newIdentifiersModule(t, registry.Config{"identity_label": "tenant-a"})

	inv := types.MCPInventory{Tools: []types.MCPTool{
		{Name: "list_orders", InputSchema: json.RawMessage(`{"type":"object","properties":{}}`)},
		{Name: "get_order", InputSchema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}`)},
	}}
	data, err := json.Marshal(inv)
	if err != nil {
		t.Fatalf("marshal inventory: %v", err)
	}
	store := recon.NewStore()
	store.Observe(output.Observation{Type: ObservationTypeInventory, Data: data})
	m.SetContext(recon.ProbeContext{Recon: store})

	primary := newTenantServer(map[string]string{"ord_1": `{"id":"ord_1"}`})
	obs, err := m.Recon(context.Background(), primary)
	if err != nil {
		t.Fatalf("Recon: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
}

// TestIdentifiers_NavigatorClassification exercises the optional navigator branch
// with a MOCK navigator: the navigator classifies the tools and the module then
// deterministically round-trip validates, so the outcome matches the heuristic
// path.
func TestIdentifiers_NavigatorClassification(t *testing.T) {
	m := newIdentifiersModule(t, registry.Config{
		"identity_label": "tenant-a",
		"use_navigator":  true,
	})
	// Inject a mock navigator (the embedded llm.Base field) that classifies the
	// two tools.
	m.Navigator = &navStub{content: `{"getters":[{"tool":"get_order","param":"id"}],"enumerators":["list_orders"]}`}

	primary := newTenantServer(map[string]string{"ord_1": `{"id":"ord_1","item":"widget"}`})
	obs, err := m.Recon(context.Background(), primary)
	if err != nil {
		t.Fatalf("Recon: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	var p types.MCPIdentifiers
	if err := json.Unmarshal(obs[0].Data, &p); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(p.Objects) != 1 || p.Objects[0].ID != "ord_1" || p.Objects[0].Tool != "get_order" {
		t.Errorf("navigator path objects wrong: %+v", p.Objects)
	}
}

// TestExtractIDs_PrefersToolTextOverEnvelope guards the real-world shape: a live
// generator returns the tool payload in ToolResult.Text and the MCP protocol
// envelope (payload nested as an escaped string) in ToolResult.Raw. extractIDs
// must parse the tool payload (Text), not walk the envelope keys.
func TestExtractIDs_PrefersToolTextOverEnvelope(t *testing.T) {
	text := `{"orders":[{"id":"ord_1001"},{"id":"ord_1002"}]}`
	envelope := []byte(`{"content":[{"type":"text","text":"{\"orders\":[{\"id\":\"ord_1001\"},{\"id\":\"ord_1002\"}]}"}],"isError":false}`)

	ids := extractIDs(wordBoundaryRE(defaultIDParamWords), text, envelope)
	if len(ids) != 2 || ids[0] != "ord_1001" || ids[1] != "ord_1002" {
		t.Fatalf("extractIDs = %v, want [ord_1001 ord_1002] from the tool payload, not the envelope", ids)
	}
}

// spyNav records whether it was invoked, and returns a canned classification.
type spyNav struct {
	called bool
	reply  string
}

func (s *spyNav) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	s.called = true
	return []attempt.Message{attempt.NewAssistantMessage(s.reply)}, nil
}
func (s *spyNav) ClearHistory()       {}
func (s *spyNav) Name() string        { return "spyNav" }
func (s *spyNav) Description() string { return "spyNav" }

func hasGetter(gs []toolSpec, name string) bool { return getterByName(gs, name) != nil }
func getterByName(gs []toolSpec, name string) *toolSpec {
	for i := range gs {
		if gs[i].name == name {
			return &gs[i]
		}
	}
	return nil
}

func hasEnum(es []toolSpec, name string) bool {
	for _, e := range es {
		if e.name == name {
			return true
		}
	}
	return false
}

// TestNavigatorClassifyPrompt_TreatsCatalogAsUntrustedData (Layer 1): the tool
// catalog is attacker-controlled, so the navigator prompt must frame it as
// untrusted data to classify — never as instructions to obey — and restrict the
// model to naming only tools present in the catalog. Hardening against a server
// that prompt-injects the navigator into selecting unintended tools.
func TestExtractIDs_CapturesScalarArrayUnderIDKey(t *testing.T) {
	ids := extractIDs(wordBoundaryRE(defaultIDParamWords), `{"order_ids":["ord_a","ord_b"]}`, nil)
	if !contains(ids, "ord_a") || !contains(ids, "ord_b") {
		t.Errorf("scalar ids under an id-like key must be captured; got %v", ids)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func (r *recordingInvoker) called(name string) bool {
	for _, c := range r.calls {
		if c == name {
			return true
		}
	}
	return false
}

func TestMCPIdentifiers_IgnoresIncompleteToolsCatalog(t *testing.T) {
	inv := types.MCPInventory{
		Tools:      []types.MCPTool{{Name: "benign_prefix_tool"}},
		Incomplete: []string{types.MCPCatalogTools},
	}
	data, err := json.Marshal(inv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	store := recon.NewStore()
	store.Observe(output.Observation{Type: ObservationTypeInventory, Data: data})

	m := &MCPIdentifiers{}
	m.SetContext(recon.ProbeContext{Recon: store})

	// A generator that is NOT a ToolInvoker: with the stored inventory rejected there
	// is no live fallback, so a correct implementation resolves no catalog rather than
	// classifying the truncated prefix.
	tools, err := m.toolCatalog(context.Background(), nonInvokerGen{})
	if err != nil {
		t.Fatalf("toolCatalog: %v", err)
	}
	if len(tools) != 0 {
		t.Errorf("reused an incomplete tools catalog (%d tools); a partial prefix must not become the ownership ground truth", len(tools))
	}
}

// TestMCPIdentifiers_ReusesCompleteInventoryDespiteOtherIncompleteCatalogs: the
// completeness check must be per catalog. This module needs only the tool surface, so
// a failed prompts or resources enumeration must not force a redundant live walk.
func TestMCPIdentifiers_ReusesCompleteInventoryDespiteOtherIncompleteCatalogs(t *testing.T) {
	inv := types.MCPInventory{
		Tools:      []types.MCPTool{{Name: "get_order"}},
		Incomplete: []string{types.MCPCatalogPrompts}, // unrelated catalog
	}
	data, err := json.Marshal(inv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	store := recon.NewStore()
	store.Observe(output.Observation{Type: ObservationTypeInventory, Data: data})

	m := &MCPIdentifiers{}
	m.SetContext(recon.ProbeContext{Recon: store})

	tools, err := m.toolCatalog(context.Background(), nonInvokerGen{})
	if err != nil {
		t.Fatalf("toolCatalog: %v", err)
	}
	if len(tools) != 1 {
		t.Errorf("got %d tools, want 1: a complete tools catalog must be reused even when a sibling catalog truncated", len(tools))
	}
}

// nonInvokerGen is a generator with no tool surface, so toolCatalog has no live
// fallback and the test observes only what it resolved from the store.
type nonInvokerGen struct{}

func (nonInvokerGen) Name() string        { return "test.NonInvoker" }
func (nonInvokerGen) Description() string { return "generator with no tool surface" }
func (nonInvokerGen) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (nonInvokerGen) ClearHistory() {}

func TestSameAsBaseline_RecognisesANotFoundDressedAsSuccess(t *testing.T) {
	base := `{"error":"no such object","object_id":"aug-nonexistent-99"}`
	cand := `{"error":"no such object","object_id":"TENANT-A"}`
	if !sameAsBaseline(cand, "TENANT-A", base, "aug-nonexistent-99") {
		t.Error("a response identical to the not-found baseline (once ids are masked) must not confirm an object")
	}

	real := `{"object":{"object_id":"obj_a1","name":"alpha report"}}`
	if sameAsBaseline(real, "obj_a1", base, "aug-nonexistent-99") {
		t.Error("a served object must be distinguishable from the not-found baseline")
	}
}

// Masking is what makes the comparison work at all: a server echoing the id it
// was asked about would otherwise make every refusal look distinct.
func TestSameAsBaseline_MasksTheEchoedIdentifier(t *testing.T) {
	if !sameAsBaseline(`{"error":"unknown id X1"}`, "X1", `{"error":"unknown id NX"}`, "NX") {
		t.Error("two refusals differing only in the echoed id are the same answer")
	}
}

// A candidate value can also appear in the BASELINE's response — a tenant
// identifier harvested as a candidate is echoed as the tenant of every call,
// baseline included. Masking each response's own id only would leave that
// occurrence behind and make two identical refusals compare unequal, which is
// exactly how a tenant id came to be confirmed as an object.
func TestSameAsBaseline_MasksBothIdsInBothResponses(t *testing.T) {
	base := `{"error":"no such object","received":{"tenant_id":"TENANT-A","object_id":"NX-1"}}`
	cand := `{"error":"no such object","received":{"tenant_id":"TENANT-A","object_id":"TENANT-A"}}`
	if !sameAsBaseline(cand, "TENANT-A", base, "NX-1") {
		t.Error("a refusal echoing the candidate value elsewhere must still match the baseline")
	}
}

// spec builds a minimal signature for a tool with the given id-shaped params.
func spec(name string, tm map[string]any, idParams ...string) toolSpec {
	sig := toolsig.Signature{Tool: name, Select: map[string]any{}}
	for _, p := range idParams {
		sig.Params = append(sig.Params, toolsig.Param{Path: toolsig.Path(p), Type: "string"})
	}
	if tm == nil {
		tm = map[string]any{"name": name}
	}
	return toolSpec{name: name, sig: sig, params: sig.Params, tm: tm}
}

// A cap that silently drops identifiers is indistinguishable from a target that
// owns fewer objects, so truncation is logged with the tool and the cap.
func TestDiscover_LogsWhenTruncatingIDs(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	defer slog.SetDefault(old)

	m := newIdentifiersModule(t, registry.Config{"use_navigator": false, "max_ids_per_tool": 1})
	inv := &recordingInvoker{body: `[{"id":"x1"},{"id":"x2"}]`} // 2 ids, cap is 1

	m.discover(context.Background(), identitySession{label: "a", inv: inv}, []toolSpec{spec("list_orders", nil)})

	if !strings.Contains(buf.String(), "max_ids_per_tool") {
		t.Errorf("truncation to max_ids_per_tool must be logged; log was: %s", buf.String())
	}
}

// Layer 2: a denied tool must be refused where the call actually happens, not
// upstream only. Authorization to invoke lives at the call site.
func TestDiscover_GatesDenylistedToolAtCallSite(t *testing.T) {
	m := newIdentifiersModule(t, registry.Config{
		"use_navigator": false,
		"tool_denylist": []any{"danger_enum", "danger_get"},
	})
	rec := &recordingInvoker{body: `[{"id":"x1"}]`}

	m.discover(context.Background(), identitySession{label: "a", inv: rec}, []toolSpec{
		spec("list_orders", nil),
		spec("danger_enum", nil),
		spec("get_order", nil, "id"),
		spec("danger_get", nil, "id"),
	})

	for _, denied := range []string{"danger_enum", "danger_get"} {
		if rec.called(denied) {
			t.Errorf("denied tool %s must not be invoked at the call site", denied)
		}
	}
	if !rec.called("list_orders") {
		t.Error("allowed tool list_orders should still be invoked")
	}
}

// Layer 2, annotations: a tool the server annotates destructive is re-checked
// and skipped where the call happens, independently of the upstream filter.
func TestDiscover_GatesDestructiveAnnotatedToolAtCallSite(t *testing.T) {
	m := newIdentifiersModule(t, registry.Config{"use_navigator": false})
	rec := &recordingInvoker{body: `[{"id":"x1"}]`}

	destructive := map[string]any{
		"name":        "wipe_orders",
		"annotations": types.MCPToolAnnotations{Destructive: boolPtr(true)},
	}
	m.discover(context.Background(), identitySession{label: "a", inv: rec}, []toolSpec{
		spec("list_orders", nil),
		spec("wipe_orders", destructive),
	})

	if rec.called("wipe_orders") {
		t.Error("a tool the server annotates destructive must not be invoked")
	}
}

// The role a tool plays is decided by what the server does, not by its name. A
// tool named "list_*" that also takes a required scope identifier must still be
// able to act as the source of identifiers — that combination is the norm on a
// tenant-scoped surface, and treating it as a getter left nothing to enumerate.
func TestDiscover_ScopeParamDoesNotPreventHarvesting(t *testing.T) {
	m := newIdentifiersModule(t, registry.Config{"use_navigator": false})
	// The stub must ANSWER DIFFERENTLY for a real id than for one that does not
	// exist, because that difference is exactly what confirms an object. A stub
	// returning one fixed body would (correctly) confirm nothing.
	rec := &objectServer{objects: map[string]string{"obj_1": "the first object"}}

	refs := m.discover(context.Background(), identitySession{label: "a", inv: rec}, []toolSpec{
		// Every tool carries a required, id-shaped scope parameter.
		spec("list_objects", nil, "tenant_id"),
		spec("get_object", nil, "tenant_id", "object_id"),
	})

	if !rec.called("list_objects") {
		t.Fatal("a tool carrying a scope id must still be called for identifiers")
	}
	found := false
	for _, r := range refs {
		if r.ID == "obj_1" && r.Param == "object_id" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected obj_1 confirmed through object_id; refs = %+v", refs)
	}
}

// recordingInvoker records which tools were invoked and answers every call with
// the same body, so a test can assert on WHICH calls a module chose to make.
type recordingInvoker struct {
	calls []string
	body  string
}

func (r *recordingInvoker) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (r *recordingInvoker) ClearHistory()                                       {}
func (r *recordingInvoker) Name() string                                        { return "recording" }
func (r *recordingInvoker) Description() string                                 { return "recording" }
func (r *recordingInvoker) ListTools(context.Context) ([]map[string]any, error) { return nil, nil }
func (r *recordingInvoker) CallTool(_ context.Context, name string, _ map[string]any) (types.ToolResult, error) {
	r.calls = append(r.calls, name)
	b := r.body
	if b == "" {
		b = `{"id":"x1"}`
	}
	return types.ToolResult{Text: b, Raw: []byte(b)}, nil
}

func boolPtr(b bool) *bool { return &b }

// objectServer answers like a real object store: a listing returns identifiers,
// a lookup returns the object for one it knows and a refusal for one it does
// not. The refusal is a NORMAL result with an error in the body, which is how
// most servers report "not found" and why confirmation cannot rest on IsError.
type objectServer struct {
	calls   []string
	objects map[string]string
}

func (o *objectServer) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (o *objectServer) ClearHistory()                                       {}
func (o *objectServer) Name() string                                        { return "objects" }
func (o *objectServer) Description() string                                 { return "objects" }
func (o *objectServer) ListTools(context.Context) ([]map[string]any, error) { return nil, nil }

func (o *objectServer) CallTool(_ context.Context, name string, args map[string]any) (types.ToolResult, error) {
	o.calls = append(o.calls, name)
	id, _ := args["object_id"].(string)
	var body string
	switch {
	case id == "":
		ids := make([]string, 0, len(o.objects))
		for k := range o.objects {
			ids = append(ids, k)
		}
		sort.Strings(ids)
		parts := make([]string, 0, len(ids))
		for _, k := range ids {
			parts = append(parts, `{"object_id":"`+k+`"}`)
		}
		body = `{"objects":[` + strings.Join(parts, ",") + `]}`
	case o.objects[id] != "":
		body = `{"object":{"object_id":"` + id + `","name":"` + o.objects[id] + `"}}`
	default:
		body = `{"error":"no such object","object_id":"` + id + `"}`
	}
	return types.ToolResult{Text: body, Raw: []byte(body)}, nil
}

func (o *objectServer) called(name string) bool {
	for _, c := range o.calls {
		if c == name {
			return true
		}
	}
	return false
}

// Reconnaissance is read-only by contract, and the destructive-annotation gate
// does not deliver that on its own: its default is PERMIT, and most servers
// annotate nothing. Discovery calls every signature it is given, so without a
// second gate an unannotated delete operation is invoked during what is meant to
// be a read-only phase — with an identifier the value chain may have harvested,
// which is what would make the call effective.
func TestDiscover_DoesNotInvokeUnannotatedWriteTools(t *testing.T) {
	m := newIdentifiersModule(t, registry.Config{"use_navigator": false})
	rec := &recordingInvoker{body: `{"records":[{"record_id":"r1"}]}`}

	m.discover(context.Background(), identitySession{label: "a", inv: rec}, []toolSpec{
		spec("list_records", nil),            // reads as retrieval
		spec("get_record", nil, "record_id"), // reads as retrieval
		spec("delete_record", nil, "record_id"),
		spec("wipe_everything", nil),
	})

	for _, safe := range []string{"list_records", "get_record"} {
		if !rec.called(safe) {
			t.Errorf("%s should be invoked: its name is recognisably a read operation", safe)
		}
	}
	for _, unsafe := range []string{"delete_record", "wipe_everything"} {
		if rec.called(unsafe) {
			t.Errorf("%s must NOT be invoked: the server does not annotate it read-only and its name is not a read operation", unsafe)
		}
	}
}

// The server's own read-only annotation is authoritative, whatever the name says.
func TestDiscover_InvokesAnnotatedReadOnlyToolWhateverItIsCalled(t *testing.T) {
	m := newIdentifiersModule(t, registry.Config{"use_navigator": false})
	rec := &recordingInvoker{body: `{"records":[{"record_id":"r1"}]}`}

	readOnly := map[string]any{
		"name":        "purge_cache",
		"annotations": types.MCPToolAnnotations{ReadOnly: true},
	}
	m.discover(context.Background(), identitySession{label: "a", inv: rec}, []toolSpec{spec("purge_cache", readOnly)})

	if !rec.called("purge_cache") {
		t.Error("a tool the server annotates read-only must be invoked despite its name")
	}
}

// Naming a tool is the operator's statement that calling it is acceptable, and
// that decision is theirs rather than the heuristic's.
func TestDiscover_InvokesToolTheOperatorNamed(t *testing.T) {
	m := newIdentifiersModule(t, registry.Config{
		"use_navigator":     false,
		"enumeration_tools": []any{"drain_queue"},
	})
	rec := &recordingInvoker{body: `{"records":[{"record_id":"r1"}]}`}

	m.discover(context.Background(), identitySession{label: "a", inv: rec}, []toolSpec{spec("drain_queue", nil)})

	if !rec.called("drain_queue") {
		t.Error("a tool named in enumeration_tools must be invoked; the operator has accepted it")
	}
}

// Name matching is per-token, so a compound name carries every verb in it. A
// tool called get_and_delete_record contains "get" and would pass a plain
// allowlist on the strength of the half that is safe. A compound name is only as
// safe as its most dangerous verb.
func TestDiscover_DestructiveVerbVetoesAReadOnlyName(t *testing.T) {
	m := newIdentifiersModule(t, registry.Config{"use_navigator": false})
	rec := &recordingInvoker{body: `{"records":[{"record_id":"r1"}]}`}

	m.discover(context.Background(), identitySession{label: "a", inv: rec}, []toolSpec{
		spec("get_and_delete_record", nil, "record_id"),
		spec("list_then_purge", nil),
		spec("read_record", nil, "record_id"),
	})

	for _, unsafe := range []string{"get_and_delete_record", "list_then_purge"} {
		if rec.called(unsafe) {
			t.Errorf("%s must NOT be invoked: a destructive verb vetoes the read-only name match", unsafe)
		}
	}
	if !rec.called("read_record") {
		t.Error("read_record should still be invoked")
	}
}

// No list of destructive verbs is ever complete, so a compound name is not
// established read-only by the retrieval verb in it. "get_and_mark_read" matches
// both "get" and "read" while the operation that matters is "mark".
func TestDiscover_CompoundNameIsNotEstablishedReadOnly(t *testing.T) {
	m := newIdentifiersModule(t, registry.Config{"use_navigator": false})
	rec := &recordingInvoker{body: `{"records":[{"record_id":"r1"}]}`}

	m.discover(context.Background(), identitySession{label: "a", inv: rec}, []toolSpec{
		spec("get_and_mark_read", nil, "record_id"),
		spec("fetch_or_create", nil, "record_id"),
		spec("list_records", nil),
	})

	for _, compound := range []string{"get_and_mark_read", "fetch_or_create"} {
		if rec.called(compound) {
			t.Errorf("%s must NOT be invoked: a conjunction means it does more than retrieve", compound)
		}
	}
	if !rec.called("list_records") {
		t.Error("a plain retrieval name must still be invoked")
	}
}
