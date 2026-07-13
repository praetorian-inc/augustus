package mcp

import (
	"context"
	"encoding/json"
	"testing"

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

// TestClassify_NavigatorPrimaryByDefault: with no use_navigator key, the LLM
// navigator must be the primary classifier (LLM-first), not the heuristics.
func TestClassify_NavigatorPrimaryByDefault(t *testing.T) {
	m := newIdentifiersModule(t, registry.Config{}) // no use_navigator set
	spy := &spyNav{reply: `{"getters":[{"tool":"get_order","param":"order_id"}],"enumerators":["list_orders"]}`}
	m.Navigator = spy // inject over the lazy default

	tools := []map[string]any{
		{"name": "list_orders", "parameters": map[string]any{"type": "object", "properties": map[string]any{}}},
		{"name": "get_order", "parameters": map[string]any{"type": "object", "properties": map[string]any{"order_id": map[string]any{"type": "string"}}, "required": []any{"order_id"}}},
	}
	getters, enums := m.classify(context.Background(), tools)
	if !spy.called {
		t.Fatal("navigator must be consulted by default (LLM-primary); it was not")
	}
	if len(getters) != 1 || getters[0].name != "get_order" || len(enums) != 1 || enums[0].name != "list_orders" {
		t.Fatalf("classification not from navigator: getters=%v enums=%v", getters, enums)
	}
}

// TestClassifyHeuristic_EditablePatterns: the keyword lists behind the
// deterministic classifier are operator-extendable (Hunter's replace/extend
// config pattern). A tool the defaults miss ("grab_widget" with a "sku" id)
// becomes classifiable once the operator adds those words.
func TestClassifyHeuristic_EditablePatterns(t *testing.T) {
	tools := []map[string]any{
		{"name": "browse_widgets", "parameters": map[string]any{"type": "object", "properties": map[string]any{}}},
		{"name": "grab_widget", "parameters": map[string]any{"type": "object", "properties": map[string]any{"sku": map[string]any{"type": "string"}}, "required": []any{"sku"}}},
	}

	// Defaults miss "grab"/"sku": grab_widget is not recognized as a getter.
	def := newIdentifiersModule(t, registry.Config{"use_navigator": false})
	g, _ := def.classifyHeuristic(tools)
	if hasGetter(g, "grab_widget") {
		t.Fatal("baseline: grab_widget should NOT be a getter under default patterns")
	}

	// Operator extends the id-param and getter-name vocabularies.
	m := newIdentifiersModule(t, registry.Config{
		"use_navigator":              false,
		"getter_name_extra_patterns": []any{"grab"},
		"id_param_extra_patterns":    []any{"sku"},
	})
	g2, e2 := m.classifyHeuristic(tools)
	gs := getterByName(g2, "grab_widget")
	if gs == nil || gs.idParam != "sku" {
		t.Fatalf("with extra patterns, grab_widget should be a getter on 'sku'; got %v", g2)
	}
	if !hasEnum(e2, "browse_widgets") {
		t.Errorf("browse_widgets should be an enumerator; got %v", e2)
	}
}

// TestClassifyHeuristic_SkipsDestructiveTools (S1): the safety gate now runs on
// server ANNOTATIONS, not tool names. classify() filters the catalog through the
// shared toolpolicy before either the navigator or the heuristic sees it, so a
// tool the server annotates destructive becomes neither getter NOR enumerator.
// The old destructive-NAME regex is gone: a destructive-SOUNDING tool with no
// annotations is KEPT and classified normally.
func TestClassifyHeuristic_SkipsDestructiveTools(t *testing.T) {
	tools := []map[string]any{
		// read-only enumerator, no annotations — kept, classified as an enumerator.
		{"name": "list_orders", "parameters": map[string]any{"type": "object", "properties": map[string]any{}}},
		// annotated destructive (non-read-only, Destructive defaults true) — dropped
		// by the policy before classification.
		{
			"name":        "wipe_orders",
			"parameters":  map[string]any{"type": "object", "properties": map[string]any{}},
			"annotations": types.MCPToolAnnotations{},
		},
		// destructive-SOUNDING name but NO annotations — the name heuristic is gone,
		// so it is KEPT and classified as a getter on its required id.
		{"name": "delete_order", "parameters": map[string]any{"type": "object", "properties": map[string]any{"id": map[string]any{"type": "string"}}, "required": []any{"id"}}},
	}

	m := newIdentifiersModule(t, registry.Config{"use_navigator": false})
	getters, enums := m.classify(context.Background(), tools)

	if hasEnum(enums, "wipe_orders") || hasGetter(getters, "wipe_orders") {
		t.Error("wipe_orders is annotated destructive; the policy must drop it before classification")
	}
	if !hasEnum(enums, "list_orders") {
		t.Errorf("list_orders should still be an enumerator; got %v", enums)
	}
	// The destructive NAME heuristic is gone: without annotations delete_order is kept.
	if !hasGetter(getters, "delete_order") {
		t.Errorf("delete_order has no annotations; with the name heuristic removed it must be KEPT and classified as a getter; got %v", getters)
	}
}

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
