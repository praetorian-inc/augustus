package toolsig

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

// envelopeSchema is the shape that defeats a top-level-only reader: two
// required scalars beside an opaque object whose real members are declared in a
// conditional branch.
const envelopeSchema = `{"type":"object",
  "properties":{
    "action":{"type":"string","enum":["get","search"]},
    "tenant_uid":{"type":"string"},
    "params":{"type":"object"}},
  "required":["action","tenant_uid"],
  "allOf":[
    {"if":{"properties":{"action":{"const":"get"}}},
     "then":{"properties":{"params":{"type":"object",
       "properties":{"record_id":{"type":"string"}},
       "required":["record_id"]}}}}]}`

func envelopeGet(t *testing.T) Signature {
	t.Helper()
	sigs, err := Signatures("list_records", json.RawMessage(envelopeSchema))
	if err != nil {
		t.Fatalf("Signatures: %v", err)
	}
	return findSig(t, sigs, "action", "get")
}

// The end-to-end shape: discriminator from the signature, opaque value from
// config, payload from the caller — rendered nested, as the server expects.
func TestBuildRendersNestedArguments(t *testing.T) {
	sig := envelopeGet(t)
	chain := Chain{
		FromSchema(),
		FromValues(map[string]any{"tenant_uid": "1234567890123456789"}),
	}

	// Build reports params.record_id missing; the caller is about to supply it.
	call, _ := sig.Build(chain)
	call.Set("params.record_id", "829471*513")

	if miss := call.Unresolved(); len(miss) != 0 {
		t.Errorf("after setting the parameter under test, nothing should remain unresolved: %v", miss)
	}

	want := map[string]any{
		"action":     "get",
		"tenant_uid": "1234567890123456789",
		"params":     map[string]any{"record_id": "829471*513"},
	}
	if got := call.Args(); !reflect.DeepEqual(got, want) {
		t.Errorf("Args() = %#v\nwant %#v", got, want)
	}
	if err := call.Validate(); err != nil {
		t.Errorf("the rendered call must satisfy the tool's own schema: %v", err)
	}
}

// A required parameter no source can supply must be reported, not papered over
// with a placeholder. A placeholder produces a rejected call and a verdict that
// describes the scanner's reach rather than the target.
func TestUnresolvedRequiredParamIsReported(t *testing.T) {
	sig := envelopeGet(t)

	call, err := sig.Build(Chain{FromSchema()}) // nothing supplies tenant_uid
	if err == nil {
		t.Fatal("Build must report required parameters no source could supply")
	}

	var ue *UnresolvedError
	if !errors.As(err, &ue) {
		t.Fatalf("error is %T, want *UnresolvedError so callers can tell this from a transport failure", err)
	}

	// The caller supplies the parameter it is testing; only the genuinely
	// unavailable one should remain.
	call.Set("params.record_id", "PAYLOAD")

	miss := call.Unresolved()
	if len(miss) != 1 || miss[0].Path != "tenant_uid" {
		t.Fatalf("unresolved = %v, want [tenant_uid] only", miss)
	}
	for _, p := range miss {
		if p.Path == "params.record_id" {
			t.Error("the parameter under test must not be reported unresolved once set")
		}
	}
}

// Two variants of one call must not share state. Under a nested representation
// they share the inner object, so setting the control's identifier also rewrites
// the attack's — both calls then address the same object and a real finding
// reads as a pass.
func TestCloneIsIndependentForNestedPaths(t *testing.T) {
	sig := envelopeGet(t)
	base, _ := sig.Build(Chain{FromSchema(), FromValues(map[string]any{"tenant_uid": "A"})})
	base.Set("params.record_id", "VICTIM_ID")

	attack := base.Clone()
	control := base.Clone()
	control.Set("params.record_id", "NONEXISTENT")

	aNested, ok := attack.Args()["params"].(map[string]any)
	if !ok {
		t.Fatalf("attack params is %T, want map", attack.Args()["params"])
	}
	if aNested["record_id"] != "VICTIM_ID" {
		t.Errorf("control mutation leaked into the attack: params.record_id = %v", aNested["record_id"])
	}
	cNested := control.Args()["params"].(map[string]any)
	if cNested["record_id"] != "NONEXISTENT" {
		t.Errorf("control params.record_id = %v, want NONEXISTENT", cNested["record_id"])
	}

	// The rendered objects must be distinct allocations, not two views of one.
	if reflect.ValueOf(aNested).Pointer() == reflect.ValueOf(cNested).Pointer() {
		t.Error("rendered nested objects are aliased between clones")
	}
}

// Sources are consulted in order and the winner is recorded, so a finding can
// say where a value came from and a wrongly filled parameter is traceable.
func TestChainOrderAndProvenance(t *testing.T) {
	sig := envelopeGet(t)
	chain := Chain{
		FromSchema(),
		FromObserved(func(p Param) (any, bool) {
			if p.Path == "tenant_uid" {
				return "FROM_OBSERVED", true
			}
			return nil, false
		}),
		FromValues(map[string]any{"tenant_uid": "FROM_CONFIG"}),
	}

	call, _ := sig.Build(chain) // params.record_id supplied below
	if got := call.Args()["tenant_uid"]; got != "FROM_OBSERVED" {
		t.Errorf("tenant_uid = %v, want FROM_OBSERVED (earlier source wins)", got)
	}

	prov := call.Provenance()
	if prov["tenant_uid"] != "observed" {
		t.Errorf("provenance[tenant_uid] = %q, want observed", prov["tenant_uid"])
	}
	if prov["action"] != "selector" {
		t.Errorf("provenance[action] = %q, want selector", prov["action"])
	}
	call.Set("params.record_id", "X")
	if call.Provenance()["params.record_id"] != "caller" {
		t.Error("a value the caller set must be attributed to the caller")
	}
}

// A more specific rule wins, so a per-tool override and a blanket name rule can
// coexist without either knowing about the other.
func TestRuleSpecificityOrdering(t *testing.T) {
	rules := []Rule{
		{Name: "tenant_uid", Value: "GLOBAL"},
		{Tool: "list_records", Path: "tenant_uid", Value: "PER_TOOL"},
	}
	src := FromRules("list_records", rules)
	v, ok := src.Value(Param{Path: "tenant_uid"})
	if !ok || v != "PER_TOOL" {
		t.Errorf("value = %v (ok=%v), want PER_TOOL", v, ok)
	}

	other := FromRules("other_tool", rules)
	v, ok = other.Value(Param{Path: "tenant_uid"})
	if !ok || v != "GLOBAL" {
		t.Errorf("value for another tool = %v (ok=%v), want GLOBAL", v, ok)
	}
}

// A rule matching a large share of parameters is a foot-gun worth warning
// about; that is only visible once the parameters are known.
func TestBroadRulesAreDetectable(t *testing.T) {
	params := []Param{
		{Path: "a.id"}, {Path: "b.id"}, {Path: "c.id"}, {Path: "tenant_uid"},
	}
	rules := []Rule{{Name: "id", Value: "x"}, {Name: "tenant_uid", Value: "y"}}
	broad := BroadRules("t", rules, params, 2)
	if len(broad) != 1 || broad[0].Name != "id" {
		t.Errorf("broad = %v, want the {name: id} rule only", broad)
	}
}

// Enum selection is deterministic and carries no judgement about which member
// is safe. Whether a tool may be called at all is the server's declaration (tool
// annotations) and the operator's decision (allow_destructive, denylists); a
// tool past those gates has every branch in scope. Ranking members by how
// dangerous they sound would substitute a guess for the server's own statement
// and make the scan unpredictable.
func TestSchemaSourceEnumIsDeterministic(t *testing.T) {
	v, ok := FromSchema().Value(Param{Enum: []string{"delete", "read"}})
	if !ok || v != "delete" {
		t.Errorf("value = %v (ok=%v), want the first declared member", v, ok)
	}
	// Const and default outrank an enum, both being unambiguous.
	if v, ok := FromSchema().Value(Param{Enum: []string{"a"}, Default: 10}); !ok || v != 10 {
		t.Errorf("value = %v (ok=%v), want the declared default", v, ok)
	}
	if v, ok := FromSchema().Value(Param{Enum: []string{"a"}, Const: "C"}); !ok || v != "C" {
		t.Errorf("value = %v (ok=%v), want the declared const", v, ok)
	}
	if _, ok := FromSchema().Value(Param{Type: "string"}); ok {
		t.Error("a parameter the schema does not determine must yield no value")
	}
}

// Hook variables are matched by upper-cased name, so an opaque value can be
// fetched at scan time instead of written into a config file.
func TestHookVarsSource(t *testing.T) {
	src := FromHookVars(map[string]string{"TENANT_UID": "FROM_HOOK"})
	if v, ok := src.Value(Param{Path: "tenant_uid"}); !ok || v != "FROM_HOOK" {
		t.Errorf("value = %v (ok=%v), want FROM_HOOK", v, ok)
	}
	if v, ok := src.Value(Param{Path: "params.tenant_uid"}); !ok || v != "FROM_HOOK" {
		t.Errorf("nested leaf should match too: %v (ok=%v)", v, ok)
	}
}

// A specific value must survive a more general one regardless of map ordering.
func TestArgsWritesShallowestFirst(t *testing.T) {
	c := &Call{kv: map[Path]any{
		"params.id": "SPECIFIC",
		"params":    map[string]any{},
	}}
	got, ok := c.Args()["params"].(map[string]any)
	if !ok {
		t.Fatalf("params is %T, want map", c.Args()["params"])
	}
	if got["id"] != "SPECIFIC" {
		t.Errorf("params.id = %v, want SPECIFIC — the object must not overwrite its member", got["id"])
	}
}

// Array element addressing must render a real array, not an object keyed "[0]".
func TestArgsRendersArrayElements(t *testing.T) {
	c := &Call{kv: map[Path]any{"filters[0].field": "name"}}
	arr, ok := c.Args()["filters"].([]any)
	if !ok {
		t.Fatalf("filters is %T, want []any", c.Args()["filters"])
	}
	if len(arr) != 1 {
		t.Fatalf("len(filters) = %d, want 1", len(arr))
	}
	el, ok := arr[0].(map[string]any)
	if !ok || el["field"] != "name" {
		t.Errorf("filters[0] = %#v, want {field: name}", arr[0])
	}
}

// A flat schema must build exactly the arguments the current flat code path
// builds. This is the regression gate for every server that is not nested.
func TestFlatSchemaBuildsFlatArguments(t *testing.T) {
	sigs, err := Signatures("read_file", json.RawMessage(
		`{"type":"object","properties":{"path":{"type":"string"},"limit":{"type":"integer"}},
		  "required":["path"]}`))
	if err != nil {
		t.Fatalf("Signatures: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("a flat schema must yield exactly one signature, got %d", len(sigs))
	}
	call, err := sigs[0].Build(Chain{FromSchema(), FromValues(map[string]any{"path": "/tmp/x"})})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	call.Set("path", "../../etc/passwd")

	want := map[string]any{"path": "../../etc/passwd"}
	if got := call.Args(); !reflect.DeepEqual(got, want) {
		t.Errorf("Args() = %#v, want %#v (no nesting, no invented keys)", got, want)
	}
}

// Operator configuration is read from the same shape the config file uses, and
// binds by selector so one rule covers a value appearing in every tool.
func TestRulesFromConfig(t *testing.T) {
	cfg := map[string]any{"values": []any{
		map[string]any{
			"match": map[string]any{"name": "tenant_uid"},
			"value": "1234567890123456789",
		},
		map[string]any{
			"match": map[string]any{"tool": "get_profile", "path": "params.id"},
			"value": "ACC-1",
		},
		map[string]any{"match": map[string]any{}, "value": "unconstrained"}, // dropped
		map[string]any{"match": map[string]any{"name": "x"}},                // no value, dropped
	}}

	rules := RulesFromConfig(cfg)
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2 (a rule constraining nothing and a rule with no value are both dropped)", len(rules))
	}

	src := FromRules("get_profile", rules)
	if v, ok := src.Value(Param{Path: "tenant_uid"}); !ok || v != "1234567890123456789" {
		t.Errorf("tenant_uid = %v (ok=%v)", v, ok)
	}
	if v, ok := src.Value(Param{Path: "params.id"}); !ok || v != "ACC-1" {
		t.Errorf("params.id = %v (ok=%v)", v, ok)
	}
}

// An operator can always decline to write a rule, but if configuration ranked
// below an inferred value there would be no way to override a wrong inference at
// all. Explicit therefore beats inferred.
func TestConfigOutranksObserved(t *testing.T) {
	observed := FromObserved(func(p Param) (any, bool) {
		if p.Path == "tenant_uid" {
			return "FROM_RESPONSE", true
		}
		return nil, false
	})
	rules := FromRules("t", []Rule{{Name: "tenant_uid", Value: "FROM_CONFIG"}})

	chain := Chain{rules, observed}
	v, from, ok := chain.Value(Param{Path: "tenant_uid"})
	if !ok || v != "FROM_CONFIG" || from != "config" {
		t.Errorf("value = %v from %q (ok=%v), want FROM_CONFIG from config", v, from, ok)
	}

	// With no rule written, the observed value is used.
	v, from, ok = Chain{FromRules("t", nil), observed}.Value(Param{Path: "tenant_uid"})
	if !ok || v != "FROM_RESPONSE" || from != "observed" {
		t.Errorf("value = %v from %q (ok=%v), want FROM_RESPONSE from observed", v, from, ok)
	}
}
