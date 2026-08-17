package toolsig

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

// paths renders a signature's parameters as dotted strings for comparison.
func paths(s Signature) []string {
	out := make([]string, 0, len(s.Params))
	for _, p := range s.Params {
		out = append(out, string(p.Path))
	}
	sort.Strings(out)
	return out
}

// findSig returns the signature selected by the given discriminator value.
func findSig(t *testing.T, sigs []Signature, key string, want any) Signature {
	t.Helper()
	for _, s := range sigs {
		if v, ok := s.Select[key]; ok && v == want {
			return s
		}
	}
	t.Fatalf("no signature with %s=%v; got %d signatures", key, want, len(sigs))
	return Signature{}
}

// TestConstructs walks one schema per JSON Schema construct an MCP server can
// legally advertise. Each case asserts the leaf parameters a caller would be
// able to reach — which is precisely what a top-level-only reader cannot do.
func TestConstructs(t *testing.T) {
	cases := []struct {
		name      string
		schema    string
		wantSigs  int
		wantPaths []string // for the single-signature cases
	}{
		{
			name: "flat",
			schema: `{"type":"object",
			  "properties":{"path":{"type":"string"},"limit":{"type":"integer"}},
			  "required":["path"]}`,
			wantSigs:  1,
			wantPaths: []string{"limit", "path"},
		},
		{
			name: "nested two levels",
			schema: `{"type":"object","properties":{
			  "filter":{"type":"object","properties":{
			    "field":{"type":"string"},
			    "range":{"type":"object","properties":{"from":{"type":"string"}}}}}}}`,
			wantSigs:  1,
			wantPaths: []string{"filter.field", "filter.range.from"},
		},
		{
			name: "ref and defs",
			schema: `{"type":"object",
			  "properties":{"filter":{"$ref":"#/$defs/Filter"}},
			  "$defs":{"Filter":{"type":"object","properties":{
			    "field":{"type":"string"},"op":{"type":"string","enum":["eq","gt"]}}}}}`,
			wantSigs:  1,
			wantPaths: []string{"filter.field", "filter.op"},
		},
		{
			name: "array of objects",
			schema: `{"type":"object","properties":{
			  "filters":{"type":"array","items":{"type":"object","properties":{
			    "field":{"type":"string"},"value":{"type":"string"}}}}}}`,
			wantSigs:  1,
			wantPaths: []string{"filters[0].field", "filters[0].value"},
		},
		{
			name: "array of scalars stays one param",
			schema: `{"type":"object","properties":{
			  "ids":{"type":"array","items":{"type":"string"}}}}`,
			wantSigs:  1,
			wantPaths: []string{"ids"},
		},
		{
			name:      "empty schema",
			schema:    `{"type":"object"}`,
			wantSigs:  1,
			wantPaths: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sigs, err := Signatures("t", json.RawMessage(tc.schema))
			if err != nil {
				t.Fatalf("Signatures: %v", err)
			}
			if len(sigs) != tc.wantSigs {
				t.Fatalf("got %d signatures, want %d", len(sigs), tc.wantSigs)
			}
			got := paths(sigs[0])
			if len(got) == 0 && len(tc.wantPaths) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.wantPaths) {
				t.Errorf("params = %v, want %v", got, tc.wantPaths)
			}
		})
	}
}

// A conditional schema has no single parameter list: record_id exists only
// under action=get and vendor_id only under action=search, and they can never
// appear in the same call. This is the shape a top-level reader collapses into
// three parameters and an opaque empty object.
func TestConditionalBranchesBecomeSeparateSignatures(t *testing.T) {
	schema := `{"type":"object",
	  "properties":{
	    "action":{"type":"string","enum":["get","search","list"]},
	    "tenant_uid":{"type":"string"},
	    "params":{"type":"object"}},
	  "required":["action","tenant_uid"],
	  "allOf":[
	    {"if":{"properties":{"action":{"const":"get"}},"required":["action"]},
	     "then":{"properties":{"params":{"type":"object",
	       "properties":{"record_id":{"type":"string"}},
	       "required":["record_id"]}}}},
	    {"if":{"properties":{"action":{"const":"search"}},"required":["action"]},
	     "then":{"properties":{"params":{"type":"object",
	       "properties":{"vendor_id":{"type":"string"},
	                     "limit":{"type":"integer","default":10}}}}}},
	    {"if":{"properties":{"action":{"const":"list"}},"required":["action"]},
	     "then":{"properties":{"params":{"type":"object",
	       "properties":{"ids":{"type":"array","items":{"type":"string"}}},
	       "required":["ids"]}}}}]}`

	sigs, err := Signatures("list_records", json.RawMessage(schema))
	if err != nil {
		t.Fatalf("Signatures: %v", err)
	}
	if len(sigs) != 3 {
		t.Fatalf("got %d signatures, want 3", len(sigs))
	}

	get := findSig(t, sigs, "action", "get")
	if want := []string{"action", "tenant_uid", "params.record_id"}; !reflect.DeepEqual(paths(get), want) {
		t.Errorf("action=get params = %v, want %v", paths(get), want)
	}

	search := findSig(t, sigs, "action", "search")
	if want := []string{"action", "tenant_uid", "params.limit", "params.vendor_id"}; !reflect.DeepEqual(paths(search), want) {
		t.Errorf("action=search params = %v, want %v", paths(search), want)
	}

	// Required is a property of the signature, not of the tool.
	cid, ok := get.Param("params.record_id")
	if !ok {
		t.Fatal("params.record_id missing from action=get")
	}
	if !cid.Required {
		t.Error("params.record_id should be required under action=get")
	}
	if _, exists := search.Param("params.record_id"); exists {
		t.Error("params.record_id must not exist under action=search")
	}
}

// Origin is what makes cross-signature deduplication sound. A base parameter is
// the same parameter everywhere; a branch parameter is distinguished by its
// branch, and two branches can share a path while meaning different operations.
func TestOriginSeparatesBaseFromBranch(t *testing.T) {
	schema := `{"type":"object",
	  "properties":{"action":{"type":"string","enum":["a","b"]},"tenant_uid":{"type":"string"}},
	  "required":["action","tenant_uid"],
	  "allOf":[
	    {"if":{"properties":{"action":{"const":"a"}}},
	     "then":{"properties":{"params":{"type":"object",
	       "properties":{"from_date":{"type":"string"}}}}}},
	    {"if":{"properties":{"action":{"const":"b"}}},
	     "then":{"properties":{"params":{"type":"object",
	       "properties":{"from_date":{"type":"string"}}}}}}]}`

	sigs, err := Signatures("t", json.RawMessage(schema))
	if err != nil {
		t.Fatalf("Signatures: %v", err)
	}
	for _, s := range sigs {
		for _, p := range s.Params {
			want := OriginBase
			if p.Path == "params.from_date" {
				want = OriginBranch
			}
			if p.Origin != want {
				t.Errorf("%s: %s origin = %v, want %v", s.Select["action"], p.Path, p.Origin, want)
			}
		}
	}
}

// Each oneOf branch is its own signature, so a caller sees only the parameters
// that can legally accompany the branch's discriminator. Merging them would
// produce a call carrying both url and path, which oneOf rejects.
func TestOneOfBranchesAreMutuallyExclusive(t *testing.T) {
	schema := `{"oneOf":[
	  {"type":"object","properties":{"kind":{"const":"url"},"url":{"type":"string"}},
	   "required":["kind","url"]},
	  {"type":"object","properties":{"kind":{"const":"file"},"path":{"type":"string"}},
	   "required":["kind","path"]}]}`

	sigs, err := Signatures("fetch", json.RawMessage(schema))
	if err != nil {
		t.Fatalf("Signatures: %v", err)
	}
	if len(sigs) != 2 {
		t.Fatalf("got %d signatures, want 2", len(sigs))
	}
	urlSig := findSig(t, sigs, "kind", "url")
	if _, ok := urlSig.Param("path"); ok {
		t.Error("url branch must not expose the file branch's path parameter")
	}
	if _, ok := urlSig.Param("url"); !ok {
		t.Error("url branch is missing its own url parameter")
	}
}

// A discriminated union declared as a FIELD rather than as the whole argument
// object is the shape a union type produces when it is one property among
// several. Enumerating only root-level branches leaves the field an opaque
// object and every member inside it invisible.
func TestNestedOneOfIsEnumerated(t *testing.T) {
	schema := `{"type":"object","properties":{
	  "job_id":{"type":"string"},
	  "source":{"type":"object","oneOf":[
	    {"type":"object","properties":{"kind":{"const":"inline"},
	      "payload":{"type":"string"}},"required":["kind","payload"]},
	    {"type":"object","properties":{"kind":{"const":"remote"},
	      "remote_url":{"type":"string"}},"required":["kind","remote_url"]}]}},
	  "required":["job_id","source"]}`

	sigs, err := Signatures("submit", json.RawMessage(schema))
	if err != nil {
		t.Fatalf("Signatures: %v", err)
	}
	if len(sigs) != 2 {
		t.Fatalf("got %d signatures, want 2 (one per union member)", len(sigs))
	}

	// The nested discriminator is addressed by its full path, like any other
	// parameter, so a caller sends it without special handling.
	inline := findSig(t, sigs, "source.kind", "inline")
	if _, ok := inline.Param("source.payload"); !ok {
		t.Errorf("source.payload not discovered; params = %v", paths(inline))
	}
	if _, ok := inline.Param("source.remote_url"); ok {
		t.Error("the inline branch must not expose the remote branch's parameter")
	}

	remote := findSig(t, sigs, "source.kind", "remote")
	if _, ok := remote.Param("source.remote_url"); !ok {
		t.Errorf("source.remote_url not discovered; params = %v", paths(remote))
	}

	// The selector must survive into the built call at its nested path.
	call, _ := inline.Build(Chain{FromSchema(), FromValues(map[string]any{"job_id": "J1"})})
	call.Set("source.payload", "PAYLOAD")
	args := call.Args()
	src, ok := args["source"].(map[string]any)
	if !ok {
		t.Fatalf("source is %T, want map", args["source"])
	}
	if src["kind"] != "inline" || src["payload"] != "PAYLOAD" {
		t.Errorf("source = %#v, want {kind: inline, payload: PAYLOAD}", src)
	}
}

// A recursive $ref must terminate and must say that it was cut short. A silent
// cap is indistinguishable from having walked the whole schema.
func TestRecursiveRefTerminatesAndReportsTruncation(t *testing.T) {
	schema := `{"type":"object",
	  "properties":{"node":{"$ref":"#/$defs/Node"}},
	  "$defs":{"Node":{"type":"object","properties":{
	    "name":{"type":"string"},
	    "child":{"$ref":"#/$defs/Node"}}}}}`

	done := make(chan []Signature, 1)
	go func() {
		sigs, err := Signatures("tree", json.RawMessage(schema))
		if err != nil {
			t.Errorf("Signatures: %v", err)
		}
		done <- sigs
	}()

	sigs := <-done
	if len(sigs) != 1 {
		t.Fatalf("got %d signatures, want 1", len(sigs))
	}
	if sigs[0].Depth == 0 {
		t.Error("a recursive schema must record the depth it was truncated at")
	}
	if sigs[0].Complete() {
		t.Error("a truncated signature must not report itself complete")
	}
	if len(sigs[0].Params) == 0 {
		t.Error("truncation should still yield the parameters found before the cap")
	}
}

// additionalProperties:true means the declared parameters are a lower bound.
// Reporting full coverage on such a tool would claim a surface was tested that
// was never enumerable in the first place.
func TestOpenEndedIsReported(t *testing.T) {
	sigs, err := Signatures("t", json.RawMessage(
		`{"type":"object","properties":{"query":{"type":"string"}},"additionalProperties":true}`))
	if err != nil {
		t.Fatalf("Signatures: %v", err)
	}
	if !sigs[0].OpenEnded {
		t.Error("additionalProperties:true must set OpenEnded")
	}
	if sigs[0].Complete() {
		t.Error("an open-ended signature must not report itself complete")
	}

	closed, err := Signatures("t", json.RawMessage(
		`{"type":"object","properties":{"query":{"type":"string"}},"additionalProperties":false}`))
	if err != nil {
		t.Fatalf("Signatures: %v", err)
	}
	if closed[0].OpenEnded {
		t.Error("additionalProperties:false must not set OpenEnded")
	}
	if !closed[0].Complete() {
		t.Error("a closed, fully-walked signature should report complete")
	}
}

// Independent discriminators multiply. The product is capped, and the cap is
// recorded so a run can say what it did not cover.
func TestIndependentDiscriminatorsAreCappedAndReported(t *testing.T) {
	// Two independent conditionals, 40 branches each: 1600 combinations uncapped.
	build := func(prop string, n int) string {
		out := ""
		for i := 0; i < n; i++ {
			if i > 0 {
				out += ","
			}
			out += `{"if":{"properties":{"` + prop + `":{"const":"v` + itoa(i) + `"}}},
			          "then":{"properties":{"p` + prop + itoa(i) + `":{"type":"string"}}}}`
		}
		return out
	}
	schema := `{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}},
	  "allOf":[` + build("a", 40) + `,` + build("b", 40) + `]}`

	sigs, err := Signatures("t", json.RawMessage(schema))
	if err != nil {
		t.Fatalf("Signatures: %v", err)
	}
	if len(sigs) > maxSignatures {
		t.Errorf("got %d signatures, want at most %d", len(sigs), maxSignatures)
	}
	if !sigs[0].Truncated {
		t.Error("dropping combinations must be reported, not silent")
	}
}

// Branches testing the SAME discriminator are alternatives, not independent
// choices. Treating them as independent would multiply five branches into
// thirty-two nonsense combinations.
func TestSameDiscriminatorDoesNotMultiply(t *testing.T) {
	schema := `{"type":"object","properties":{"action":{"type":"string"}},
	  "allOf":[
	    {"if":{"properties":{"action":{"const":"a"}}},"then":{"properties":{"x":{"type":"string"}}}},
	    {"if":{"properties":{"action":{"const":"b"}}},"then":{"properties":{"y":{"type":"string"}}}},
	    {"if":{"properties":{"action":{"const":"c"}}},"then":{"properties":{"z":{"type":"string"}}}}]}`

	sigs, err := Signatures("t", json.RawMessage(schema))
	if err != nil {
		t.Fatalf("Signatures: %v", err)
	}
	if len(sigs) != 3 {
		t.Fatalf("got %d signatures, want 3 (one per action value)", len(sigs))
	}
}

// A malformed schema must be an error. Falling back to "no parameters" would
// let an unreadable tool be reported as one with nothing to test.
func TestMalformedSchemaIsAnError(t *testing.T) {
	if _, err := Signatures("t", json.RawMessage(`{"type":`)); err == nil {
		t.Error("a schema that cannot be parsed must return an error")
	}
}

// A tool with no schema takes no arguments — one signature, no parameters.
func TestEmptySchemaYieldsOneEmptySignature(t *testing.T) {
	sigs, err := Signatures("ping", nil)
	if err != nil {
		t.Fatalf("Signatures: %v", err)
	}
	if len(sigs) != 1 || len(sigs[0].Params) != 0 {
		t.Errorf("got %d signatures with %d params, want 1 with 0", len(sigs), len(sigs[0].Params))
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
