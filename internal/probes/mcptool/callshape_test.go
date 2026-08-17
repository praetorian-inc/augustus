package mcptool

import (
	"testing"

	"github.com/praetorian-inc/augustus/internal/toolsig"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func dateParams() []paramInfo {
	return []paramInfo{
		{name: "action", path: "action", typ: "string", required: true, candidates: []string{"search"}},
		{name: "from_date", path: "from_date", typ: "string"}, // optional per schema
	}
}

// The default must not change the call. A probe tests the call a client would
// make, and an argument the caller never sent is both a different test and a
// wider blast radius on a live target.
func TestWithShape_DefaultSendsOnlyRequiredParams(t *testing.T) {
	ts := sigOf(dateParams()).withShape(fillOptionalNever)
	args := ts.args(paramInfo{name: "action", path: "action"}, "PAYLOAD")

	if _, ok := args["from_date"]; ok {
		t.Errorf("from_date was sent by default; args = %v", args)
	}
	if args["action"] != "PAYLOAD" {
		t.Errorf("action = %v, want the payload", args["action"])
	}
}

func TestWithShape_AlwaysSendsOptionalParams(t *testing.T) {
	ts := sigOf(dateParams()).withShape(fillOptionalAlways)
	args := ts.args(paramInfo{name: "action", path: "action"}, "PAYLOAD")

	if _, ok := args["from_date"]; !ok {
		t.Errorf("fill_optional: always did not send the optional param; args = %v", args)
	}
	if args["action"] != "PAYLOAD" {
		t.Errorf("action = %v, want the payload", args["action"])
	}
}

// The precise answer for a parameter the server requires but the schema does
// not: name it. This needs no shape setting at all — a rule reaches an optional
// parameter — and it supplies a value the operator knows is valid rather than a
// placeholder the server will reject on format.
func TestValueRuleReachesAnOptionalParam(t *testing.T) {
	ts := sigOf(dateParams())
	ts.pre = toolsig.Chain{toolsig.FromRules("t", []toolsig.Rule{
		{Name: "from_date", Value: "2024-01-01"},
	})}

	args := ts.args(paramInfo{name: "action", path: "action"}, "PAYLOAD")
	if args["from_date"] != "2024-01-01" {
		t.Errorf("from_date = %v, want the configured value", args["from_date"])
	}
}

// A filled optional parameter is a guess, so it must be visible as one: a
// refusal of a call carrying invented values says nothing about the payload, and
// guessedArgs is what records that.
func TestWithShape_AlwaysMarksTheFilledOptionalAsInvented(t *testing.T) {
	ts := sigOf(dateParams()).withShape(fillOptionalAlways)
	call, _ := ts.sig.Build(ts.chain())

	if from := call.Provenance()["from_date"]; from != sourcePlaceholder {
		t.Errorf("from_date provenance = %q, want %q so a refusal stays unattributable",
			from, sourcePlaceholder)
	}
	guessed := ts.guessedArgs(paramInfo{name: "action", path: "action"})
	if len(guessed) == 0 {
		t.Error("a widened call's invented arguments must appear in guessedArgs")
	}
}

func TestConfigure_FillOptional(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, fillOptionalNever},
		{"always", fillOptionalAlways},
		{"never", fillOptionalNever},
		{"auto", fillOptionalNever}, // unrecognised falls back, loudly
		{"yes please", fillOptionalNever},
	}
	for _, c := range cases {
		cfg := registry.Config{}
		if c.in != nil {
			cfg["fill_optional"] = c.in
		}
		var r reconContext
		r.configure(cfg)
		if got := r.shapeMode(); got != c.want {
			t.Errorf("fill_optional=%v -> %q, want %q", c.in, got, c.want)
		}
	}
}

// A probe that never called configure must still behave like the default rather
// than like the empty string.
func TestShapeMode_UnconfiguredIsTheDefault(t *testing.T) {
	var r reconContext
	if got := r.shapeMode(); got != fillOptionalNever {
		t.Errorf("unconfigured shapeMode = %q, want %q", got, fillOptionalNever)
	}
}
