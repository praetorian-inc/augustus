package toolsig

import (
	"sort"
	"strings"
)

// Source answers one question: what value belongs in this parameter?
//
// A signature says which parameters exist; it says nothing about what to put in
// them. Most values a schema supplies itself — an enum member, a declared
// default. Some it structurally cannot: an opaque tenant or account identifier
// appears in a schema as nothing more than {"type": "string"}, and no amount of
// parsing will ever yield the value. Those must come from outside.
//
// Sources exist so that "outside" is one ordered mechanism rather than a
// per-tool table baked into each caller. Adding a new place values can come from
// is a new implementation of this interface and no change to any probe.
type Source interface {
	// Name identifies the source in output, so a finding can say where a value
	// came from and a mis-filled parameter can be traced to its origin.
	Name() string

	// Value returns the value for p, and whether this source has one.
	Value(p Param) (any, bool)
}

// Chain is an ordered list of sources. The first source with a value wins.
type Chain []Source

// Value asks each source in turn, returning the value and the name of the
// source that supplied it.
func (c Chain) Value(p Param) (val any, from string, ok bool) {
	for _, s := range c {
		if s == nil {
			continue
		}
		if v, found := s.Value(p); found {
			return v, s.Name(), true
		}
	}
	return nil, "", false
}

// --- schema ----------------------------------------------------------------

type schemaSource struct{}

// FromSchema supplies values the schema itself determines: a const, a declared
// default, or a member of an enum. It costs nothing and needs no configuration,
// so it belongs first in any chain.
func FromSchema() Source { return schemaSource{} }

func (schemaSource) Name() string { return "schema" }

// Value returns what the schema itself says the parameter holds.
//
// An enum member is chosen deterministically — the first declared value — and
// no judgement is applied to which member is "safe". That judgement is not this
// package's to make, and not a guess worth making: whether a tool may be called
// at all is declared by the server in its tool annotations and decided by the
// operator through allow_destructive and the tool allow/denylists. A tool that
// has passed those gates has been declared callable by the party that owns it,
// and every branch it exposes is in scope by that same declaration.
//
// The alternative — a local word list ranking enum members by how dangerous
// they sound — substitutes a guess for the server's own statement, makes the
// scan's behaviour unpredictable, and hides the more useful outcome: a tool
// annotated non-destructive that turns out to write is a finding, not a case to
// route around.
func (schemaSource) Value(p Param) (any, bool) {
	if p.Const != nil {
		return p.Const, true
	}
	if p.Default != nil {
		return p.Default, true
	}
	if len(p.Enum) > 0 {
		return p.Enum[0], true
	}
	return nil, false
}

// --- plain map -------------------------------------------------------------

type valuesSource struct{ v map[string]any }

// FromValues supplies values from a map keyed by leaf parameter name. It is the
// simple case: one value, matched wherever that name appears, at any depth and
// in any tool.
func FromValues(v map[string]any) Source { return valuesSource{v: v} }

func (s valuesSource) Name() string { return "values" }

func (s valuesSource) Value(p Param) (any, bool) {
	if s.v == nil {
		return nil, false
	}
	if val, ok := s.v[string(p.Path)]; ok {
		return val, true
	}
	val, ok := s.v[p.Path.Leaf()]
	return val, ok
}

// --- selector rules --------------------------------------------------------

// Rule binds a value to the parameters it matches. An empty field does not
// constrain: {Name: "tenant_uid"} matches that leaf name in every tool at any
// depth, which is the point — one declaration rather than one per tool.
type Rule struct {
	Tool  string // exact tool name
	Path  string // exact dotted path
	Name  string // exact leaf name
	Value any
}

// specificity counts the constraints a rule applies. A more specific rule wins,
// so a per-tool override beats a blanket name match without either needing to
// know about the other.
func (r Rule) specificity() int {
	n := 0
	for _, s := range []string{r.Tool, r.Path, r.Name} {
		if s != "" {
			n++
		}
	}
	return n
}

func (r Rule) matches(tool string, p Param) bool {
	if r.Tool != "" && r.Tool != tool {
		return false
	}
	if r.Path != "" && r.Path != string(p.Path) {
		return false
	}
	if r.Name != "" && r.Name != p.Path.Leaf() {
		return false
	}
	// A rule with no constraints at all would match every parameter of every
	// tool, which is never what an operator means.
	return r.specificity() > 0
}

type rulesSource struct {
	tool  string
	rules []Rule
}

// FromRules supplies values from operator-supplied selector rules, scoped to one
// tool. Rules are consulted most-specific first.
func FromRules(tool string, rules []Rule) Source {
	sorted := append([]Rule{}, rules...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].specificity() > sorted[j].specificity()
	})
	return rulesSource{tool: tool, rules: sorted}
}

func (s rulesSource) Name() string { return "config" }

func (s rulesSource) Value(p Param) (any, bool) {
	for _, r := range s.rules {
		if r.matches(s.tool, p) {
			return r.Value, true
		}
	}
	return nil, false
}

// BroadRules reports rules that match an unusually large share of parameters,
// so a caller can warn before a scan runs. A rule such as {Name: "id"} is a
// foot-gun in a way {Name: "tenant_uid"} is not, and the difference is only
// visible once the parameters are known.
func BroadRules(tool string, rules []Rule, params []Param, threshold int) []Rule {
	var broad []Rule
	for _, r := range rules {
		n := 0
		for _, p := range params {
			if r.matches(tool, p) {
				n++
			}
		}
		if n > threshold {
			broad = append(broad, r)
		}
	}
	return broad
}

// --- hook variables --------------------------------------------------------

type hookSource struct{ vars map[string]string }

// FromHookVars supplies values produced at runtime by lifecycle hooks, matched
// by upper-cased leaf name. It lets an opaque value be fetched when the scan
// starts rather than written into a configuration file that gets circulated.
func FromHookVars(vars map[string]string) Source { return hookSource{vars: vars} }

func (s hookSource) Name() string { return "hook" }

func (s hookSource) Value(p Param) (any, bool) {
	if len(s.vars) == 0 {
		return nil, false
	}
	if v, ok := s.vars[strings.ToUpper(strings.ReplaceAll(string(p.Path), ".", "_"))]; ok {
		return v, true
	}
	v, ok := s.vars[strings.ToUpper(p.Path.Leaf())]
	return v, ok
}

// --- observed --------------------------------------------------------------

type observedSource struct{ f func(Param) (any, bool) }

// FromObserved supplies values harvested from earlier responses — identifiers a
// previous call returned. It is a function rather than a map because the caller
// owns the store and decides what counts as a match for a given parameter.
func FromObserved(f func(Param) (any, bool)) Source { return observedSource{f: f} }

func (s observedSource) Name() string { return "observed" }

func (s observedSource) Value(p Param) (any, bool) {
	if s.f == nil {
		return nil, false
	}
	return s.f(p)
}

// RulesFromConfig reads operator-supplied value rules from a component's
// configuration.
//
//	values:
//	  - match: {name: "tenant_uid"}          # every tool, any depth
//	    value: "1234567890123456789"
//	  - match: {tool: "get_account", path: "params.id"}
//	    value: "..."                      # a per-tool override beats the above
//
// Binding by SELECTOR rather than by tool name is what keeps the configuration
// proportional to the target: one rule covers a value that appears in every
// tool, at whatever depth each schema puts it, instead of one entry per tool
// repeating the same value.
//
// A malformed entry is skipped rather than failing the scan: a bad rule must not
// take down a run that is useful without it.
func RulesFromConfig(cfg map[string]any) []Rule {
	raw, ok := cfg["values"].([]any)
	if !ok {
		return nil
	}
	out := make([]Rule, 0, len(raw))
	for _, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		v, hasValue := entry["value"]
		if !hasValue {
			continue
		}
		r := Rule{Value: v}
		if m, ok := entry["match"].(map[string]any); ok {
			r.Tool, _ = m["tool"].(string)
			r.Path, _ = m["path"].(string)
			r.Name, _ = m["name"].(string)
		}
		// A rule constraining nothing would match every parameter of every tool,
		// which is never what an operator means.
		if r.specificity() == 0 {
			continue
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
