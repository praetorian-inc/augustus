// Package toolsig reads an MCP tool's JSON Schema and reports what the tool can
// actually be called with.
//
// The MCP specification returns a tool's inputSchema as an arbitrary JSON
// Schema, and JSON Schema permits nesting, $ref composition, allOf/anyOf/oneOf
// and if/then conditionals. A reader that looks only at top-level "properties"
// is therefore wrong for a whole class of servers — and wrong silently, because
// the call it builds is rejected during argument validation and the tool is
// recorded as having been tested.
//
// This package answers two questions for any schema the specification allows:
//
//	Signatures  — which concrete calls does this tool accept?
//	Call        — what arguments make up one of those calls?
//
// A tool whose parameters depend on a discriminator has more than one call
// SIGNATURE, and they are not interchangeable: a parameter required under one
// discriminator value may not exist under another. That is why discovery cannot
// return a flat []Param — the grouping is a property of the schema, not a
// convenience.
//
// The package deliberately knows JSON Schema and nothing about attacks. There
// is no notion of a payload, an injectable parameter or a URL. Callers keep
// their own policy, which is what lets recon and every probe family share one
// implementation.
package toolsig

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
)

const (
	// maxDepth bounds object nesting during flattening. Six is far beyond any
	// shape observed in practice and exists to make a pathological or recursive
	// schema terminate. Hitting it is recorded on the Signature, never applied
	// silently.
	maxDepth = 6

	// maxSignatures bounds the combinations produced when a tool carries several
	// independent discriminators, whose product would otherwise grow without
	// limit. Truncation is reported.
	maxSignatures = 64
)

// Signature is one concrete way to call a tool: the discriminator values that
// select it, and the parameters valid under that selection.
type Signature struct {
	// Tool is the tool's name, carried so a caller iterating signatures from
	// several tools does not have to track it separately.
	Tool string

	// Select holds the discriminator values that choose this signature — the
	// const values from the if/oneOf branch it came from. A tool with no
	// conditionals yields one signature with an empty Select.
	//
	// These are values the caller MUST send: they are what make the call match
	// this signature rather than another.
	Select map[string]any

	// Params are the leaf parameters valid under this signature, in a stable
	// order.
	Params []Param

	// OpenEnded reports that the schema accepts properties it does not declare
	// (additionalProperties is not false). Params is then a lower bound on the
	// surface, and a caller must not report full coverage.
	OpenEnded bool

	// Depth is the nesting level at which flattening was truncated, or 0 when
	// the walk completed. Non-zero means Params is a lower bound.
	Depth int

	// Truncated reports that sibling signatures were dropped to stay within
	// maxSignatures. Set on every signature of the affected tool.
	Truncated bool

	// resolved is the tool's schema prepared for validation. It is shared by all
	// signatures of one tool and used by Validate.
	resolved *jsonschema.Resolved
}

// Complete reports whether this signature describes the whole parameter surface
// — neither open-ended nor truncated. A caller reporting coverage should say so
// only when this is true.
func (s Signature) Complete() bool {
	return !s.OpenEnded && s.Depth == 0 && !s.Truncated
}

// Validate checks an argument map against the tool's schema, using the schema's
// own semantics rather than a reimplementation of them. It is the gate that
// keeps a malformed candidate from becoming a request.
//
// A nil resolved schema (a Signature built by hand in a test) validates
// everything, so Validate is never the reason a call is not attempted.
func (s Signature) Validate(args map[string]any) error {
	if s.resolved == nil {
		return nil
	}
	return s.resolved.Validate(args)
}

// Param returns the parameter at path, and whether it exists in this signature.
func (s Signature) Param(path Path) (Param, bool) {
	for _, p := range s.Params {
		if p.Path == path {
			return p, true
		}
	}
	return Param{}, false
}

// Signatures enumerates the concrete calls a tool's schema permits.
//
// An empty or absent schema yields a single signature with no parameters, which
// is the correct description of a tool that takes no arguments. A schema that
// cannot be parsed is an error: guessing at a shape we failed to read is how a
// scan comes to report on a surface it never saw.
func Signatures(tool string, raw json.RawMessage) ([]Signature, error) {
	if len(raw) == 0 {
		return []Signature{{Tool: tool, Select: map[string]any{}}}, nil
	}

	var root jsonschema.Schema
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("toolsig: %s: parse schema: %w", tool, err)
	}

	// Resolve prepares the schema for validation. Its internal reference
	// resolution is not reachable from outside the package, so traversal below
	// follows $ref itself against $defs; this call exists for Validate.
	resolved, err := root.Resolve(nil)
	if err != nil {
		// A schema we cannot prepare for validation is still worth enumerating —
		// we simply lose the local gate. Losing the gate is not a reason to lose
		// the parameters.
		resolved = nil
	}

	r := &refs{root: &root}
	combos, truncated := enumerate(&root, r)

	baseOnly := &jsonschema.Schema{
		Type:                 root.Type,
		Properties:           root.Properties,
		Required:             root.Required,
		AdditionalProperties: root.AdditionalProperties,
	}

	basePaths := map[Path]bool{}
	for _, p := range flatten(baseOnly, r) {
		basePaths[p.Path] = true
	}

	out := make([]Signature, 0, len(combos))
	for _, c := range combos {
		// Root-level branches are merged up front; branches that apply deeper in
		// the tree are handed to the flattener, which applies each as it reaches
		// the property it belongs to.
		merged := mergeAll(&root, c.at[""])

		f := newFlattener(r)
		f.overlay = c.at
		params := f.run(merged)
		for i := range params {
			if !basePaths[params[i].Path] {
				params[i].Origin = OriginBranch
			}
		}

		sig := Signature{
			Tool:      tool,
			Select:    c.sel,
			Params:    params,
			OpenEnded: openEnded(merged),
			Depth:     f.truncatedAt,
			Truncated: truncated,
			resolved:  resolved,
		}
		if sig.Select == nil {
			sig.Select = map[string]any{}
		}
		out = append(out, sig)
	}
	return out, nil
}

// --- reference resolution -------------------------------------------------

// refs resolves local $ref pointers against the root schema's $defs. Remote
// references are deliberately not followed: a scanner fetching a URL named by
// its target's schema is an outbound request the operator did not ask for.
type refs struct{ root *jsonschema.Schema }

// deref follows s.Ref while it names a local definition, returning the schema it
// ultimately points at. A pointer it cannot resolve yields s unchanged, so an
// unreadable reference costs one parameter rather than the whole tool.
//
// The seen set terminates reference cycles. This is load-bearing: the library
// resolves cycles internally but does not expose the result, so this walk
// follows raw Ref strings and would otherwise not terminate.
func (r *refs) deref(s *jsonschema.Schema) *jsonschema.Schema {
	seen := map[*jsonschema.Schema]bool{}
	for s != nil && s.Ref != "" {
		if seen[s] {
			return s
		}
		seen[s] = true
		next := r.lookup(s.Ref)
		if next == nil || next == s {
			return s
		}
		s = next
	}
	return s
}

// lookup resolves a JSON pointer of the form "#/$defs/Name" or
// "#/definitions/Name", including nested pointers such as
// "#/$defs/A/properties/b".
func (r *refs) lookup(ref string) *jsonschema.Schema {
	if !strings.HasPrefix(ref, "#/") {
		return nil
	}
	cur := r.root
	for _, tok := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		if cur == nil {
			return nil
		}
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch tok {
		case "$defs":
			cur = pick(cur.Defs, nextToken(ref, "$defs"))
		case "definitions":
			cur = pick(cur.Definitions, nextToken(ref, "definitions"))
		case "properties", "items", "then", "else":
			// handled by the token that follows; nothing to do here
		default:
			if cur.Properties != nil {
				if s, ok := cur.Properties[tok]; ok {
					cur = s
					continue
				}
			}
			if cur.Defs != nil {
				if s, ok := cur.Defs[tok]; ok {
					cur = s
					continue
				}
			}
			if cur.Definitions != nil {
				if s, ok := cur.Definitions[tok]; ok {
					cur = s
					continue
				}
			}
		}
	}
	return cur
}

func pick(m map[string]*jsonschema.Schema, name string) *jsonschema.Schema {
	if m == nil {
		return nil
	}
	return m[name]
}

// nextToken returns the pointer token that follows key.
func nextToken(ref, key string) string {
	parts := strings.Split(strings.TrimPrefix(ref, "#/"), "/")
	for i, p := range parts {
		if p == key && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// --- branch enumeration ---------------------------------------------------

// combo is one selection of branches: the discriminator values that identify it
// and the schemas those branches contribute, keyed by the path they apply at.
//
// Branches are not only a root-level construct. A property whose own schema
// carries a oneOf — the shape a discriminated union produces when it appears as
// a field rather than as the whole argument object — is a branch point at that
// property's path, and its alternatives multiply signatures exactly as a
// root-level one does. Selector keys are therefore dotted paths, so a nested
// discriminator is addressed the same way any other parameter is.
type combo struct {
	sel map[string]any
	// at maps a path to the branch schemas chosen there. The empty path is the
	// root; anything else is applied when flattening reaches that property.
	at map[Path][]*jsonschema.Schema
}

func (c combo) with(at Path, sel map[string]any, branches []*jsonschema.Schema) combo {
	next := combo{
		sel: make(map[string]any, len(c.sel)+len(sel)),
		at:  make(map[Path][]*jsonschema.Schema, len(c.at)+1),
	}
	for k, v := range c.sel {
		next.sel[k] = v
	}
	for k, v := range sel {
		next.sel[k] = v
	}
	for k, v := range c.at {
		next.at[k] = append([]*jsonschema.Schema{}, v...)
	}
	next.at[at] = append(next.at[at], branches...)
	return next
}

// alternatives is a set of mutually exclusive branches at one point in the
// schema. Exactly one is chosen per combination.
type alternatives struct {
	at    Path
	choix []struct {
		sel      map[string]any
		branches []*jsonschema.Schema
	}
}

func (a *alternatives) add(sel map[string]any, branches ...*jsonschema.Schema) {
	a.choix = append(a.choix, struct {
		sel      map[string]any
		branches []*jsonschema.Schema
	}{sel, branches})
}

// enumerate produces every combination of branches the schema offers, capped at
// maxSignatures. The bool reports whether the cap dropped combinations.
//
// Conditionals are grouped by the property they discriminate on: two if/then
// clauses testing action=get and action=search are alternatives, not
// independent choices, so they must not multiply. Clauses testing different
// properties are independent and do multiply.
func enumerate(s *jsonschema.Schema, r *refs) ([]combo, bool) {
	groups := branchPoints(s, "", r, map[*jsonschema.Schema]bool{}, 1)

	out := []combo{{sel: map[string]any{}, at: map[Path][]*jsonschema.Schema{}}}
	truncated := false
	for _, g := range groups {
		next := make([]combo, 0, len(out)*len(g.choix))
		for _, base := range out {
			for _, alt := range g.choix {
				if len(next) >= maxSignatures {
					truncated = true
					break
				}
				next = append(next, base.with(g.at, alt.sel, alt.branches))
			}
			if truncated {
				break
			}
		}
		if len(next) > 0 {
			out = next
		}
	}
	return out, truncated
}

// branchPoints collects every point in the schema tree that offers a choice of
// branches, walking into object properties so a discriminated union declared as
// a field is found as readily as one declared at the root.
//
// The seen set and depth bound make this safe on a recursive schema: a branch
// point reached through a $ref cycle is not re-expanded.
func branchPoints(s *jsonschema.Schema, prefix Path, r *refs, seen map[*jsonschema.Schema]bool, depth int) []alternatives {
	if s == nil || depth > maxDepth || seen[s] {
		return nil
	}
	seen[s] = true
	defer delete(seen, s)

	var groups []alternatives

	// if/then conditionals, grouped by the property they discriminate on:
	// clauses testing the same property are alternatives and must not multiply,
	// while clauses testing different properties are independent and do.
	byDiscriminator := map[string]*alternatives{}
	var order []string
	for _, c := range conditionals(s) {
		sel := prefixSel(prefix, selectorOf(c.If))
		key := discriminatorKey(sel)
		if key == "" {
			// A conditional whose discriminator we cannot read applies
			// unconditionally: keep its contribution rather than dropping it.
			g := alternatives{at: prefix}
			if c.Then != nil {
				g.add(map[string]any{}, r.deref(c.Then))
			}
			if c.Else != nil {
				g.add(map[string]any{}, r.deref(c.Else))
			}
			groups = append(groups, g)
			continue
		}
		if _, ok := byDiscriminator[key]; !ok {
			byDiscriminator[key] = &alternatives{at: prefix}
			order = append(order, key)
		}
		if c.Then != nil {
			byDiscriminator[key].add(sel, r.deref(c.Then))
		}
		// The else branch is the operation taken when the condition does NOT
		// hold. Its parameters are as real as the then branch's, and dropping
		// them removes an entire operation from every signature while the scan
		// still reports as complete.
		//
		// Its selector is a negation, which a map of fixed values cannot express,
		// so it carries none: the discriminator is left to the value chain, which
		// picks a declared member. That reaches the else operation whenever the
		// enum has a member the condition does not pin — the ordinary case — and
		// where it does not, the parameters are still discovered and reported
		// rather than silently absent.
		if c.Else != nil {
			byDiscriminator[key].add(map[string]any{}, r.deref(c.Else))
		}
	}
	for _, k := range order {
		groups = append(groups, *byDiscriminator[k])
	}

	// oneOf / anyOf branches are alternatives among themselves.
	for _, set := range [][]*jsonschema.Schema{s.OneOf, s.AnyOf} {
		if len(set) == 0 {
			continue
		}
		g := alternatives{at: prefix}
		for _, b := range set {
			b = r.deref(b)
			g.add(prefixSel(prefix, selectorOf(b)), b)
		}
		groups = append(groups, g)
	}

	// allOf entries without a conditional apply unconditionally: a single
	// alternative, so they contribute without multiplying.
	var always []*jsonschema.Schema
	for _, a := range s.AllOf {
		if a == nil || a.If != nil {
			continue
		}
		always = append(always, r.deref(a))
	}
	if len(always) > 0 {
		g := alternatives{at: prefix}
		g.add(map[string]any{}, always...)
		groups = append(groups, g)
	}

	// Recurse into object properties and array elements.
	for _, name := range sortedKeys(s.Properties) {
		sub := r.deref(s.Properties[name])
		if sub == nil {
			continue
		}
		path := prefix.Child(name)
		if typeOf(sub) == "array" && sub.Items != nil {
			groups = append(groups, branchPoints(r.deref(sub.Items), path.Index(0), r, seen, depth+1)...)
			continue
		}
		groups = append(groups, branchPoints(sub, path, r, seen, depth+1)...)
	}
	return groups
}

// prefixSel rewrites a branch's selector keys as full paths, so a discriminator
// nested inside an object is addressed the same way every other parameter is.
func prefixSel(prefix Path, sel map[string]any) map[string]any {
	if prefix == "" {
		return sel
	}
	out := make(map[string]any, len(sel))
	for k, v := range sel {
		out[string(prefix.Child(k))] = v
	}
	return out
}

// conditional pairs an if with its then.
type conditional struct{ If, Then, Else *jsonschema.Schema }

// conditionals collects if/then pairs from the schema itself and from its allOf
// entries, which is where servers most often place them.
func conditionals(s *jsonschema.Schema) []conditional {
	var out []conditional
	if s.If != nil && (s.Then != nil || s.Else != nil) {
		out = append(out, conditional{s.If, s.Then, s.Else})
	}
	for _, a := range s.AllOf {
		if a != nil && a.If != nil && (a.Then != nil || a.Else != nil) {
			out = append(out, conditional{a.If, a.Then, a.Else})
		}
	}
	return out
}

// selectorOf reads the fixed property values a branch condition pins down —
// {"action": "get"} from {"properties": {"action": {"const": "get"}}}. These are
// what a caller must send for the branch to apply.
func selectorOf(cond *jsonschema.Schema) map[string]any {
	sel := map[string]any{}
	if cond == nil {
		return sel
	}
	for name, p := range cond.Properties {
		if p == nil {
			continue
		}
		if p.Const != nil {
			sel[name] = *p.Const
			continue
		}
		if len(p.Enum) == 1 {
			sel[name] = p.Enum[0]
		}
	}
	return sel
}

// discriminatorKey identifies which properties a selector constrains, so that
// branches testing the same property are recognised as alternatives.
func discriminatorKey(sel map[string]any) string {
	if len(sel) == 0 {
		return ""
	}
	keys := make([]string, 0, len(sel))
	for k := range sel {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// --- merging --------------------------------------------------------------

// mergeAll folds every chosen branch onto the base schema.
func mergeAll(base *jsonschema.Schema, branches []*jsonschema.Schema) *jsonschema.Schema {
	out := shallow(base)
	for _, b := range branches {
		out = merge(out, b)
	}
	return out
}

// shallow copies the fields flattening reads, leaving composition keywords
// behind: they have already been consumed by enumeration, and carrying them
// would make a merged branch's own conditionals reapply.
func shallow(s *jsonschema.Schema) *jsonschema.Schema {
	if s == nil {
		return &jsonschema.Schema{}
	}
	out := &jsonschema.Schema{
		Type:                 s.Type,
		Types:                s.Types,
		Required:             append([]string{}, s.Required...),
		AdditionalProperties: s.AdditionalProperties,
		Items:                s.Items,
		Enum:                 s.Enum,
		Const:                s.Const,
		Default:              s.Default,
		Description:          s.Description,
		Ref:                  s.Ref,
		Defs:                 s.Defs,
		Definitions:          s.Definitions,
	}
	if s.Properties != nil {
		out.Properties = make(map[string]*jsonschema.Schema, len(s.Properties))
		for k, v := range s.Properties {
			out.Properties[k] = v
		}
	}
	return out
}

// merge folds overlay onto base, recursing into properties so a branch that
// supplies only the inner members of an object does not discard the outer one.
func merge(base, overlay *jsonschema.Schema) *jsonschema.Schema {
	if overlay == nil {
		return base
	}
	out := shallow(base)
	if overlay.Type != "" {
		out.Type = overlay.Type
	}
	if overlay.Items != nil {
		out.Items = overlay.Items
	}
	if overlay.Enum != nil {
		out.Enum = overlay.Enum
	}
	if overlay.Const != nil {
		out.Const = overlay.Const
	}
	if overlay.Default != nil {
		out.Default = overlay.Default
	}
	if overlay.Description != "" {
		out.Description = overlay.Description
	}
	if overlay.AdditionalProperties != nil {
		out.AdditionalProperties = overlay.AdditionalProperties
	}
	for _, req := range overlay.Required {
		if !contains(out.Required, req) {
			out.Required = append(out.Required, req)
		}
	}
	if overlay.Properties != nil {
		if out.Properties == nil {
			out.Properties = map[string]*jsonschema.Schema{}
		}
		for name, sub := range overlay.Properties {
			if existing, ok := out.Properties[name]; ok {
				out.Properties[name] = merge(existing, sub)
				continue
			}
			out.Properties[name] = sub
		}
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// openEnded reports whether the schema admits properties it does not declare.
// JSON Schema's default is permissive, but a tool schema that declares
// properties and says nothing about additional ones is in practice generated by
// an SDK that rejects extras, so only an explicit non-false setting counts.
func openEnded(s *jsonschema.Schema) bool {
	ap := s.AdditionalProperties
	if ap == nil {
		return len(s.Properties) == 0
	}
	// A false schema is encoded as one that matches nothing.
	if ap.Not != nil && isEmptySchema(ap.Not) {
		return false
	}
	return !isFalseSchema(ap)
}

func isEmptySchema(s *jsonschema.Schema) bool {
	return s != nil && s.Type == "" && len(s.Types) == 0 && s.Properties == nil && s.Not == nil
}

func isFalseSchema(s *jsonschema.Schema) bool {
	// jsonschema-go models `false` as a schema whose Not is the empty schema.
	return s != nil && s.Not != nil && isEmptySchema(s.Not)
}

// --- flattening -----------------------------------------------------------

// flattener walks a merged schema into leaf parameters, bounded in depth and
// safe against reference cycles.
type flattener struct {
	r   *refs
	out []Param
	// overlay carries the branch schemas chosen at each nested path, applied
	// when the walk reaches that property. A branch declared inside a field
	// cannot be merged up front, because which one applies is a per-signature
	// choice and the property may not exist until an outer branch is merged.
	overlay     map[Path][]*jsonschema.Schema
	seen        map[*jsonschema.Schema]int
	truncatedAt int
}

func newFlattener(r *refs) *flattener {
	return &flattener{r: r, seen: map[*jsonschema.Schema]int{}}
}

func flatten(s *jsonschema.Schema, r *refs) []Param {
	f := newFlattener(r)
	return f.run(s)
}

func (f *flattener) run(s *jsonschema.Schema) []Param {
	f.walk(s, "", 1)
	sort.Slice(f.out, func(i, j int) bool { return f.out[i].Path < f.out[j].Path })
	return f.out
}

// walk emits a Param for every leaf reachable from s.
func (f *flattener) walk(s *jsonschema.Schema, prefix Path, depth int) {
	if s == nil {
		return
	}
	if depth > maxDepth {
		if f.truncatedAt == 0 || depth < f.truncatedAt {
			f.truncatedAt = depth
		}
		return
	}
	s = f.r.deref(s)

	// A schema reached twice on the same walk is a cycle. Record the depth so
	// the truncation is reported rather than silently applied.
	if n, ok := f.seen[s]; ok && n <= depth {
		if f.truncatedAt == 0 || depth < f.truncatedAt {
			f.truncatedAt = depth
		}
		return
	}
	f.seen[s] = depth
	defer delete(f.seen, s)

	required := map[string]bool{}
	for _, r := range s.Required {
		required[r] = true
	}

	for _, name := range sortedKeys(s.Properties) {
		sub := f.r.deref(s.Properties[name])
		if sub == nil {
			continue
		}
		path := prefix.Child(name)
		f.emit(sub, path, required[name], depth)
	}
}

// emit records one property, recursing when it contains further parameters.
func (f *flattener) emit(sub *jsonschema.Schema, path Path, req bool, depth int) {
	// Apply any branch chosen at this path before deciding what the property is:
	// a field declared as a bare object may gain all of its members from the
	// branch, and without this it would be emitted as an opaque empty object.
	if branches := f.overlay[path]; len(branches) > 0 {
		sub = mergeAll(sub, branches)
	}
	switch {
	case typeOf(sub) == "object" && len(sub.Properties) > 0:
		f.walk(sub, path, depth+1)

	case typeOf(sub) == "array" && sub.Items != nil:
		items := f.r.deref(sub.Items)
		if typeOf(items) == "object" && len(items.Properties) > 0 {
			// Address the first element: a probe exercising an array of objects
			// needs one concrete element, not a description of the element type.
			f.walk(items, path.Index(0), depth+1)
			return
		}
		f.out = append(f.out, paramFrom(sub, path, req, typeOf(items)))

	default:
		f.out = append(f.out, paramFrom(sub, path, req, ""))
	}
}

func paramFrom(s *jsonschema.Schema, path Path, req bool, items string) Param {
	p := Param{
		Path:     path,
		Type:     typeOf(s),
		Items:    items,
		Required: req,
		Enum:     enumStrings(s),
		Default:  defaultValue(s),
		Doc:      s.Description,
		Origin:   OriginBase,
	}
	if s.Const != nil {
		p.Const = *s.Const
	}
	return p
}

// defaultValue decodes a declared default into a plain Go value.
//
// Schema.Default is a json.RawMessage, and a nil RawMessage stored in an `any`
// field is NOT a nil interface — it is a non-nil interface holding a nil slice.
// Returning it directly would make every parameter appear to carry a default,
// and that default would then be sent as a JSON null-ish value the server
// rejects. Decode explicitly, and only when there is something to decode.
func defaultValue(s *jsonschema.Schema) any {
	if len(s.Default) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(s.Default, &v); err != nil {
		return nil
	}
	return v
}

func typeOf(s *jsonschema.Schema) string {
	if s == nil {
		return ""
	}
	if s.Type != "" {
		return s.Type
	}
	// A union type is reported as its first non-null member: a caller needs one
	// concrete type to synthesise a value.
	for _, t := range s.Types {
		if t != "null" {
			return t
		}
	}
	return ""
}

// enumStrings renders a declared enum as strings, keeping numeric and boolean
// members that a caller could still send.
func enumStrings(s *jsonschema.Schema) []string {
	if len(s.Enum) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.Enum))
	for _, v := range s.Enum {
		switch t := v.(type) {
		case string:
			if t != "" {
				out = append(out, t)
			}
		case bool:
			out = append(out, strconv.FormatBool(t))
		case float64:
			out = append(out, strconv.FormatFloat(t, 'f', -1, 64))
		case json.Number:
			out = append(out, t.String())
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sortedKeys(m map[string]*jsonschema.Schema) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
