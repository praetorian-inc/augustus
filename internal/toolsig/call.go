package toolsig

import (
	"fmt"
	"maps"
	"sort"
	"strings"
)

// Call is a tool call under construction.
//
// Values are held in a FLAT map keyed by Path, and the nested wire shape is
// produced once, in Args, immediately before the request. Two properties follow
// from that, and both matter:
//
//   - Set is a plain map write. Building a twenty-parameter call is twenty
//     assignments and one traversal, not twenty traversals.
//   - Clone is a shallow copy that is genuinely independent. A nested
//     representation shares its inner objects between copies, so mutating one
//     variant of a call silently mutates the other — which is how an
//     authorization test can end up sending its attack and its control to the
//     same object and reporting a pass.
type Call struct {
	sig  Signature
	kv   map[Path]any
	from map[Path]string
}

// Build fills every parameter of the signature it can, using the chain, and
// returns the call.
//
// The discriminator values that select the signature are written first and are
// not negotiable: without them the server takes a different branch, and the
// call no longer exercises what the signature describes.
//
// A required parameter no source can supply does not stop construction. The
// call is always returned, and the error is a convenience for callers that
// supply nothing further. A caller that is about to Set the parameter it is
// testing should build, set, and then check Unresolved — which reflects the
// call's current state rather than a verdict frozen at build time:
//
//	base, _ := sig.Build(chain)      // may report the parameter under test
//	c := base.Clone()
//	c.Set(p.Path, payload)
//	if miss := c.Unresolved(); len(miss) > 0 {
//	        report.Untested(sig, miss)
//	        continue
//	}
func (s Signature) Build(c Chain) (*Call, error) {
	call := &Call{
		sig:  s,
		kv:   make(map[Path]any, len(s.Params)+len(s.Select)),
		from: make(map[Path]string, len(s.Params)),
	}

	for k, v := range s.Select {
		call.kv[Path(k)] = v
		call.from[Path(k)] = "selector"
	}

	for _, p := range s.Params {
		if _, pinned := call.kv[p.Path]; pinned {
			continue // a discriminator; already fixed by the signature
		}
		if v, from, ok := c.Value(p); ok {
			call.kv[p.Path] = v
			call.from[p.Path] = from
		}
	}

	if miss := call.Unresolved(); len(miss) > 0 {
		return call, &UnresolvedError{Tool: s.Tool, Params: miss}
	}
	return call, nil
}

// UnresolvedError reports required parameters that no source could supply.
//
// It is a distinct type so a caller can tell this apart from a transport or
// protocol failure: the target was never exercised, and the correct report is
// that the parameter was not tested — not that the tool is safe.
type UnresolvedError struct {
	Tool   string
	Params []Param
}

func (e *UnresolvedError) Error() string {
	names := make([]string, 0, len(e.Params))
	for _, p := range e.Params {
		names = append(names, string(p.Path))
	}
	sort.Strings(names)
	return fmt.Sprintf("toolsig: %s: no source supplied required parameter(s): %s",
		e.Tool, strings.Join(names, ", "))
}

// Signature returns the signature this call was built from.
func (c *Call) Signature() Signature { return c.sig }

// Set assigns a value at path, overwriting whatever the chain supplied. It is
// how a caller places the value it is actually testing.
func (c *Call) Set(p Path, v any) {
	if c.kv == nil {
		c.kv = map[Path]any{}
	}
	c.kv[p] = v
	if c.from == nil {
		c.from = map[Path]string{}
	}
	c.from[p] = "caller"
}

// Get returns the value currently held at path.
func (c *Call) Get(p Path) (any, bool) {
	v, ok := c.kv[p]
	return v, ok
}

// Clone returns an independent copy. Because the representation is flat,
// maps.Clone is sufficient: there are no nested containers to share.
//
// Callers rely on this for two things — cheap per-payload copies of a prepared
// benign call, and genuinely independent variants of one call, such as an
// attack and the control it is compared against.
func (c *Call) Clone() *Call {
	return &Call{
		sig:  c.sig,
		kv:   maps.Clone(c.kv),
		from: maps.Clone(c.from),
	}
}

// Args renders the nested argument object to send.
//
// Paths are written shallowest-first so that a specific value survives a more
// general one: if both "params" and "params.id" are set, the object is created
// first and the member written into it, rather than the object replacing it.
func (c *Call) Args() map[string]any {
	out := map[string]any{}
	paths := make([]Path, 0, len(c.kv))
	for p := range c.kv {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool {
		di, dj := paths[i].Depth(), paths[j].Depth()
		if di != dj {
			return di < dj
		}
		return paths[i] < paths[j]
	})
	for _, p := range paths {
		setPath(out, p, c.kv[p])
	}
	return out
}

// Unresolved lists required parameters that currently hold no value — neither
// supplied by a source nor set by the caller.
//
// It is computed from the call's present state, so a caller that sets the
// parameter it is testing sees it disappear from this list. A non-empty result
// means any verdict drawn from this call describes the scanner's reach rather
// than the target's security, and the correct report is that those parameters
// were not tested.
func (c *Call) Unresolved() []Param {
	var out []Param
	for _, p := range c.sig.Params {
		if !p.Required {
			continue
		}
		if _, ok := c.kv[p.Path]; !ok {
			out = append(out, p)
		}
	}
	return out
}

// Provenance maps each parameter to the source that supplied its value:
// "schema", "config", "hook", "observed", "values", "selector" or "caller".
// It makes a finding able to say where a value came from, and a wrongly filled
// parameter traceable without rerunning the scan.
func (c *Call) Provenance() map[Path]string { return maps.Clone(c.from) }

// Validate checks the rendered arguments against the tool's own schema. A
// failure here is a candidate that should never become a request.
func (c *Call) Validate() error { return c.sig.Validate(c.Args()) }
