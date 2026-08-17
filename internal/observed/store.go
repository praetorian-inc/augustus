// Package observed records the values a scan has seen in tool responses so
// that a value returned by one tool can fill a parameter of another.
//
// Servers routinely require values no schema declares and no caller can invent:
// an account identifier, a room id, a job reference. Those values do exist —
// the server hands them out in the responses to its own listing tools — but
// only a caller that remembers what it read can use them. Without that memory a
// probe fills the parameter with a placeholder, the server rejects the call,
// and the tool is recorded as tested.
//
// # Identity
//
// Every value records the identity whose session observed it, and Source
// returns only what THAT identity saw. Crossing identities is a separate,
// explicitly named call.
//
// This is the package's load-bearing safety property, not a nicety. An
// authorization probe works by replaying one identity's object identifier under
// another identity's session. If ordinary calls could be auto-filled with
// another identity's values, the scanner would manufacture cross-identity
// access out of its own plumbing — inventing findings that are artefacts, and
// masking real ones by making every call look cross-identity. Crossing must be
// something a probe does deliberately.
package observed

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/praetorian-inc/augustus/internal/toolsig"
	"github.com/praetorian-inc/augustus/pkg/types"
)

const (
	// maxPerKey bounds how many distinct values are kept for one key. A listing
	// tool can return thousands of rows; a handful of identifiers is enough to
	// fill a parameter, and the rest is memory a scan does not need.
	maxPerKey = 8
	// maxKeys bounds the number of distinct keys tracked across a scan.
	maxKeys = 4096
	// maxStringLen skips values too long to be an identifier or a discriminator.
	// Prose, documents and encoded blobs are not what this store is for, and
	// sending one into a parameter is not a test of anything.
	maxStringLen = 512
	// maxDepth bounds the response walk. Deeply nested payloads are traversed to
	// a sane limit rather than unboundedly.
	maxDepth = 12
)

// Value is one scalar seen in a tool response.
type Value struct {
	// Key is the JSON key the value appeared under.
	Key string
	// Parent is the enclosing key, which is what lets a generic "id" inside a
	// "contracts" array satisfy a parameter named "record_id".
	Parent string
	// V is the value itself: a string, number or bool.
	V any
	// Tool is the tool whose response produced it.
	Tool string
	// Identity is the identity whose session observed it.
	Identity string
	// Seq orders values by when they were seen, so the most recent wins.
	Seq int
}

// Store holds the values a scan has observed. The zero value is not usable;
// call New. A Store is safe for concurrent use.
type Store struct {
	mu    sync.RWMutex
	byKey map[string][]Value
	seq   int
}

func New() *Store { return &Store{byKey: make(map[string][]Value)} }

// Record walks a tool result and remembers the scalars it contains.
//
// Text is preferred over Raw: for an MCP result Raw is the protocol envelope
// with the payload nested as an escaped string, so walking it would find the
// envelope's own keys rather than the object the tool returned.
//
// Prefer RecordCall: without the arguments that produced the response there is
// no way to tell what the server KNOWS from what the scanner just told it.
func (s *Store) Record(identity, tool string, res types.ToolResult) {
	s.RecordCall(identity, tool, nil, res)
}

// RecordCall records a response and ignores the values the caller just SENT.
//
// A response that repeats an argument back is not telling us anything. Many
// servers echo their input — as a confirmation block, in a validation message,
// or in the object they return — and without this the store fills up with the
// scanner's own placeholders and sentinels. Since the most recently seen value
// wins, that junk then OUTRANKS the identifiers the target actually handed out.
//
// Measured live: after one reconnaissance pass, the store's answer for
// "tenant_id" was the deliberately-nonexistent sentinel recon uses to establish
// a not-found baseline, and its answer for "object_id" was a tenant identifier
// that recon had tried in that slot. Both had been echoed straight back. Every
// probe that followed built its calls out of them.
//
// An echo is matched on the argument's own NAME as well as its value, so a value
// the server returns under a DIFFERENT key than the one it was sent under is
// kept: that repetition is the server saying something (this object's owner is
// the tenant you asked as), rather than repeating what it was told.
func (s *Store) RecordCall(identity, tool string, sent map[string]any, res types.ToolResult) {
	root, ok := decode(res.Raw, res.Text)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.walk(root, "", "", identity, tool, 1, echoesOf(sent))
}

// echoesOf renders the arguments of a call as the set of (key, value) pairs that
// would be an echo if they came back.
func echoesOf(sent map[string]any) map[string]bool {
	if len(sent) == 0 {
		return nil
	}
	out := map[string]bool{}
	for path, v := range toolsig.FlattenArgs(sent) {
		if !usable(v) {
			continue
		}
		out[echoKey(path.Leaf(), v)] = true
	}
	return out
}

func echoKey(key string, v any) string {
	return normalize(key) + "\x00" + fmt.Sprint(v)
}

func (s *Store) walk(v any, key, parent, identity, tool string, depth int, echoes map[string]bool) {
	if depth > maxDepth {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		// Sorted so a scan is reproducible: Go map iteration order is randomised,
		// and the sequence numbers below would otherwise differ between runs.
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			s.walk(t[k], k, key, identity, tool, depth+1, echoes)
		}
	case []any:
		// An array element inherits its container's key, so items of "contracts"
		// are seen as belonging to "contracts" rather than to nothing.
		for _, e := range t {
			s.walk(e, key, parent, identity, tool, depth+1, echoes)
		}
	default:
		if echoes[echoKey(key, v)] {
			return // the caller sent this; the server is repeating, not telling
		}
		s.record(key, parent, v, identity, tool)
	}
}

func (s *Store) record(key, parent string, v any, identity, tool string) {
	if key == "" || !usable(v) {
		return
	}
	norm := normalize(key)
	if _, exists := s.byKey[norm]; !exists && len(s.byKey) >= maxKeys {
		return
	}
	vals := s.byKey[norm]
	for _, existing := range vals {
		if existing.V == v && existing.Identity == identity && existing.Parent == parent {
			return // already known from this identity in this position
		}
	}
	s.seq++
	vals = append(vals, Value{
		Key: key, Parent: parent, V: v, Tool: tool, Identity: identity, Seq: s.seq,
	})
	// The cap is per (key, IDENTITY), not per key.
	//
	// Identities are recorded one session after another, so a shared cap lets the
	// last session seen evict everything the first recorded under the same key.
	// The primary identity's values would vanish because a victim session
	// happened to return eight of its own, and Source("primary") would then have
	// nothing to offer — an empty result caused entirely by scan ordering.
	s.byKey[norm] = capPerIdentity(vals, identity)
}

// capPerIdentity drops the oldest values belonging to the given identity once it
// exceeds the cap, leaving every other identity's history untouched.
func capPerIdentity(vals []Value, identity string) []Value {
	n := 0
	for _, v := range vals {
		if v.Identity == identity {
			n++
		}
	}
	if n <= maxPerKey {
		return vals
	}
	drop := n - maxPerKey
	out := make([]Value, 0, len(vals)-drop)
	for _, v := range vals {
		if drop > 0 && v.Identity == identity {
			drop--
			continue
		}
		out = append(out, v)
	}
	return out
}

// usable reports whether a scalar is worth keeping as a candidate argument.
func usable(v any) bool {
	switch t := v.(type) {
	case string:
		return t != "" && len(t) <= maxStringLen
	case float64, bool, json.Number:
		return true
	default:
		return false
	}
}

// Values returns every value observed for a key, most recent first. Intended
// for tests and reporting.
func (s *Store) Values(key string) []Value {
	s.mu.RLock()
	defer s.mu.RUnlock()
	vals := s.byKey[normalize(key)]
	out := make([]Value, len(vals))
	for i := range vals {
		out[i] = vals[len(vals)-1-i]
	}
	return out
}

// Keys returns the normalised keys held, in a deterministic order.
func (s *Store) Keys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.byKey))
	for k := range s.byKey {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Len reports how many distinct keys the store holds.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byKey)
}

// --- matching --------------------------------------------------------------

// Source returns a toolsig.Source over the values IDENTITY observed.
//
// It never returns another identity's values. A probe that needs those must ask
// for them by name through SourceFrom, which is what makes a cross-identity
// test a deliberate act rather than an accident of shared state.
func (s *Store) Source(identity string) toolsig.Source {
	return &source{store: s, identity: identity}
}

// SourceFrom returns a Source over the values a DIFFERENT identity observed.
// This is the deliberate cross-identity case — replaying one identity's object
// under another's session — and it is spelled differently from Source so that
// it cannot be reached by accident.
func (s *Store) SourceFrom(identity string) toolsig.Source {
	return &source{store: s, identity: identity, crossed: true}
}

type source struct {
	store    *Store
	identity string
	crossed  bool
}

func (s *source) Name() string {
	if s.crossed {
		return "observed:" + s.identity
	}
	return "observed"
}

// Value picks the best observed value for a parameter, in strict precedence:
// an exact key match, then a case- and separator-insensitive one, then an
// entity match where a parameter named "<entity>_id" accepts a plain "id" seen
// inside a container named for that entity.
//
// Looser matching than this — any string for any string parameter — would fill
// a parameter with something arbitrary and call the result a test.
func (s *source) Value(p toolsig.Param) (any, bool) {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()

	leaf := p.Path.Leaf()
	if v, ok := s.best(s.store.byKey[normalize(leaf)], p, func(Value) bool { return true }); ok {
		return v, true
	}

	entity, isID := entityOf(leaf)
	if !isID {
		return nil, false
	}
	// A bare "id" is only meaningful when it sat inside a container named for
	// the entity the parameter wants; an "id" from anywhere would be a guess.
	return s.best(s.store.byKey["id"], p, func(v Value) bool {
		return matchesEntity(v.Parent, entity)
	})
}

// best picks the most recently observed value that belongs to this source's
// identity, is type-compatible with the parameter, and satisfies extra.
func (s *source) best(vals []Value, p toolsig.Param, extra func(Value) bool) (any, bool) {
	for i := len(vals) - 1; i >= 0; i-- {
		v := vals[i]
		if v.Identity != s.identity {
			continue
		}
		if !compatible(p.Type, v.V) {
			continue
		}
		if !extra(v) {
			continue
		}
		return v.V, true
	}
	return nil, false
}

// compatible reports whether an observed value can stand in for a parameter of
// the declared type. An unknown type accepts any scalar; a declared one is
// honoured, because sending a string where an integer is required fails
// validation and tests nothing.
func compatible(typ string, v any) bool {
	switch typ {
	case "", "string":
		_, ok := v.(string)
		if typ == "" {
			return ok || isNumber(v) || isBool(v)
		}
		return ok
	case "integer", "number":
		return isNumber(v)
	case "boolean":
		return isBool(v)
	default:
		return false
	}
}

func isNumber(v any) bool {
	switch v.(type) {
	case float64, json.Number, int, int64:
		return true
	}
	return false
}

func isBool(v any) bool { _, ok := v.(bool); return ok }

// normalize renders a key for insensitive comparison: lower case, separators
// removed. "contractId", "record_id" and "Contract-ID" all become one key.
func normalize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToLower(s) {
		if r == '_' || r == '-' || r == ' ' || r == '.' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// entityOf splits an identifier-shaped parameter name into the entity it names.
// "record_id" yields "contract"; "id" alone yields nothing, because a bare id
// names no entity to match a container against.
// minEntityLen is the shortest entity name that can be matched against a
// container. Below it the match is noise: "uid" would yield the entity "u", and
// any container whose key merely ends in that letter — "menu" — would satisfy
// it, filling the parameter with an unrelated identifier and reporting a test
// that never touched the intended object.
const minEntityLen = 3

func entityOf(name string) (string, bool) {
	n := normalize(name)
	if n == "id" || !strings.HasSuffix(n, "id") {
		return "", false
	}
	entity := strings.TrimSuffix(n, "id")
	if len(entity) < minEntityLen {
		return "", false
	}
	return entity, true
}

// matchesEntity reports whether a container key names the given entity, in
// either singular or plural form: "contract", "contracts" and "contractlist"
// all denote contracts.
func matchesEntity(parent, entity string) bool {
	if entity == "" || parent == "" {
		return false
	}
	p := normalize(parent)
	switch {
	case p == entity, p == entity+"s", p == entity+"es":
		return true
	case strings.HasSuffix(p, entity), strings.HasSuffix(p, entity+"s"):
		return true
	}
	return false
}

// decode reads a tool result into a generic JSON value, preferring the
// assembled text payload over the protocol envelope.
func decode(raw []byte, text string) (any, bool) {
	var root any
	if strings.TrimSpace(text) != "" {
		if err := json.Unmarshal([]byte(text), &root); err == nil {
			return root, true
		}
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &root); err == nil {
			return root, true
		}
	}
	return nil, false
}
