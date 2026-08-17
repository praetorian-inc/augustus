package toolsig

import (
	"strconv"
	"strings"
)

// Path locates a parameter inside a tool's argument object.
//
//	"url"                  a top-level parameter
//	"params.record_id"   nested inside an object
//	"filters[0].field"     inside the first element of an array of objects
//
// The dotted form is the same one operators already write in configuration, so
// there is no translation layer between what a rule says and what the code
// addresses. MCP parameter names come from language identifiers (both the
// Python and TypeScript SDKs derive schemas from function signatures), so a dot
// inside a key does not occur in practice; Signatures rejects one at parse time
// rather than carrying a heavier representation everywhere for a case that does
// not arise.
type Path string

// Leaf returns the final segment without its index, which is what a probe wants
// when matching a parameter by name ("url", "record_id") rather than
// addressing it.
func (p Path) Leaf() string {
	s := string(p)
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexByte(s, '['); i >= 0 {
		s = s[:i]
	}
	return s
}

// Child returns the path of a named property of p.
func (p Path) Child(name string) Path {
	if p == "" {
		return Path(name)
	}
	return p + "." + Path(name)
}

// Index returns the path of the i'th element of the array at p.
func (p Path) Index(i int) Path {
	return p + Path("["+strconv.Itoa(i)+"]")
}

// Depth reports how many object levels deep the path sits. A top-level
// parameter has depth 1.
func (p Path) Depth() int { return len(segments(string(p))) }

// segment is one step of a path: either a named key or an array index.
type segment struct {
	key   string
	index int
	isIdx bool
}

// segments splits a dotted path into its steps, treating "[N]" as an index step
// of its own. It mirrors the segmentation the REST generator already performs on
// JSONPath expressions, so the two agree on what "a[0].b" addresses.
func segments(path string) []segment {
	if path == "" {
		return nil
	}
	var out []segment
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, segment{key: cur.String()})
			cur.Reset()
		}
	}
	for i := 0; i < len(path); i++ {
		switch c := path[i]; c {
		case '.':
			flush()
		case '[':
			flush()
			j := i + 1
			for j < len(path) && path[j] != ']' {
				j++
			}
			if j >= len(path) {
				// Unterminated index: treat the remainder as a literal key so a
				// malformed path degrades to a miss rather than a panic.
				cur.WriteString(path[i:])
				i = len(path)
				continue
			}
			n, err := strconv.Atoi(path[i+1 : j])
			if err != nil {
				n = 0
			}
			out = append(out, segment{index: n, isIdx: true})
			i = j
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// setPath assigns value at path within args, creating intermediate objects and
// arrays as needed.
//
// An existing non-container value at an intermediate step is replaced. The path
// comes from the schema, which is a stronger statement about the argument's
// shape than whatever placeholder happens to occupy the slot.
func setPath(args map[string]any, path Path, value any) {
	segs := segments(string(path))
	if len(segs) == 0 || args == nil {
		return
	}
	// The root is always an object: MCP tool arguments are a JSON object.
	if segs[0].isIdx {
		return
	}

	// container holds whatever we are currently writing into, addressed through
	// the parent so we can replace it when it turns out to be the wrong type.
	var (
		curMap map[string]any = args
		curArr []any
		inArr  bool
	)
	// setParent writes v back into whichever container held the previous step.
	var setParent func(v any)

	for i := 0; i < len(segs); i++ {
		last := i == len(segs)-1
		s := segs[i]

		if s.isIdx {
			if !inArr {
				return // an index step with no array to index: malformed path
			}
			for len(curArr) <= s.index {
				curArr = append(curArr, nil)
			}
			if last {
				curArr[s.index] = value
				setParent(curArr)
				return
			}
			grown := curArr
			idx := s.index
			parentSet := setParent
			next, ok := curArr[s.index].(map[string]any)
			if !ok {
				next = map[string]any{}
				grown[idx] = next
			}
			parentSet(grown)
			curMap, inArr, curArr = next, false, nil
			setParent = func(v any) {
				grown[idx] = v
				parentSet(grown)
			}
			continue
		}

		if last {
			curMap[s.key] = value
			return
		}

		key := s.key
		owner := curMap
		// Look ahead: an index step next means this key holds an array.
		if i+1 < len(segs) && segs[i+1].isIdx {
			arr, _ := owner[key].([]any)
			curArr, inArr = arr, true
			setParent = func(v any) { owner[key] = v }
			continue
		}
		next, ok := owner[key].(map[string]any)
		if !ok {
			next = map[string]any{}
			owner[key] = next
		}
		curMap, inArr, curArr = next, false, nil
		setParent = func(v any) { owner[key] = v }
	}
}

// SetPath assigns value at a path within an existing argument map, creating
// intermediate objects and arrays as needed.
//
// It exists for callers holding a raw argument map rather than a Call — a
// recorded observation being replayed, for instance — so that they place a value
// where the server reads it rather than at the top level.
func SetPath(args map[string]any, p Path, value any) { setPath(args, p, value) }

// FlattenArgs reduces a nested argument object to the leaf values it holds,
// keyed by the same Path that addresses them.
//
// It is the inverse of the rendering Call.Args performs, and exists so a caller
// holding a recorded argument map — one identity's validated call, replayed by
// another — can reason about it one argument at a time instead of treating it as
// an opaque blob. An argument that carries identity is a leaf like any other,
// and it cannot be found, compared, or replaced without a path to name it by.
func FlattenArgs(args map[string]any) map[Path]any {
	out := map[Path]any{}
	flattenInto(out, "", args)
	return out
}

func flattenInto(out map[Path]any, prefix Path, v any) {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 && prefix != "" {
			out[prefix] = t
			return
		}
		for k, sub := range t {
			flattenInto(out, prefix.Child(k), sub)
		}
	case []any:
		if len(t) == 0 && prefix != "" {
			out[prefix] = t
			return
		}
		for i, sub := range t {
			flattenInto(out, prefix.Index(i), sub)
		}
	default:
		if prefix != "" {
			out[prefix] = v
		}
	}
}

// CopyArgs deep-copies an argument map so that mutating one copy cannot reach
// another.
//
// A shallow copy shares every nested object between the copies, so writing to
// one writes to both. Where a caller builds two variants of a call — an attack
// and the control it is compared against — that sharing makes both calls address
// the same object, and a real finding reads as a pass.
func CopyArgs(args map[string]any) map[string]any {
	if args == nil {
		return nil
	}
	out := make(map[string]any, len(args))
	for k, v := range args {
		out[k] = copyValue(v)
	}
	return out
}

func copyValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return CopyArgs(t)
	case []any:
		arr := make([]any, len(t))
		for i, e := range t {
			arr[i] = copyValue(e)
		}
		return arr
	default:
		return v
	}
}
