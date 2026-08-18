package toolsig

// Origin records where a parameter was declared, which decides whether two
// parameters sharing a path are the same parameter.
//
// It is captured during parsing because it cannot be recovered afterwards: a
// base parameter and a branch parameter can occupy the same path, and once the
// signature is flattened there is nothing left to tell them apart.
type Origin uint8

const (
	// OriginBase is a parameter declared in the schema's own properties, outside
	// any conditional branch. It is one parameter across every signature of the
	// tool: declared once, and reached the same way whichever branch is taken.
	OriginBase Origin = iota

	// OriginBranch is a parameter contributed by an if/then, oneOf or anyOf
	// branch. The branch is what distinguishes it. Two branches may declare the
	// same path and mean entirely different operations, so a branch parameter
	// must never be collapsed with another that merely shares its path.
	OriginBranch
)

func (o Origin) String() string {
	if o == OriginBranch {
		return "branch"
	}
	return "base"
}

// Param is one leaf parameter of one call signature.
//
// A leaf is a parameter that takes a value: a nested object is not a Param, its
// scalar members are. That is what lets a caller iterate parameters without
// knowing anything about the schema's shape.
type Param struct {
	// Path addresses the parameter within the argument object.
	Path Path

	// Type is the JSON Schema type ("string", "integer", "boolean", "array",
	// "number", "null"), or "" when the schema declares none.
	Type string

	// Items is the element type of an array parameter, "" otherwise.
	Items string

	// Required reports whether this signature requires the parameter. It is a
	// property of the SIGNATURE, not of the tool: a parameter can be required
	// under one branch and absent from another.
	Required bool

	// Enum holds the declared permissible values, rendered as strings. A
	// non-empty Enum means the server constrains this parameter, so an
	// arbitrary payload will be rejected before reaching any sink.
	Enum []string

	// Default is the schema's declared default, nil when there is none.
	Default any

	// Const is the schema's fixed value, nil when there is none. A parameter
	// with a Const has exactly one legal value.
	Const any

	// Origin records base-versus-branch provenance. See Origin.
	Origin Origin

	// Doc is the parameter's own description. Callers mine it for candidate
	// values when the schema declares none.
	Doc string
}

// HasValue reports whether the schema itself determines this parameter's value,
// in which case no external source is needed.
func (p Param) HasValue() bool {
	return p.Const != nil || p.Default != nil || len(p.Enum) > 0
}
