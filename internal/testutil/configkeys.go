package testutil

import (
	"errors"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

const registryPath = "github.com/praetorian-inc/augustus/pkg/registry"

// registryKeyAt1 lists pkg/registry readers whose second argument is the config
// key; later arguments are defaults, never keys.
var registryKeyAt1 = map[string]bool{
	"GetString": true, "GetInt": true, "GetFloat32": true, "GetFloat64": true,
	"GetBool": true, "GetStringSlice": true, "RequireString": true, "RequireStringSlice": true,
}

// registryAPIKeyReaders read the hard-coded "api_key" key inside pkg/registry.
var registryAPIKeyReaders = map[string]bool{
	"GetAPIKeyWithEnv": true, "GetOptionalAPIKeyWithEnv": true,
}

// ConfigKeysRead type-checks the Go source files of one package and returns the
// sorted, de-duplicated config keys its functions read from config maps.
//
// A config map is a function-declaration parameter typed registry.Config or
// map[string]any (map[string]interface{}), or a local variable assigned from
// one (mm := m, var mm = m). In every function declaration with a config map
// the guard enforces, failing closed:
//
//   - The key of a read m[key], and of a pkg/registry getter, must be a
//     package-level string constant declared in one of the files. The only
//     other accepted key is a parameter of the enclosing function (or a range
//     variable over one): a pass-through helper whose call sites are checked.
//     Anything else — raw literal, local or package variable, function-local
//     constant, concatenation, call — is an error.
//   - A config map may be passed only to a known pkg/registry reader, a
//     builtin, or a function or method declared in the scanned files, whose
//     other arguments must then be keys as above. Passing it to any other
//     callee (another package, an unresolved name, an unhandled registry
//     function) is an error.
//
// Writes (m[k] = v) are not reads and are ignored. Not enforced: ranging over
// a config map; config maps reached through struct fields or function-literal
// parameters; a config map converted to another type (var a any = m, &m, an
// any-typed or generic helper parameter, a local alias of the map type); and
// pkg/registry imported under another name (the type check matches the
// package name, not the import path). Every map[string]any parameter counts
// as a config map, so a non-config JSON helper in a scanned file must live in
// an excluded file. Imports are stubbed, so only package-local identifiers
// resolve; type errors from the stubs are ignored.
func ConfigKeysRead(files ...string) ([]string, error) {
	fset := token.NewFileSet()
	parsed := make([]*ast.File, 0, len(files))
	for _, p := range files {
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, f)
	}

	info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
	conf := types.Config{Importer: stubImporter{}, Error: func(error) {}}
	pkg, _ := conf.Check("configkeys", fset, parsed, info) // stub imports always yield type errors

	c := &keyCollector{fset: fset, info: info, pkg: pkg, keys: map[string]struct{}{}}
	for _, f := range parsed {
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				c.funcDecl(fn)
			}
		}
	}
	if len(c.errs) > 0 {
		return nil, errors.Join(c.errs...)
	}
	return slices.Sorted(maps.Keys(c.keys)), nil
}

// PackageSources returns the non-test .go files in dir minus the named
// exclusions, so a file added to the package is scanned by default. Every
// exclusion must name an existing file; a stale exclusion is an error.
func PackageSources(dir string, exclude ...string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	skip := map[string]bool{}
	for _, name := range exclude {
		skip[name] = true
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if skip[name] {
			delete(skip, name)
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	if len(skip) > 0 {
		return nil, fmt.Errorf("%s: excluded files not found: %v", dir, slices.Sorted(maps.Keys(skip)))
	}
	return out, nil
}

// stubImporter resolves every import to an empty package, so type-checking
// needs no build of dependencies and still resolves package-local scopes.
type stubImporter struct{}

func (stubImporter) Import(p string) (*types.Package, error) {
	pkg := types.NewPackage(p, path.Base(p))
	pkg.MarkComplete()
	return pkg, nil
}

type keyCollector struct {
	fset *token.FileSet
	info *types.Info
	pkg  *types.Package
	keys map[string]struct{}
	errs []error
}

// funcScope tracks one function declaration's config maps and the parameters
// it may use as pass-through keys.
type funcScope struct {
	info      *types.Info
	config    map[types.Object]bool
	keyParams map[types.Object]bool
}

func (s *funcScope) isConfig(e ast.Expr) bool {
	id, ok := ast.Unparen(e).(*ast.Ident)
	return ok && s.config[s.info.Uses[id]]
}

func (c *keyCollector) funcDecl(fn *ast.FuncDecl) {
	s := c.params(fn.Type.Params)
	if len(s.config) == 0 {
		return
	}
	writes := map[*ast.IndexExpr]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			c.assign(s, n.Tok, n.Lhs, n.Rhs, writes)
		case *ast.ValueSpec:
			lhs := make([]ast.Expr, len(n.Names))
			for i, name := range n.Names {
				lhs[i] = name
			}
			c.assign(s, token.DEFINE, lhs, n.Values, writes)
		case *ast.RangeStmt:
			if id, ok := ast.Unparen(n.X).(*ast.Ident); ok && s.keyParams[c.info.Uses[id]] && n.Value != nil {
				s.keyParams[c.object(n.Value)] = true
			}
		case *ast.IndexExpr:
			if !writes[n] && s.isConfig(n.X) {
				c.key(s, n.Index, n)
			}
		case *ast.CallExpr:
			if i := slices.IndexFunc(n.Args, s.isConfig); i >= 0 {
				c.call(s, n)
			}
		}
		return true
	})
}

// assign marks m[k] = v targets as writes and propagates config-map aliases.
func (c *keyCollector) assign(s *funcScope, tok token.Token, lhs, rhs []ast.Expr, writes map[*ast.IndexExpr]bool) {
	for i, l := range lhs {
		if ix, ok := ast.Unparen(l).(*ast.IndexExpr); ok && tok == token.ASSIGN {
			writes[ix] = true
		}
		if len(lhs) == len(rhs) && s.isConfig(rhs[i]) {
			if obj := c.object(l); obj != nil {
				s.config[obj] = true
			}
		}
	}
}

// call checks a call that receives a config map.
func (c *keyCollector) call(s *funcScope, n *ast.CallExpr) {
	fun := ast.Unparen(n.Fun)
	if sel, ok := fun.(*ast.SelectorExpr); ok {
		if pn, ok := c.info.Uses[identOf(sel.X)].(*types.PkgName); ok {
			if pn.Imported().Path() == registryPath {
				c.registryCall(s, n, sel.Sel.Name)
				return
			}
			c.errorf(n, "config map passed to %s outside the scanned package", types.ExprString(fun))
			return
		}
		fun = sel.Sel
	}
	switch obj := c.info.Uses[identOf(fun)].(type) {
	case *types.Builtin:
		return
	case *types.Func:
		if obj.Pkg() == c.pkg {
			for _, arg := range n.Args {
				if !s.isConfig(arg) {
					c.key(s, arg, n.Fun)
				}
			}
			return
		}
	}
	c.errorf(n, "config map passed to unresolved function %s", types.ExprString(n.Fun))
}

func (c *keyCollector) registryCall(s *funcScope, n *ast.CallExpr, name string) {
	switch {
	case registryKeyAt1[name] && len(n.Args) > 1:
		c.key(s, n.Args[1], n.Fun)
	case registryAPIKeyReaders[name]:
		c.keys["api_key"] = struct{}{}
	default:
		c.errorf(n, "unhandled registry.%s reads config", name)
	}
}

// key records a package-level string constant key, accepts a pass-through
// parameter, and reports every other expression as an error.
func (c *keyCollector) key(s *funcScope, e ast.Expr, at ast.Expr) {
	switch e := ast.Unparen(e).(type) {
	case *ast.BasicLit:
		c.errorf(e, "config key %s is a raw literal; read it through a key constant", e.Value)
		return
	case *ast.Ident:
		switch obj := c.info.Uses[e].(type) {
		case *types.Const:
			if obj.Parent() == c.pkg.Scope() && obj.Val().Kind() == constant.String {
				c.keys[constant.StringVal(obj.Val())] = struct{}{}
				return
			}
		case *types.Var:
			if s.keyParams[obj] {
				return
			}
		}
	}
	c.errorf(e, "%s: config key %s is not a package-level string constant", types.ExprString(at), types.ExprString(e))
}

// params collects config-map parameters and the remaining (pass-through key)
// parameters of a function declaration.
func (c *keyCollector) params(fields *ast.FieldList) *funcScope {
	s := &funcScope{info: c.info, config: map[types.Object]bool{}, keyParams: map[types.Object]bool{}}
	for _, f := range fields.List {
		target := s.keyParams
		if isConfigType(f.Type) {
			target = s.config
		}
		for _, name := range f.Names {
			if obj := c.info.Defs[name]; obj != nil {
				target[obj] = true
			}
		}
	}
	return s
}

// object returns the variable an assignment target or range variable denotes.
func (c *keyCollector) object(e ast.Expr) types.Object {
	id := identOf(e)
	if id == nil {
		return nil
	}
	if obj := c.info.Defs[id]; obj != nil {
		return obj
	}
	return c.info.Uses[id]
}

func (c *keyCollector) errorf(n ast.Node, format string, args ...any) {
	c.errs = append(c.errs, fmt.Errorf("%s: %s", c.fset.Position(n.Pos()), fmt.Sprintf(format, args...)))
}

// isConfigType reports whether a parameter type is registry.Config or
// map[string]any / map[string]interface{}.
func isConfigType(t ast.Expr) bool {
	switch t := t.(type) {
	case *ast.SelectorExpr:
		pkg, ok := t.X.(*ast.Ident)
		return ok && pkg.Name == "registry" && t.Sel.Name == "Config"
	case *ast.MapType:
		k, ok := t.Key.(*ast.Ident)
		if !ok || k.Name != "string" {
			return false
		}
		switch v := t.Value.(type) {
		case *ast.Ident:
			return v.Name == "any"
		case *ast.InterfaceType:
			return len(v.Methods.List) == 0
		}
	}
	return false
}

func identOf(e ast.Expr) *ast.Ident {
	id, _ := ast.Unparen(e).(*ast.Ident)
	return id
}
