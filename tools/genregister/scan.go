package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// registeredSubpackages returns the sorted base names of the immediate
// subdirectories of scanDir whose (non-test) Go source calls Register on the
// package imported from registerImportPath.
func registeredSubpackages(scanDir, registerImportPath string) ([]string, error) {
	entries, err := os.ReadDir(scanDir)
	if err != nil {
		return nil, fmt.Errorf("read dir %s: %w", scanDir, err)
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(scanDir, e.Name())
		ok, err := packageRegisters(dir, registerImportPath)
		if err != nil {
			return nil, err
		}
		if ok {
			names = append(names, e.Name())
		}
		// The generator only emits blank imports for immediate subdirectories.
		// A registration nested deeper would be silently dropped — and the drift
		// guard could not catch it, since it compares against this same
		// generator. Fail loudly instead.
		if err := assertNoNestedRegistration(dir, registerImportPath); err != nil {
			return nil, err
		}
	}
	sort.Strings(names)
	return names, nil
}

// assertNoNestedRegistration returns an error if any package strictly below
// pkgDir registers itself, which genregister does not support (it only imports
// packages one level under internal/<type>/).
func assertNoNestedRegistration(pkgDir, registerImportPath string) error {
	return filepath.WalkDir(pkgDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() || p == pkgDir {
			return nil
		}
		ok, err := packageRegisters(p, registerImportPath)
		if err != nil {
			return err
		}
		if ok {
			return fmt.Errorf("package %s registers itself but is nested below %s; genregister only supports registrations one level under internal/<type>/", p, pkgDir)
		}
		return nil
	})
}

// packageRegisters reports whether the Go package in dir calls Register on the
// package imported from registerImportPath. Test files (_test.go) are ignored.
func packageRegisters(dir, registerImportPath string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, fmt.Errorf("read dir %s: %w", dir, err)
	}

	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			return false, fmt.Errorf("parse %s: %w", filepath.Join(dir, name), err)
		}
		if fileRegisters(file, registerImportPath) {
			return true, nil
		}
	}
	return false, nil
}

// fileRegisters reports whether file imports registerImportPath and calls
// <localname>.Register(...) on it.
func fileRegisters(file *ast.File, registerImportPath string) bool {
	local, ok := importLocalName(file, registerImportPath)
	if !ok {
		return false
	}

	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Register" {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if ok && ident.Name == local {
			found = true
			return false
		}
		return true
	})
	return found
}

// importLocalName returns the local name under which importPath is imported in
// file. It handles aliased and unaliased imports, and returns false when the
// path is not imported or is imported as "_" or ".".
func importLocalName(file *ast.File, importPath string) (string, bool) {
	for _, imp := range file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != importPath {
			continue
		}
		if imp.Name != nil {
			switch imp.Name.Name {
			case "_", ".":
				return "", false
			default:
				return imp.Name.Name, true
			}
		}
		// Unaliased import: the local name is the package's declared name, which
		// for every Augustus register package equals the final path segment.
		return path.Base(importPath), true
	}
	return "", false
}
