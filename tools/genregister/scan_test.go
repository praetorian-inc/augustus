package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// registerImportPath is a fake register-package import path used by the fixture
// tree. The detector must key off the import path, not a hard-coded local name.
const testRegisterPath = "example.com/reg/detectors"

// writePkg creates dir/<name>.go with the given source under root/sub.
func writePkg(t *testing.T, root, sub, filename, src string) {
	t.Helper()
	dir := filepath.Join(root, sub)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(src), 0o644); err != nil {
		t.Fatalf("write %s: %v", filename, err)
	}
}

func TestRegisteredSubpackages(t *testing.T) {
	root := t.TempDir()

	// (a) Registers via the target import path -> included.
	writePkg(t, root, "included", "included.go", `package included

import reg "example.com/reg/detectors"

func init() { reg.Register("included.Thing", nil) }
`)

	// (b) Helper package with no Register call -> excluded.
	writePkg(t, root, "helper", "helper.go", `package helper

func Thing() string { return "helper" }
`)

	// (c) Registers on a DIFFERENT package's import path -> excluded.
	//     Proves detection resolves the import path, not the bare "Register".
	writePkg(t, root, "otherreg", "otherreg.go", `package otherreg

import "example.com/reg/probes"

func init() { probes.Register("otherreg.Thing", nil) }
`)

	// (d) Register call lives only in a _test.go file -> excluded.
	writePkg(t, root, "testonly", "testonly.go", `package testonly

func Thing() string { return "testonly" }
`)
	writePkg(t, root, "testonly", "testonly_test.go", `package testonly

import (
	"testing"

	reg "example.com/reg/detectors"
)

func TestX(t *testing.T) { reg.Register("testonly.Thing", nil) }
`)

	got, err := registeredSubpackages(root, testRegisterPath)
	if err != nil {
		t.Fatalf("registeredSubpackages: %v", err)
	}

	want := []string{"included"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("registeredSubpackages() = %v, want %v", got, want)
	}
}
