package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRegisterFilesUpToDate fails if the committed pkg/register/<type>/<type>.go
// files differ from what genregister would produce. This is the CI enforcement
// point: a PR that adds or removes a capability package without running
// `make generate` fails here (the drift check runs as part of `go test ./...`).
func TestRegisterFilesUpToDate(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("moduleRoot: %v", err)
	}
	modulePath, err := modulePathOf(root)
	if err != nil {
		t.Fatalf("modulePathOf: %v", err)
	}

	for _, c := range capabilities {
		t.Run(c.pkgName, func(t *testing.T) {
			scanDir := filepath.Join(root, "internal", c.pkgName)
			names, err := registeredSubpackages(scanDir, c.registerPkgPath(modulePath))
			if err != nil {
				t.Fatalf("registeredSubpackages: %v", err)
			}

			importPaths := make([]string, len(names))
			for i, n := range names {
				importPaths[i] = modulePath + "/internal/" + c.pkgName + "/" + n
			}

			want, err := c.render(modulePath, importPaths)
			if err != nil {
				t.Fatalf("render: %v", err)
			}

			outFile := filepath.Join(root, "pkg", "register", c.pkgName, c.pkgName+".go")
			got, err := os.ReadFile(outFile)
			if err != nil {
				t.Fatalf("read %s: %v", outFile, err)
			}

			if string(got) != string(want) {
				t.Errorf("%s is out of date; run `make generate` and commit the result", outFile)
			}
		})
	}
}
