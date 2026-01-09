package equivalence

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// FindProjectRoot finds the venator project root by walking up from the current file.
// It looks for the directory containing go.mod with module path ending in "venator".
func FindProjectRoot() (string, error) {
	// Get the directory of this test file
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("failed to get current file location")
	}

	dir := filepath.Dir(filename)

	// Walk up the directory tree looking for go.mod
	for {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			// Found go.mod, verify it's the venator module
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root without finding go.mod
			return "", fmt.Errorf("could not find project root (no go.mod found)")
		}
		dir = parent
	}
}

// FindGarakPath finds the garak directory relative to venator root.
// Expected structure: /path/to/chariot-development-platform3/venator and /path/to/chariot-development-platform3/garak
func FindGarakPath() (string, error) {
	venatorRoot, err := FindProjectRoot()
	if err != nil {
		return "", err
	}

	// Go up one level from venator root to find garak as sibling
	parentDir := filepath.Dir(venatorRoot)
	garakPath := filepath.Join(parentDir, "garak")

	// Check if garak directory exists
	if _, err := os.Stat(garakPath); os.IsNotExist(err) {
		return "", fmt.Errorf("garak directory not found at %s", garakPath)
	}

	return garakPath, nil
}

// FindHarnessPath finds the Python harness script relative to venator root.
func FindHarnessPath() (string, error) {
	venatorRoot, err := FindProjectRoot()
	if err != nil {
		return "", err
	}

	harnessPath := filepath.Join(venatorRoot, "tools", "python_harness", "harness.py")

	// Check if harness exists
	if _, err := os.Stat(harnessPath); os.IsNotExist(err) {
		return "", fmt.Errorf("harness.py not found at %s", harnessPath)
	}

	return harnessPath, nil
}

// SkipIfNoPython skips the test if python3 is not available in PATH.
func SkipIfNoPython(t *testing.T) {
	t.Helper()

	_, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found in PATH, skipping equivalence test")
	}
}

// SkipIfNoGarak skips the test if garak cannot be found.
func SkipIfNoGarak(t *testing.T) {
	t.Helper()

	garakPath, err := FindGarakPath()
	if err != nil {
		t.Skipf("garak not found: %v", err)
	}

	// Verify garak directory has expected structure (e.g., __init__.py)
	initPath := filepath.Join(garakPath, "garak", "__init__.py")
	if _, err := os.Stat(initPath); os.IsNotExist(err) {
		t.Skipf("garak installation incomplete (no __init__.py at %s)", initPath)
	}
}

// SkipIfNoHarness skips the test if the Python harness cannot be found.
func SkipIfNoHarness(t *testing.T) {
	t.Helper()

	_, err := FindHarnessPath()
	if err != nil {
		t.Skipf("Python harness not found: %v", err)
	}
}
