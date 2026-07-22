package mcptool

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func newPathTraversalDetector(t *testing.T) *PathTraversalDetector {
	t.Helper()
	d, err := NewPathTraversalDetector(registry.Config{})
	if err != nil {
		t.Fatalf("NewPathTraversalDetector: %v", err)
	}
	return d.(*PathTraversalDetector)
}

func ptAttemptWith(signatures []string, output string) *attempt.Attempt {
	a := attempt.New("../../etc/passwd")
	if len(signatures) > 0 {
		a.Metadata[attempt.MetadataKeyPathTraversalSignatures] = signatures
	}
	a.AddOutput(output)
	return a
}

func TestPathTraversalDetector(t *testing.T) {
	tests := []struct {
		name string
		a    *attempt.Attempt
		want float64
	}{
		{"passwd signature present -> vuln", ptAttemptWith([]string{"root:x:0:0:"}, "root:x:0:0:root:/root:/bin/bash\n"), 1.0},
		{"win.ini signature present -> vuln", ptAttemptWith([]string{"[extensions]", "[fonts]"}, "; for 16-bit app support\n[fonts]\n"), 1.0},
		{"signature absent -> safe", ptAttemptWith([]string{"root:x:0:0:"}, "read ../../etc/passwd"), 0.0},
		{"no signature recorded -> safe", ptAttemptWith(nil, "root:x:0:0:"), 0.0},
	}

	d := newPathTraversalDetector(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scores, err := d.Detect(context.Background(), tt.a)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if len(scores) != 1 || scores[0] != tt.want {
				t.Errorf("Detect = %v, want [%v]", scores, tt.want)
			}
		})
	}
}

// TestPathTraversalDetector_ToleratesJSONRoundTrip: metadata read as []any
// (post-JSON) still resolves signatures.
func TestPathTraversalDetector_ToleratesJSONRoundTrip(t *testing.T) {
	a := attempt.New("../../etc/passwd")
	a.Metadata[attempt.MetadataKeyPathTraversalSignatures] = []any{"root:x:0:0:"}
	a.AddOutput("root:x:0:0:root:/root:/bin/bash")

	scores, err := newPathTraversalDetector(t).Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(scores) != 1 || scores[0] != 1.0 {
		t.Errorf("Detect = %v, want [1]", scores)
	}
}
