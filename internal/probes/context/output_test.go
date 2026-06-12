package context

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/types"
)

func TestWriteAndLoadExtractedContext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "context.yaml")

	original := &types.ExtractedContext{
		Version:      1,
		SystemPrompt: "You are a helpful assistant",
		Tools: []types.ToolSchema{
			{
				Name:        "get_order",
				Description: "Get order details",
				Parameters:  map[string]string{"order_id": "string"},
			},
		},
		Identity: types.IdentityContext{
			UserID:      "user_123",
			Tenant:      "acme",
			Role:        "customer",
			Permissions: []string{"read:orders"},
		},
		Confidence: 0.85,
	}

	if err := WriteExtractedContext(path, original); err != nil {
		t.Fatalf("WriteExtractedContext: %v", err)
	}

	loaded, err := LoadExtractedContext(path)
	if err != nil {
		t.Fatalf("LoadExtractedContext: %v", err)
	}

	if loaded.Version != original.Version {
		t.Errorf("Version: got %d, want %d", loaded.Version, original.Version)
	}
	if loaded.SystemPrompt != original.SystemPrompt {
		t.Errorf("SystemPrompt: got %q, want %q", loaded.SystemPrompt, original.SystemPrompt)
	}
	if len(loaded.Tools) != len(original.Tools) {
		t.Fatalf("Tools: got %d, want %d", len(loaded.Tools), len(original.Tools))
	}
	if loaded.Tools[0].Name != "get_order" {
		t.Errorf("Tools[0].Name: got %q, want %q", loaded.Tools[0].Name, "get_order")
	}
	if loaded.Identity.UserID != original.Identity.UserID {
		t.Errorf("Identity.UserID: got %q, want %q", loaded.Identity.UserID, original.Identity.UserID)
	}
	if loaded.Identity.Tenant != original.Identity.Tenant {
		t.Errorf("Identity.Tenant: got %q, want %q", loaded.Identity.Tenant, original.Identity.Tenant)
	}
	if loaded.Confidence != original.Confidence {
		t.Errorf("Confidence: got %f, want %f", loaded.Confidence, original.Confidence)
	}
}

func TestLoadExtractedContext_InvalidFile(t *testing.T) {
	dir := t.TempDir()

	// Non-existent file
	_, err := LoadExtractedContext(filepath.Join(dir, "missing.yaml"))
	if err == nil {
		t.Error("expected error for missing file")
	}

	// Invalid YAML
	badPath := filepath.Join(dir, "bad.yaml")
	os.WriteFile(badPath, []byte(":::invalid"), 0o644)
	_, err = LoadExtractedContext(badPath)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}

	// Valid YAML but fails validation (empty)
	emptyPath := filepath.Join(dir, "empty.yaml")
	os.WriteFile(emptyPath, []byte("version: 1\n"), 0o644)
	_, err = LoadExtractedContext(emptyPath)
	if err == nil {
		t.Error("expected error for empty context")
	}
}
