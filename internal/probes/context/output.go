package context

import (
	"fmt"
	"os"

	"github.com/praetorian-inc/augustus/pkg/types"
	"gopkg.in/yaml.v3"
)

// WriteExtractedContext writes an ExtractedContext to a YAML file.
func WriteExtractedContext(path string, ec *types.ExtractedContext) error {
	data, err := yaml.Marshal(ec)
	if err != nil {
		return fmt.Errorf("marshal extracted context: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write extracted context to %s: %w", path, err)
	}
	return nil
}

// LoadExtractedContext reads and validates an ExtractedContext from a YAML file.
func LoadExtractedContext(path string) (*types.ExtractedContext, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read context file %s: %w", path, err)
	}

	var ec types.ExtractedContext
	if err := yaml.Unmarshal(data, &ec); err != nil {
		return nil, fmt.Errorf("parse context file %s: %w", path, err)
	}

	if err := ec.Validate(); err != nil {
		return nil, fmt.Errorf("invalid context file %s: %w", path, err)
	}

	return &ec, nil
}
