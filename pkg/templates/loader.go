package templates

import (
	"embed"
	"fmt"
	"os"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// Loader loads probe templates from an embedded filesystem.
type Loader struct {
	fs      embed.FS
	basedir string
}

// NewLoader creates a new template loader.
func NewLoader(fs embed.FS, basedir string) *Loader {
	return &Loader{
		fs:      fs,
		basedir: basedir,
	}
}

// Load loads a single template by filename.
func (l *Loader) Load(filename string) (*ProbeTemplate, error) {
	filepath := path.Join(l.basedir, filename)

	data, err := l.fs.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("reading template %s: %w", filename, err)
	}

	var tmpl ProbeTemplate
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("parsing template %s: %w", filename, err)
	}

	return &tmpl, nil
}

// LoadAll loads all YAML templates from the embedded filesystem.
func (l *Loader) LoadAll() ([]*ProbeTemplate, error) {
	entries, err := l.fs.ReadDir(l.basedir)
	if err != nil {
		return nil, fmt.Errorf("reading template directory: %w", err)
	}

	templates := make([]*ProbeTemplate, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		tmpl, err := l.Load(entry.Name())
		if err != nil {
			return nil, err
		}
		templates = append(templates, tmpl)
	}

	return templates, nil
}

// LoadFromPath loads templates from a filesystem path (not embedded).
// This enables runtime loading of custom templates without recompilation.
func LoadFromPath(basedir string) ([]*ProbeTemplate, error) {
	entries, err := os.ReadDir(basedir)
	if err != nil {
		return nil, fmt.Errorf("reading template directory %s: %w", basedir, err)
	}

	templates := make([]*ProbeTemplate, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml")) {
			continue
		}

		filepath := path.Join(basedir, entry.Name())
		data, err := os.ReadFile(filepath)
		if err != nil {
			return nil, fmt.Errorf("reading template %s: %w", filepath, err)
		}

		var tmpl ProbeTemplate
		if err := yaml.Unmarshal(data, &tmpl); err != nil {
			return nil, fmt.Errorf("parsing template %s: %w", filepath, err)
		}
		templates = append(templates, &tmpl)
	}

	return templates, nil
}
