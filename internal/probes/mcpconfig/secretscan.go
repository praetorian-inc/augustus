// Package mcpconfig provides static-analysis probes over MCP (Model Context
// Protocol) server configuration.
//
// SecretScan is a static probe: unlike prompt-based probes it does not call the
// generator. It sources configuration content (from an inline string, a file,
// or a directory of config files) and emits it as attempt outputs so the
// mcpsecrets.ConfigLeak detector can flag exposed credentials. This covers the
// static half of LAB-4463 (Credential Exposure) and runs without a live MCP
// server, mapping to OWASP MCP01 (Token Mismanagement) / MCP04 (Supply Chain).
package mcpconfig

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

const (
	probeName       = "mcpconfig.SecretScan"
	primaryDetector = "mcpsecrets.ConfigLeak"

	// maxFileSize caps how large a config file may be before it is skipped.
	// Larger files are recorded as an error source rather than buffered whole.
	maxFileSize = 5 << 20 // 5 MiB
)

func init() {
	probes.Register(probeName, NewSecretScan)
}

// configExtensions are the file extensions treated as scannable config when a
// directory is provided. Files named ".env*" are also included (see isConfigFile).
var configExtensions = map[string]bool{
	".json": true, ".env": true, ".yaml": true, ".yml": true,
	".toml": true, ".ini": true, ".cfg": true, ".conf": true,
}

// source is a single unit of content to scan, or a read error for one path.
type source struct {
	label   string
	content string
	err     error
}

// SecretScan scans MCP configuration content for exposed credentials.
type SecretScan struct {
	path    string
	content string
}

// NewSecretScan builds the probe from config. Recognized keys:
//   - "path":    a file or directory to scan
//   - "content": inline configuration content to scan
//
// At least one should be set; otherwise Probe emits a single error attempt.
func NewSecretScan(cfg registry.Config) (probes.Prober, error) {
	s := &SecretScan{}
	if v, ok := cfg["path"].(string); ok {
		s.path = v
	}
	if v, ok := cfg["content"].(string); ok {
		s.content = v
	}
	return s, nil
}

// Probe collects config sources and emits one attempt per source. The generator
// is intentionally unused: this is static analysis of configuration at rest.
func (s *SecretScan) Probe(ctx context.Context, _ probes.Generator) ([]*attempt.Attempt, error) {
	sources, err := s.collect()
	if err != nil {
		a := attempt.New(probeName)
		a.Probe = probeName
		a.Detector = primaryDetector
		a.SetError(err)
		return []*attempt.Attempt{a}, nil
	}

	attempts := make([]*attempt.Attempt, 0, len(sources))
	for _, src := range sources {
		select {
		case <-ctx.Done():
			return attempts, ctx.Err()
		default:
		}

		a := attempt.New(src.label)
		a.Probe = probeName
		a.Detector = primaryDetector
		a.WithMetadata("source", src.label)
		if src.err != nil {
			a.SetError(src.err)
		} else {
			a.AddOutput(src.content)
			a.Complete()
		}
		attempts = append(attempts, a)
	}
	return attempts, nil
}

// collect gathers all sources from inline content and/or the configured path.
// It returns an error only when there is nothing at all to scan.
func (s *SecretScan) collect() ([]source, error) {
	var sources []source
	if s.content != "" {
		sources = append(sources, source{label: "inline", content: s.content})
	}
	if s.path != "" {
		found, err := readPath(s.path)
		if err != nil {
			sources = append(sources, source{label: s.path, err: err})
		} else {
			sources = append(sources, found...)
		}
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("mcpconfig.SecretScan: no config source provided (set 'path' or 'content')")
	}
	return sources, nil
}

// readPath reads a single file, or walks a directory collecting config files.
func readPath(path string) ([]source, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.IsDir() {
		if info.Size() > maxFileSize {
			return []source{{label: path, err: oversizeErr(path, info.Size())}}, nil
		}
		// #nosec G304 -- operator-supplied path; scanning the operator-designated MCP config file is this probe's purpose.
		content, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		return []source{{label: path, content: string(content)}}, nil
	}

	var sources []source
	walkErr := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isConfigFile(d.Name()) {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			sources = append(sources, source{label: p, err: infoErr})
			return nil
		}
		if info.Size() > maxFileSize {
			sources = append(sources, source{label: p, err: oversizeErr(p, info.Size())})
			return nil
		}
		// #nosec G304 -- entry under the operator-designated config directory being walked for scanning.
		content, readErr := os.ReadFile(filepath.Clean(p))
		if readErr != nil {
			sources = append(sources, source{label: p, err: readErr})
			return nil
		}
		sources = append(sources, source{label: p, content: string(content)})
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return sources, nil
}

// oversizeErr builds the error recorded for a file that exceeds maxFileSize.
func oversizeErr(path string, size int64) error {
	return fmt.Errorf("skip %s: file size %d bytes exceeds max %d bytes", path, size, maxFileSize)
}

// isConfigFile reports whether a filename should be scanned as configuration.
func isConfigFile(name string) bool {
	if strings.HasPrefix(name, ".env") {
		return true
	}
	return configExtensions[filepath.Ext(name)]
}

// Name returns the fully qualified probe name.
func (s *SecretScan) Name() string { return probeName }

// Description returns a human-readable description.
func (s *SecretScan) Description() string {
	return "Statically scans MCP server configuration (files, directories, or inline content) for exposed credentials"
}

// Goal returns the probe's goal.
func (s *SecretScan) Goal() string {
	return "detect credentials exposed in MCP configuration and referenced .env files"
}

// GetPrimaryDetector returns the recommended detector for this probe.
func (s *SecretScan) GetPrimaryDetector() string { return primaryDetector }

// GetPrompts returns the probe's prompts. SecretScan is static and sends none.
func (s *SecretScan) GetPrompts() []string { return nil }
