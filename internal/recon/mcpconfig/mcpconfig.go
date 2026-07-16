// Package mcpconfig provides the MCP configuration reconnaissance module.
//
// It collects MCP (Model Context Protocol) server configuration content — from
// an inline string, a single file, or a directory of config files — and emits
// each source as a descriptive output.Observation. It renders no verdict:
// reconnaissance measures, it does not test. Scoring that content for exposed
// credentials is a separate test probe's job (mcpconfig.CredentialExposure,
// which reads these observations back and scores them with the
// mcpsecrets.Credential detector).
//
// The module operates on LOCAL files and is independent of the scan target: the
// recon contract sanctions target-less modules, so it runs regardless of which
// generator (if any) is under assessment. It maps to OWASP MCP01 (Token
// Mismanagement) / MCP04 (Supply Chain).
//
// Caveat: observation payloads embed the scanned content verbatim, including any
// real credential present, so the resulting JSONL report artifacts are
// secret-bearing and should be treated as sensitive.
package mcpconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/output"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// ObservationTypeConfig is the stable slug for an MCP configuration-source
// observation.
const ObservationTypeConfig = "mcp.config"

// maxFileSize caps how large a config file may be before it is skipped. A file
// exceeding it is skipped (recon measures; it does not buffer an unbounded blob).
const maxFileSize = 5 << 20 // 5 MiB

// maxFiles caps how many config files a single directory walk collects. Reaching
// it stops the walk (and is logged, not silently truncated) so an enormous or
// adversarial directory tree cannot make the module buffer unbounded content.
const maxFiles = 10000

// maxTotalBytes caps the cumulative content a single directory walk buffers.
// The per-file (maxFileSize) and file-count (maxFiles) caps alone still permit
// ~tens of GiB (10000 files x 5 MiB), so this bounds the aggregate. Reaching it
// stops the walk (logged, not silently truncated).
const maxTotalBytes = 50 << 20 // 50 MiB

func init() {
	recon.Register("recon.MCPConfig", New)
}

// Compile-time assertion.
var _ recon.Recon = (*Module)(nil)

// configExtensions are the file extensions treated as scannable config when a
// directory is provided. Files named ".env*" are also included (see isConfigFile).
var configExtensions = map[string]bool{
	".json": true, ".env": true, ".yaml": true, ".yml": true,
	".toml": true, ".ini": true, ".cfg": true, ".conf": true,
}

// Module is the MCP configuration reconnaissance module.
type Module struct {
	path    string
	content string
}

// New constructs the module from config. Recognized keys:
//   - "path":    a file or directory to collect config from
//   - "content": inline configuration content
//
// Either, both, or neither may be set; an empty module simply yields no
// observations.
func New(cfg registry.Config) (recon.Recon, error) {
	m := &Module{}
	if v, ok := cfg["path"].(string); ok {
		m.path = v
	}
	if v, ok := cfg["content"].(string); ok {
		m.content = v
	}
	return m, nil
}

// Name returns the fully qualified module name.
func (m *Module) Name() string { return "recon.MCPConfig" }

// Recon collects config sources and emits one observation per source. The
// generator is intentionally unused: this measures local configuration at rest,
// independent of the target. Unreadable or oversize files are skipped rather
// than failing the run; a cancelled context aborts and returns ctx.Err().
func (m *Module) Recon(ctx context.Context, _ types.Generator) ([]output.Observation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sources, err := m.collect(ctx)
	if err != nil {
		// Only a cancelled context reaches here (a read/stat error is a skip).
		return nil, err
	}

	obs := make([]output.Observation, 0, len(sources))
	for _, src := range sources {
		data, err := json.Marshal(src.content)
		if err != nil {
			return nil, fmt.Errorf("recon.MCPConfig: marshal content for %q: %w", src.label, err)
		}
		obs = append(obs, output.Observation{
			Type:   ObservationTypeConfig,
			Target: src.label,
			Data:   data,
			Source: m.Name(),
		})
	}
	return obs, nil
}

// source is a single unit of collected content, labelled by its origin.
type source struct {
	label   string
	content string
}

// collect gathers all sources from inline content and/or the configured path.
func (m *Module) collect(ctx context.Context) ([]source, error) {
	var sources []source
	if m.content != "" {
		sources = append(sources, source{label: "inline", content: m.content})
	}
	if m.path != "" {
		found, err := readPath(ctx, m.path)
		if err != nil {
			// A cancelled walk aborts the whole run; surface it so Recon can
			// propagate ctx.Err().
			return nil, err
		}
		sources = append(sources, found...)
	}
	return sources, nil
}

// readPath reads a single file, or walks a directory collecting config files.
// The context lets a directory walk be cancelled between entries. Unreadable or
// oversize paths/entries are skipped (recon measures; it does not error the whole
// run); only a cancelled context returns a non-nil error.
func readPath(ctx context.Context, path string) ([]source, error) {
	info, err := os.Stat(path)
	if err != nil {
		// Unreadable path: skip rather than error the run.
		return nil, nil
	}
	if !info.IsDir() {
		// Only regular files are collected: a FIFO/device would block the read
		// indefinitely, and non-regular files are not config sources.
		if !info.Mode().IsRegular() {
			return nil, nil
		}
		if info.Size() > maxFileSize {
			return nil, nil
		}
		// #nosec G304 -- operator-supplied path; collecting the operator-designated MCP config file is this module's purpose.
		content, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return nil, nil
		}
		return []source{{label: path, content: string(content)}}, nil
	}

	// Resolve a symlinked directory ROOT before walking. os.Stat follows the
	// symlink (so it is seen as a directory here), but WalkDir would receive the
	// symlink itself as its root entry and the entry-level symlink skip below
	// would then drop it, collecting zero files. Walking the resolved path avoids
	// that false clean while still skipping symlinked entries INSIDE the tree.
	if resolved, resolveErr := filepath.EvalSymlinks(path); resolveErr == nil {
		path = resolved
	}

	var sources []source
	var totalBytes int64
	walkErr := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			// Skip an unreadable entry (e.g. permission denied) and keep walking.
			return nil
		}
		// Skip symlinks: a symlinked .json/.env could resolve to a file OUTSIDE the
		// scanned tree (reading data not under it) and bypass the size cap. Only
		// regular files are collected. (WalkDir does not follow symlinks, so this
		// also prevents traversing a symlinked directory.)
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			// Skip massive/irrelevant subtrees (node_modules, .git, any hidden dir)
			// so the walk does not scan huge trees that never hold MCP config. The
			// walk ROOT is never skipped, even if it is itself hidden.
			if p != path && skipDirName(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !isConfigFile(d.Name()) {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}
		// Only regular files are collected: a FIFO/device would block the read
		// indefinitely, and non-regular files are not config sources.
		if !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() > maxFileSize {
			return nil
		}
		// Stop once the file-count cap is reached. Log it so the truncation is
		// observable rather than a silent partial collection.
		if len(sources) >= maxFiles {
			slog.Warn("recon.MCPConfig: file count cap reached; truncating directory walk",
				"max_files", maxFiles, "path", path)
			return filepath.SkipAll
		}
		// #nosec G304 -- entry under the operator-designated config directory being walked for collection.
		content, readErr := os.ReadFile(filepath.Clean(p))
		if readErr != nil {
			return nil
		}
		sources = append(sources, source{label: p, content: string(content)})
		// Stop once the cumulative-byte cap is reached so a large tree cannot make
		// the module buffer tens of GiB. Log it so the truncation is observable.
		totalBytes += int64(len(content))
		if totalBytes >= maxTotalBytes {
			slog.Warn("recon.MCPConfig: cumulative byte cap reached; truncating directory walk",
				"max_total_bytes", maxTotalBytes, "path", path)
			return filepath.SkipAll
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return sources, nil
}

// skipDirName reports whether a subdirectory should not be descended into: large
// dependency trees (node_modules) and VCS / hidden directories (.git and any
// dotfile-prefixed dir) never hold MCP config and only slow the walk. Applies to
// DIRECTORIES only — ".env*" FILES are still collected (see isConfigFile).
func skipDirName(name string) bool {
	return name == "node_modules" || strings.HasPrefix(name, ".")
}

// isConfigFile reports whether a filename should be scanned as configuration.
// The name and extension are lowercased first so mixed-case files (config.JSON,
// config.Yaml, .ENV) are still recognized.
func isConfigFile(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, ".env") {
		return true
	}
	return configExtensions[strings.ToLower(filepath.Ext(name))]
}

// MCPConfig is a single collected configuration source decoded from a store
// observation: the origin label and the verbatim content.
type MCPConfig struct {
	Source  string
	Content string
}

// ConfigsFrom decodes every MCP config observation held by the store back into a
// typed MCPConfig. It is the reader counterpart to the writer in (*Module).Recon:
// both sides agree on ObservationTypeConfig and the payload schema, so this
// package remains the single source of truth for the mcp.config observation shape.
//
// Observations of other types, and observations whose payload fails to decode,
// are skipped. A nil store yields no configs.
func ConfigsFrom(store *recon.Store) []MCPConfig {
	if store == nil {
		return nil
	}
	var out []MCPConfig
	for _, o := range store.Observations() {
		if o.Type != ObservationTypeConfig {
			continue
		}
		var content string
		if err := json.Unmarshal(o.Data, &content); err != nil {
			continue
		}
		out = append(out, MCPConfig{Source: o.Target, Content: content})
	}
	return out
}
