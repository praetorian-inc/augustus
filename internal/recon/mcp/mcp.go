// Package mcp provides the MCP reconnaissance module.
//
// It enumerates an MCP server's attack surface — declared capabilities,
// negotiated protocol version, server instructions, and the tool / resource /
// resource-template / prompt catalog — and emits it as a single descriptive
// output.Observation. It renders no verdict: reconnaissance measures, it does
// not test. (Detecting whether that surface is malicious — e.g. tool poisoning
// — is a separate test probe's job.)
package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/output"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// ObservationTypeInventory is the stable slug for the MCP attack-surface
// inventory observation.
const ObservationTypeInventory = "mcp.inventory"

func init() {
	recon.Register("recon.MCP", New)
}

// Compile-time assertion.
var _ recon.Recon = (*MCP)(nil)

// MCP is the MCP reconnaissance module.
type MCP struct{}

// New constructs the module.
func New(_ registry.Config) (recon.Recon, error) { return &MCP{}, nil }

// Name returns the fully qualified module name.
func (m *MCP) Name() string { return "recon.MCP" }

// Recon enumerates the target's MCP attack surface via the generator's
// MCPReconnaissance capability and returns it as one inventory observation.
// Targets that are not MCP reconnaissance-capable yield no observations (skip).
func (m *MCP) Recon(ctx context.Context, gen types.Generator) ([]output.Observation, error) {
	rc, ok := gen.(types.MCPReconnaissance)
	if !ok {
		return nil, nil
	}

	inv, err := rc.MCPInventory(ctx)
	if err != nil {
		return nil, fmt.Errorf("recon.MCP: inventory: %w", err)
	}
	if inv == nil {
		return nil, nil
	}

	data, err := json.Marshal(inv)
	if err != nil {
		return nil, fmt.Errorf("recon.MCP: marshal inventory: %w", err)
	}

	return []output.Observation{{
		Type:   ObservationTypeInventory,
		Target: inv.ServerName,
		Data:   data,
		Source: m.Name(),
	}}, nil
}
