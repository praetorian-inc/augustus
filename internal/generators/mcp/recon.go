package mcp

import (
	"context"
	"encoding/json"
	"sort"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/praetorian-inc/augustus/pkg/types"
)

// Compile-time assertion that MCP exposes MCP reconnaissance.
var _ types.MCPReconnaissance = (*MCP)(nil)

// MCPInventory implements types.MCPReconnaissance. It reads the connected
// session's InitializeResult (declared capabilities, negotiated protocol
// version, server instructions/info) and enumerates the tool, resource,
// resource-template, and prompt catalog into a raw, JSON-serializable inventory.
//
// It assembles ONLY raw data: suspicious-pattern scanning is the probe/detector
// layer's job, so Flags is left empty here. Catalog enumeration is gated on the
// server's declared capabilities and is best-effort — a list call that fails
// leaves that catalog empty rather than failing the whole inventory, so a
// partially reachable server still yields a usable fingerprint.
func (m *MCP) MCPInventory(ctx context.Context) (*types.MCPInventory, error) {
	inv := &types.MCPInventory{Transport: m.cfg.Transport}

	err := m.withSession(ctx, func(ctx context.Context, sess *mcpsdk.ClientSession) error {
		callCtx, cancel := context.WithTimeout(ctx, m.cfg.RequestTimeout)
		defer cancel()

		if init := sess.InitializeResult(); init != nil {
			inv.ProtocolVersion = init.ProtocolVersion
			inv.Instructions = init.Instructions
			if init.ServerInfo != nil {
				inv.ServerName = init.ServerInfo.Name
				inv.ServerVersion = init.ServerInfo.Version
			}
			inv.Capabilities = capabilitiesFrom(init.Capabilities)
		}

		if inv.Capabilities.Tools {
			if res, e := sess.ListTools(callCtx, nil); e == nil {
				inv.Tools = mcpToolsFrom(res.Tools)
			}
		}
		if inv.Capabilities.Resources {
			if res, e := sess.ListResources(callCtx, nil); e == nil {
				inv.Resources = mcpResourcesFrom(res.Resources)
			}
			if res, e := sess.ListResourceTemplates(callCtx, nil); e == nil {
				inv.ResourceTemplates = mcpResourceTemplatesFrom(res.ResourceTemplates)
			}
		}
		if inv.Capabilities.Prompts {
			if res, e := sess.ListPrompts(callCtx, nil); e == nil {
				inv.Prompts = mcpPromptsFrom(res.Prompts)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	inv.Counts = types.MCPInventoryCounts{
		Tools:             len(inv.Tools),
		Resources:         len(inv.Resources),
		ResourceTemplates: len(inv.ResourceTemplates),
		Prompts:           len(inv.Prompts),
	}
	return inv, nil
}

// capabilitiesFrom maps the SDK's ServerCapabilities to the presence booleans
// (plus experimental/extension keys) recorded in the inventory.
func capabilitiesFrom(c *mcpsdk.ServerCapabilities) types.MCPCapabilities {
	caps := types.MCPCapabilities{}
	if c == nil {
		return caps
	}
	caps.Tools = c.Tools != nil
	caps.Resources = c.Resources != nil
	caps.Prompts = c.Prompts != nil
	caps.Logging = c.Logging != nil
	caps.Completions = c.Completions != nil
	caps.Experimental = sortedKeys(c.Experimental)
	caps.Extensions = sortedKeys(c.Extensions)
	return caps
}

func sortedKeys(m map[string]any) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mcpToolsFrom(tools []*mcpsdk.Tool) []types.MCPTool {
	out := make([]types.MCPTool, 0, len(tools))
	for _, t := range tools {
		if t == nil {
			continue
		}
		mt := types.MCPTool{Name: t.Name, Title: t.Title, Description: t.Description}
		if t.InputSchema != nil {
			if raw, err := json.Marshal(t.InputSchema); err == nil {
				mt.InputSchema = raw
			}
		}
		out = append(out, mt)
	}
	return out
}

func mcpResourcesFrom(res []*mcpsdk.Resource) []types.MCPResource {
	out := make([]types.MCPResource, 0, len(res))
	for _, r := range res {
		if r == nil {
			continue
		}
		out = append(out, types.MCPResource{
			URI:         r.URI,
			Name:        r.Name,
			Title:       r.Title,
			Description: r.Description,
			MIMEType:    r.MIMEType,
		})
	}
	return out
}

func mcpResourceTemplatesFrom(tpls []*mcpsdk.ResourceTemplate) []types.MCPResourceTemplate {
	out := make([]types.MCPResourceTemplate, 0, len(tpls))
	for _, t := range tpls {
		if t == nil {
			continue
		}
		out = append(out, types.MCPResourceTemplate{
			URITemplate: t.URITemplate,
			Name:        t.Name,
			Title:       t.Title,
			Description: t.Description,
			MIMEType:    t.MIMEType,
		})
	}
	return out
}

func mcpPromptsFrom(prompts []*mcpsdk.Prompt) []types.MCPPrompt {
	out := make([]types.MCPPrompt, 0, len(prompts))
	for _, p := range prompts {
		if p == nil {
			continue
		}
		mp := types.MCPPrompt{Name: p.Name, Title: p.Title, Description: p.Description}
		for _, arg := range p.Arguments {
			if arg == nil {
				continue
			}
			mp.Arguments = append(mp.Arguments, types.MCPPromptArgument{
				Name:        arg.Name,
				Description: arg.Description,
				Required:    arg.Required,
			})
		}
		out = append(out, mp)
	}
	return out
}
