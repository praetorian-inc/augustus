package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
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
	inv := &types.MCPInventory{}

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

		// Each catalog is paginated: follow nextCursor across all pages so a server
		// cannot hide poisoned/hostile definitions on a later page behind a benign
		// first page. listAll bounds pages and detects cursor repetition.
		if inv.Capabilities.Tools {
			inv.Tools = mcpToolsFrom(reconList("tools", func(cursor string) ([]*mcpsdk.Tool, string, error) {
				res, err := sess.ListTools(callCtx, &mcpsdk.ListToolsParams{Cursor: cursor})
				if err != nil {
					return nil, "", err
				}
				return res.Tools, res.NextCursor, nil
			}))
		}
		if inv.Capabilities.Resources {
			inv.Resources = mcpResourcesFrom(reconList("resources", func(cursor string) ([]*mcpsdk.Resource, string, error) {
				r, err := sess.ListResources(callCtx, &mcpsdk.ListResourcesParams{Cursor: cursor})
				if err != nil {
					return nil, "", err
				}
				return r.Resources, r.NextCursor, nil
			}))
			inv.ResourceTemplates = mcpResourceTemplatesFrom(reconList("resource_templates", func(cursor string) ([]*mcpsdk.ResourceTemplate, string, error) {
				r, err := sess.ListResourceTemplates(callCtx, &mcpsdk.ListResourceTemplatesParams{Cursor: cursor})
				if err != nil {
					return nil, "", err
				}
				return r.ResourceTemplates, r.NextCursor, nil
			}))
		}
		if inv.Capabilities.Prompts {
			inv.Prompts = mcpPromptsFrom(reconList("prompts", func(cursor string) ([]*mcpsdk.Prompt, string, error) {
				r, err := sess.ListPrompts(callCtx, &mcpsdk.ListPromptsParams{Cursor: cursor})
				if err != nil {
					return nil, "", err
				}
				return r.Prompts, r.NextCursor, nil
			}))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Record the transport actually used, not the configured value: an "auto"
	// target resolves to a concrete "http"/"sse" during connect, and the
	// inventory should report what it really connected over.
	inv.Transport = m.resolvedTransport()

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
		mt := types.MCPTool{Name: t.Name, Title: t.Title, Description: t.Description, Annotations: annotationsFrom(t.Annotations)}
		if t.InputSchema != nil {
			if raw, err := json.Marshal(t.InputSchema); err == nil {
				mt.InputSchema = raw
			}
		}
		out = append(out, mt)
	}
	return out
}

// annotationsFrom maps the SDK's tool annotations to the descriptive recon type,
// returning nil when the tool declared none so consumers can tell "no hints" from
// "hints, all false". It is the single converter used by both the recon-inventory
// path (mcpToolsFrom) and the live ListTools path (toolsToMaps).
func annotationsFrom(a *mcpsdk.ToolAnnotations) *types.MCPToolAnnotations {
	if a == nil {
		return nil
	}
	return &types.MCPToolAnnotations{
		ReadOnly:    a.ReadOnlyHint,
		Destructive: a.DestructiveHint,
		Idempotent:  a.IdempotentHint,
		OpenWorld:   a.OpenWorldHint,
		Title:       a.Title,
	}
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

// maxListPages caps catalog pagination so a server that repeats or never
// terminates its cursor cannot hang the scan. Real MCP catalogs are far smaller.
const maxListPages = 1000

// errListTruncated signals that pagination stopped at maxListPages with a cursor
// still pending — the catalog was NOT fully enumerated. Callers keep the items
// gathered so far but must not treat the enumeration as complete (a hostile
// catalog could hide content past the cap).
var errListTruncated = errors.New("mcp: catalog pagination exceeded page cap; results may be incomplete")

// listAll follows an MCP list operation's nextCursor across all pages,
// accumulating items. It guards against a hostile/buggy server with a hard page
// cap and cursor-repeat detection. list must return one page's items plus the
// next cursor ("" when there are no more pages) for the given cursor. It returns
// errListTruncated (with the items collected so far) if the page budget is
// exhausted while a fresh cursor is still pending — never a silent partial-as-complete.
func listAll[T any](list func(cursor string) ([]T, string, error)) ([]T, error) {
	var out []T
	seen := make(map[string]bool)
	cursor := ""
	for range maxListPages {
		items, next, err := list(cursor)
		if err != nil {
			return out, err
		}
		out = append(out, items...)
		if next == "" || seen[next] {
			return out, nil
		}
		seen[next] = true
		cursor = next
	}
	return out, errListTruncated
}

// reconList runs a paginated catalog enumeration for the inventory. On a
// truncated-at-cap result it keeps what was gathered but logs a warning so the
// partial catalog is never mistaken for a complete one; on any other list error
// it returns nil, preserving the best-effort "leave that catalog empty" behavior.
func reconList[T any](catalog string, list func(cursor string) ([]T, string, error)) []T {
	items, err := listAll(list)
	if err == nil {
		return items
	}
	if errors.Is(err, errListTruncated) {
		slog.Warn("recon.MCP: catalog truncated at page cap; results may be incomplete",
			"catalog", catalog, "pages", maxListPages)
		return items
	}
	return nil
}
