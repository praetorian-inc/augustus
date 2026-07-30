package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"time"

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
		budget := m.walkBudget()

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
		// first page. Each enumeration gets its OWN walk budget so a slow tools/list
		// cannot starve the resource and prompt catalogs into coming back empty.
		if inv.Capabilities.Tools {
			inv.Tools = mcpToolsFrom(reconList(ctx, budget, "tools", func(cursor string) ([]*mcpsdk.Tool, string, error) {
				pctx, cancel := m.pageCtx(ctx)
				defer cancel()
				res, err := sess.ListTools(pctx, &mcpsdk.ListToolsParams{Cursor: cursor})
				if err != nil {
					return nil, "", err
				}
				return res.Tools, res.NextCursor, nil
			}))
		}
		if inv.Capabilities.Resources {
			inv.Resources = mcpResourcesFrom(reconList(ctx, budget, "resources", func(cursor string) ([]*mcpsdk.Resource, string, error) {
				pctx, cancel := m.pageCtx(ctx)
				defer cancel()
				r, err := sess.ListResources(pctx, &mcpsdk.ListResourcesParams{Cursor: cursor})
				if err != nil {
					return nil, "", err
				}
				return r.Resources, r.NextCursor, nil
			}))
			inv.ResourceTemplates = mcpResourceTemplatesFrom(reconList(ctx, budget, "resource_templates", func(cursor string) ([]*mcpsdk.ResourceTemplate, string, error) {
				pctx, cancel := m.pageCtx(ctx)
				defer cancel()
				r, err := sess.ListResourceTemplates(pctx, &mcpsdk.ListResourceTemplatesParams{Cursor: cursor})
				if err != nil {
					return nil, "", err
				}
				return r.ResourceTemplates, r.NextCursor, nil
			}))
		}
		if inv.Capabilities.Prompts {
			inv.Prompts = mcpPromptsFrom(reconList(ctx, budget, "prompts", func(cursor string) ([]*mcpsdk.Prompt, string, error) {
				pctx, cancel := m.pageCtx(ctx)
				defer cancel()
				r, err := sess.ListPrompts(pctx, &mcpsdk.ListPromptsParams{Cursor: cursor})
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

// pageCtx derives the deadline for a single page of a paginated enumeration.
// Config documents RequestTimeout as the deadline for each individual call, so
// every page gets its own budget instead of all pages splitting one: sharing a
// single deadline across pages would make a slow multi-page catalog fail partway
// and report EMPTY, which is a worse answer than the truncated one this whole
// helper exists to avoid. walkCtx bounds the enumeration as a whole.
//
// Page deadlines derive from the caller's ctx, NOT from walkCtx, so a page
// already in flight when the overall budget runs out still completes on its own
// terms; listAll then stops cleanly at the next loop boundary and reports
// truncation, rather than surfacing a mid-request cancellation as a hard error.
func (m *MCP) pageCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, m.cfg.RequestTimeout)
}

// walkBudget is the wall-clock bound for ONE paginated catalog enumeration.
// Because pageCtx gives every page its own RequestTimeout, maxListPages caps the
// page COUNT but nothing caps the total: a hostile server answering each page
// just under the per-page deadline could stall a scan for hours, and both
// --timeout and --probe-timeout default to no timeout while the recon phase sets
// no deadline at all. Exhausting this budget is reported as truncation (partial
// catalog plus a warning), never as an error, so a merely slow server still
// yields the pages it did serve.
//
// It is deliberately PER CATALOG rather than per inventory: one budget shared
// across tools, resources, resource templates, and prompts would let a large or
// deliberately slow tool list exhaust it and force every later catalog to come
// back empty — hiding hostile resource and prompt definitions behind a slow
// tools/list, which is the very failure this bound exists to prevent.
func (m *MCP) walkBudget() time.Duration {
	return listWalkBudgetFactor * m.cfg.RequestTimeout
}

// walkCtx derives a fresh whole-enumeration budget for one catalog walk.
func (m *MCP) walkCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, m.walkBudget())
}

const (
	// maxListPages caps catalog pagination so a server that repeats or never
	// terminates its cursor cannot hang the scan. Real MCP catalogs are far smaller.
	maxListPages = 1000

	// listWalkBudgetFactor sets the whole-enumeration wall-clock budget as a
	// multiple of the per-page RequestTimeout (10 minutes at the 60s default) —
	// ample for any legitimate catalog, while bounding a deliberate stall.
	listWalkBudgetFactor = 10
)

// errListTruncated signals that pagination stopped early with a cursor still
// pending — at maxListPages, on a repeated cursor, or with the whole-enumeration
// budget spent. The catalog was NOT fully enumerated: callers keep the items
// gathered so far but must not treat the enumeration as complete (a hostile
// catalog could hide content on the pages that were never fetched).
var errListTruncated = errors.New("mcp: catalog pagination stopped early; results may be incomplete")

// listAll follows an MCP list operation's nextCursor across all pages,
// accumulating items. It guards against a hostile/buggy server with a hard page
// cap, cursor-repeat detection, and the walkCtx wall-clock budget. list must
// return one page's items plus the next cursor ("" when there are no more pages)
// for the given cursor.
//
// Exactly one condition means "the catalog ended": the server returned an empty
// nextCursor. Every other stop leaves a cursor pending and returns
// errListTruncated with the items collected so far — never a silent
// partial-as-complete. Caller cancellation is distinct from both and propagates.
func listAll[T any](ctx, walkCtx context.Context, list func(cursor string) ([]T, string, error)) ([]T, error) {
	var out []T
	seen := make(map[string]bool)
	cursor := ""
	for range maxListPages {
		// The caller aborting — scan shutdown, --timeout, Ctrl-C — is NOT truncation.
		// Reporting it as such would have the scan carry on against a partial catalog
		// it was told to stop building, so propagate it and let the caller unwind.
		// Checked before walkCtx because walkCtx is derived from ctx and would
		// otherwise mask a cancellation as our own budget expiring.
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if walkCtx.Err() != nil {
			return out, errListTruncated
		}
		items, next, err := list(cursor)
		if err != nil {
			return out, err
		}
		out = append(out, items...)
		if next == "" {
			return out, nil
		}
		// A cursor we have already followed means the server is looping: we cannot
		// make progress, and a cursor is still pending. That is truncation, not
		// completion — otherwise a hostile server could halt the walk after page one
		// by repeating a cursor and have the partial catalog reported as the target's
		// full attack surface, with no warning and nothing marking it incomplete.
		if seen[next] {
			return out, errListTruncated
		}
		seen[next] = true
		cursor = next
	}
	return out, errListTruncated
}

// reconList runs one paginated catalog enumeration for the inventory under its
// own walk budget. On a truncated result it keeps what was gathered but logs a
// warning so the partial catalog is never mistaken for a complete one; on any
// other list error it returns nil, preserving the best-effort "leave that catalog
// empty" behavior — but says so rather than failing silently.
func reconList[T any](ctx context.Context, budget time.Duration, catalog string, list func(cursor string) ([]T, string, error)) []T {
	walkCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	items, err := listAll(ctx, walkCtx, list)
	switch {
	case err == nil:
		return items
	case errors.Is(err, errListTruncated):
		slog.Warn("recon.MCP: catalog enumeration stopped early; results may be incomplete",
			"catalog", catalog, "collected", len(items), "page_cap", maxListPages)
		return items
	default:
		slog.Warn("recon.MCP: catalog enumeration failed; leaving it empty",
			"catalog", catalog, "error", err)
		return nil
	}
}
