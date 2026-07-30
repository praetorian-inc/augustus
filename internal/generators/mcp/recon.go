package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
		lim := m.walkLimits()

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
		// cannot hide poisoned or hostile definitions on a later page behind a benign
		// first page. listAll derives a fresh walk budget per call, so a slow
		// tools/list cannot starve the resource and prompt catalogs.
		//
		// A catalog that stopped early is recorded in inv.Incomplete: the inventory is
		// then a lower bound on the surface, and a consumer must not score it as if it
		// were the whole one.
		markIncomplete := func(catalog string, truncated bool) {
			if truncated {
				inv.Incomplete = append(inv.Incomplete, catalog)
			}
		}

		if inv.Capabilities.Tools {
			tools, truncated, err := reconList(ctx, lim, types.MCPCatalogTools, func(pctx context.Context, cursor string) ([]*mcpsdk.Tool, string, error) {
				res, err := sess.ListTools(pctx, &mcpsdk.ListToolsParams{Cursor: cursor})
				if err != nil {
					return nil, "", err
				}
				return res.Tools, res.NextCursor, nil
			})
			if err != nil {
				return err
			}
			inv.Tools = mcpToolsFrom(tools)
			markIncomplete(types.MCPCatalogTools, truncated)
		}
		if inv.Capabilities.Resources {
			resources, truncated, err := reconList(ctx, lim, types.MCPCatalogResources, func(pctx context.Context, cursor string) ([]*mcpsdk.Resource, string, error) {
				r, err := sess.ListResources(pctx, &mcpsdk.ListResourcesParams{Cursor: cursor})
				if err != nil {
					return nil, "", err
				}
				return r.Resources, r.NextCursor, nil
			})
			if err != nil {
				return err
			}
			inv.Resources = mcpResourcesFrom(resources)
			markIncomplete(types.MCPCatalogResources, truncated)

			templates, truncated, err := reconList(ctx, lim, types.MCPCatalogResourceTemplates, func(pctx context.Context, cursor string) ([]*mcpsdk.ResourceTemplate, string, error) {
				r, err := sess.ListResourceTemplates(pctx, &mcpsdk.ListResourceTemplatesParams{Cursor: cursor})
				if err != nil {
					return nil, "", err
				}
				return r.ResourceTemplates, r.NextCursor, nil
			})
			if err != nil {
				return err
			}
			inv.ResourceTemplates = mcpResourceTemplatesFrom(templates)
			markIncomplete(types.MCPCatalogResourceTemplates, truncated)
		}
		if inv.Capabilities.Prompts {
			prompts, truncated, err := reconList(ctx, lim, types.MCPCatalogPrompts, func(pctx context.Context, cursor string) ([]*mcpsdk.Prompt, string, error) {
				r, err := sess.ListPrompts(pctx, &mcpsdk.ListPromptsParams{Cursor: cursor})
				if err != nil {
					return nil, "", err
				}
				return r.Prompts, r.NextCursor, nil
			})
			if err != nil {
				return err
			}
			inv.Prompts = mcpPromptsFrom(prompts)
			markIncomplete(types.MCPCatalogPrompts, truncated)
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

// walkLimits are the two deadlines that bound one paginated catalog enumeration.
// Config documents RequestTimeout as the deadline for each individual call, so
// Page is applied per page rather than to a whole walk: one deadline shared across
// pages would make a slow multi-page catalog fail partway and report EMPTY, which
// is a worse answer than the truncated one this helper exists to produce.
//
// Walk then bounds the enumeration as a whole. Per-page deadlines alone leave the
// page COUNT capped by maxListPages but the total time uncapped, and a hostile
// server answering each page just under the per-page deadline could stall a scan
// for hours — both --timeout and --probe-timeout default to no timeout, and the
// recon phase sets no deadline at all.
type walkLimits struct {
	Walk time.Duration // wall-clock bound for the whole enumeration
	Page time.Duration // deadline for a single page

	// BeforePage, when set, runs before every page request. It carries the
	// generator's rate limiter: withSession waits once per session, so without a
	// per-page wait a paginated walk could fire up to maxListPages requests
	// back-to-back and blow straight through a configured request rate — against a
	// customer's production MCP server, in a tool whose whole job is to be pointed
	// at infrastructure someone else owns.
	BeforePage func(context.Context) error
}

// walkLimits reports the enumeration deadlines for this generator. listAll derives
// a FRESH Walk budget per call, so every catalog is bounded independently: one
// budget shared across tools, resources, resource templates, and prompts would let
// a large or deliberately slow tool list exhaust it and force every later catalog
// to come back empty — hiding hostile resource and prompt definitions behind a
// slow tools/list, the very failure this bound exists to prevent.
func (m *MCP) walkLimits() walkLimits {
	return walkLimits{
		Walk:       listWalkBudgetFactor * m.cfg.RequestTimeout,
		Page:       m.cfg.RequestTimeout,
		BeforePage: m.waitLimit,
	}
}

// waitLimit charges one token to the configured rate limiter, or does nothing when
// no limit is configured.
func (m *MCP) waitLimit(ctx context.Context) error {
	if m.limiter == nil {
		return nil
	}
	if err := m.limiter.Wait(ctx); err != nil {
		return fmt.Errorf("mcp: rate limit wait cancelled: %w", err)
	}
	return nil
}

const (
	// maxListPages caps catalog pagination so a server that repeats or never
	// terminates its cursor cannot hang the scan. Real MCP catalogs are far smaller.
	maxListPages = 1000

	// listWalkBudgetFactor sets the whole-enumeration wall-clock budget as a
	// multiple of the per-page RequestTimeout (10 minutes at the 60s default) —
	// ample for any legitimate catalog, while bounding a deliberate stall.
	listWalkBudgetFactor = 10

	// maxListItems bounds how many server-controlled entries one enumeration will
	// accumulate. The page cap alone bounds the number of REQUESTS, not the volume:
	// a hostile server can return large pages and, well inside the page and
	// wall-clock bounds, drive the scanner into memory exhaustion. Overflow is
	// reported as truncation, so an oversized catalog degrades to a marked-partial
	// result rather than an OOM. Far above any real MCP catalog.
	maxListItems = 50_000
)

// errListTruncated signals that pagination stopped early with a cursor still
// pending — at maxListPages, on a repeated cursor, or with the walk budget spent.
// The catalog was NOT fully enumerated: callers keep the items gathered so far but
// must not treat the enumeration as complete (a hostile catalog could hide content
// on the pages that were never fetched).
// It WRAPS types.ErrCatalogTruncated so the same failure is recognisable from
// outside this package: consumers in internal/recon and internal/probes cannot test
// an unexported sentinel, and a cross-package errors.Is that silently never matches
// would disable their fail-closed handling without any signal.
var errListTruncated = fmt.Errorf("mcp: catalog pagination stopped early; results may be incomplete: %w", types.ErrCatalogTruncated)

// listAll follows an MCP list operation's nextCursor across all pages,
// accumulating items. It owns both enumeration deadlines: a fresh whole-walk
// budget (so each call is bounded independently) and a per-page deadline derived
// FROM that budget, so an in-flight page can never push the walk past its bound.
// list receives the page context and returns one page's items plus the next cursor
// ("" when there are no more pages).
//
// Exactly one condition means "the catalog ended": the server returned an empty
// nextCursor. Every other stop leaves a cursor pending and returns
// errListTruncated with the items collected so far — never a silent
// partial-as-complete. Caller cancellation is distinct from both and propagates.
func listAll[T any](ctx context.Context, lim walkLimits, list func(pctx context.Context, cursor string) ([]T, string, error)) ([]T, error) {
	walkCtx, cancelWalk := context.WithTimeout(ctx, lim.Walk)
	defer cancelWalk()

	var out []T
	seen := make(map[string]bool)
	cursor := ""
	for range maxListPages {
		// The caller aborting — scan shutdown, --timeout, Ctrl-C — is NOT truncation.
		// Reporting it as such would have the scan carry on against a partial catalog
		// it was told to stop building, so propagate it and let the caller unwind.
		// Checked before walkCtx because walkCtx derives from ctx and would otherwise
		// mask a cancellation as our own budget expiring.
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if walkCtx.Err() != nil {
			return out, errListTruncated
		}

		// Charge the rate limiter per page, not once per walk. Bounded by walkCtx so a
		// long wait counts against the enumeration budget; a wait cut short by that
		// budget is truncation, and a caller abort still propagates.
		if lim.BeforePage != nil {
			if err := lim.BeforePage(walkCtx); err != nil {
				if ctx.Err() == nil && walkCtx.Err() != nil {
					return out, errListTruncated
				}
				return out, err
			}
		}

		// Page deadline derives from walkCtx, so it is min(Page, walk remaining): a
		// page starting just before the budget expires cannot overrun it.
		pctx, cancelPage := context.WithTimeout(walkCtx, lim.Page)
		items, next, err := list(pctx, cursor)
		cancelPage()
		if err != nil {
			// Classify by WHICH deadline fired, not by the error the SDK surfaced. A
			// page cut short because the walk budget ran out is truncation — keep the
			// pages we have. Reporting it as a transport failure would collapse the
			// catalog to empty, which is the outcome this whole bound exists to avoid.
			if ctx.Err() == nil && walkCtx.Err() != nil {
				return out, errListTruncated
			}
			return out, err
		}

		out = append(out, items...)
		if next == "" {
			return out, nil
		}
		// Volume bound: pages remain, so this is truncation like every other early
		// stop — never a complete catalog.
		if len(out) >= maxListItems {
			return out, errListTruncated
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

// reconList runs one paginated catalog enumeration for the inventory. It reports
// the items, whether the enumeration was truncated (so the inventory can carry a
// machine-readable completeness marker), and a fatal error.
//
// Three outcomes, deliberately distinct:
//   - truncated: keep what was gathered, warn, mark the catalog incomplete
//   - a failed list call: leave that catalog empty and warn, preserving the
//     best-effort contract that a partially reachable SERVER still yields a usable
//     fingerprint rather than failing the whole inventory
//   - the CALLER aborted: return the error. Best-effort emptiness exists for an
//     unreachable server, not for a scan being torn down — flattening a Ctrl-C or a
//     --timeout into "empty catalogs" would hand back a successful-looking inventory
//     that merely looks like a target with nothing on it.
func reconList[T any](ctx context.Context, lim walkLimits, catalog string, list func(pctx context.Context, cursor string) ([]T, string, error)) ([]T, bool, error) {
	items, err := listAll(ctx, lim, list)
	switch {
	case err == nil:
		return items, false, nil
	case errors.Is(err, errListTruncated):
		slog.Warn("recon.MCP: catalog enumeration stopped early; results may be incomplete",
			"catalog", catalog, "collected", len(items), "page_cap", maxListPages)
		return items, true, nil
	case ctx.Err() != nil:
		return nil, true, err
	default:
		slog.Warn("recon.MCP: catalog enumeration failed; leaving it empty",
			"catalog", catalog, "error", err)
		return nil, true, nil
	}
}
