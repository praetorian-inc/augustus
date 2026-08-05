package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// testLimits are generous enumeration deadlines for the unit tests: they exercise
// cursor semantics, not timing, so neither bound should ever fire.
var testLimits = walkLimits{Walk: time.Minute, Page: 10 * time.Second}

// TestListAll_FollowsCursors: listAll accumulates items across every page,
// following nextCursor until it is empty.
func TestListAll_FollowsCursors(t *testing.T) {
	pages := map[string]struct {
		items []int
		next  string
	}{
		"":   {[]int{1, 2}, "c1"},
		"c1": {[]int{3}, "c2"},
		"c2": {[]int{4}, ""}, // last page
	}
	got, err := listAll(context.Background(), testLimits, func(_ context.Context, cursor string) ([]int, string, error) {
		p := pages[cursor]
		return p.items, p.next, nil
	})
	if err != nil {
		t.Fatalf("listAll: %v", err)
	}
	if fmt.Sprint(got) != "[1 2 3 4]" {
		t.Errorf("got %v, want [1 2 3 4] (all pages followed)", got)
	}
}

// TestListAll_StopsOnCursorRepeat: a hostile/buggy server that returns the same
// non-empty cursor forever must not loop indefinitely, and must report the walk as
// TRUNCATED rather than complete — a cursor is still pending, so a repeat is the
// same "pages we never fetched" situation as the page cap and the walk budget.
// Reporting completion here would let a server halt the walk after page one and
// have the partial catalog pass as the target's full attack surface.
func TestListAll_StopsOnCursorRepeat(t *testing.T) {
	calls := 0
	got, err := listAll(context.Background(), testLimits, func(_ context.Context, _ string) ([]int, string, error) {
		calls++
		return []int{calls}, "loop", nil // always the same next cursor
	})
	if !errors.Is(err, errListTruncated) {
		t.Fatalf("listAll err = %v, want errListTruncated on a repeated cursor", err)
	}
	if calls > 2 {
		t.Errorf("cursor repeat not detected: %d calls (want <= 2)", calls)
	}
	if len(got) == 0 {
		t.Error("expected the first page's items to be retained")
	}
}

// TestListAll_PropagatesError: a page error is returned (with the pages gathered
// so far), not silently swallowed.
func TestListAll_PropagatesError(t *testing.T) {
	_, err := listAll(context.Background(), testLimits, func(_ context.Context, _ string) ([]int, string, error) {
		return nil, "", errors.New("boom")
	})
	if err == nil {
		t.Fatal("expected the page error to propagate")
	}
}

// TestListAll_ErrorsOnPageCapExhaustion: a catalog that keeps emitting fresh
// unique cursors past the page budget must surface errListTruncated (with the
// items gathered so far) rather than silently reporting a complete enumeration.
func TestListAll_ErrorsOnPageCapExhaustion(t *testing.T) {
	n := 0
	items, err := listAll(context.Background(), testLimits, func(_ context.Context, _ string) ([]int, string, error) {
		n++
		return []int{n}, fmt.Sprintf("cursor-%d", n), nil // always a new unique cursor
	})
	if !errors.Is(err, errListTruncated) {
		t.Fatalf("expected errListTruncated on cap exhaustion, got %v", err)
	}
	if len(items) != maxListPages {
		t.Errorf("expected %d items gathered before the cap, got %d", maxListPages, len(items))
	}
}

// --- end-to-end: a genuinely paginating server over the real wire protocol ---
//
// The listAll unit tests above cover the helper in isolation; these drive all
// three catalog-consuming paths against an SDK server that really splits its
// catalogs into pages. They are the regression guard that matters: each one
// fails against a single-page (cursor-ignoring) client.

const (
	paginatedPageSize  = 2
	paginatedToolCount = 5 // spans 3 pages at the page size above
)

// newPaginatedTarget starts an httptest MCP server over streamable HTTP whose
// tool, resource, resource-template, and prompt catalogs are all served in pages
// of paginatedPageSize. A client that reads only the first page sees a truncated
// catalog, which is exactly the under-scan this fix prevents.
func newPaginatedTarget(t *testing.T) string {
	t.Helper()

	handler := mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server {
		srv := mcpsdk.NewServer(
			&mcpsdk.Implementation{Name: "augustus-paginated-server", Version: "v0"},
			&mcpsdk.ServerOptions{PageSize: paginatedPageSize},
		)
		for i := range paginatedToolCount {
			mcpsdk.AddTool(srv,
				&mcpsdk.Tool{Name: toolPageName(i), Description: "page-spanning tool"},
				func(_ context.Context, _ *mcpsdk.CallToolRequest, _ toolInput) (*mcpsdk.CallToolResult, any, error) {
					return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: "ok"}}}, nil, nil
				})
			srv.AddResource(
				&mcpsdk.Resource{URI: fmt.Sprintf("file:///res-%02d.txt", i), Name: fmt.Sprintf("res-%02d", i)},
				func(_ context.Context, _ *mcpsdk.ReadResourceRequest) (*mcpsdk.ReadResourceResult, error) {
					return &mcpsdk.ReadResourceResult{}, nil
				})
			srv.AddResourceTemplate(
				&mcpsdk.ResourceTemplate{URITemplate: fmt.Sprintf("file:///tpl-%02d/{id}", i), Name: fmt.Sprintf("tpl-%02d", i)},
				func(_ context.Context, _ *mcpsdk.ReadResourceRequest) (*mcpsdk.ReadResourceResult, error) {
					return &mcpsdk.ReadResourceResult{}, nil
				})
			srv.AddPrompt(
				&mcpsdk.Prompt{Name: fmt.Sprintf("prompt-%02d", i)},
				func(_ context.Context, _ *mcpsdk.GetPromptRequest) (*mcpsdk.GetPromptResult, error) {
					return &mcpsdk.GetPromptResult{}, nil
				})
		}
		return srv
	}, nil)

	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts.URL
}

func toolPageName(i int) string { return fmt.Sprintf("tool-%02d", i) }

// TestToolInvoker_ListTools_EnumeratesEveryPage: the ToolInvoker path every
// mcptool.* probe uses must return the whole catalog. Reading only page one here
// would silently shrink the attack surface all those probes test.
func TestToolInvoker_ListTools_EnumeratesEveryPage(t *testing.T) {
	inv := newGen(t, registry.Config{
		"transport": "http",
		"endpoint":  newPaginatedTarget(t),
	}).(types.ToolInvoker)

	tools, err := inv.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools) != paginatedToolCount {
		t.Fatalf("ListTools returned %d tools, want %d (later pages dropped)", len(tools), paginatedToolCount)
	}

	got := make(map[string]bool, len(tools))
	for _, tm := range tools {
		name, _ := tm["name"].(string)
		got[name] = true
	}
	for i := range paginatedToolCount {
		if !got[toolPageName(i)] {
			t.Errorf("tool %q missing from the enumerated catalog", toolPageName(i))
		}
	}
}

// TestMCPInventory_EnumeratesEveryPage: recon.MCP's inventory must span all pages
// of every catalog it collects, so downstream context-aware probes inherit the
// full surface rather than page one.
func TestMCPInventory_EnumeratesEveryPage(t *testing.T) {
	rec := newGen(t, registry.Config{
		"transport": "http",
		"endpoint":  newPaginatedTarget(t),
	}).(types.MCPReconnaissance)

	inv, err := rec.MCPInventory(context.Background())
	if err != nil {
		t.Fatalf("MCPInventory: %v", err)
	}

	for _, tc := range []struct {
		catalog string
		got     int
	}{
		{"tools", len(inv.Tools)},
		{"resources", len(inv.Resources)},
		{"resource templates", len(inv.ResourceTemplates)},
		{"prompts", len(inv.Prompts)},
	} {
		if tc.got != paginatedToolCount {
			t.Errorf("inventory %s = %d, want %d (later pages dropped)", tc.catalog, tc.got, paginatedToolCount)
		}
	}
}

// TestGenerate_ListToolsMode_EnumeratesEveryPage: the mode:list_tools rendering
// path feeds detectors that inspect advertised names/descriptions/schemas, so a
// tool parked on a later page must still reach them.
func TestGenerate_ListToolsMode_EnumeratesEveryPage(t *testing.T) {
	g := newGen(t, registry.Config{
		"transport": "http",
		"endpoint":  newPaginatedTarget(t),
		"mode":      "list_tools",
	})

	got := generate(t, g, "ignored prompt")
	for i := range paginatedToolCount {
		if !strings.Contains(got, toolPageName(i)) {
			t.Errorf("list_tools output missing %q (later pages dropped); got:\n%s", toolPageName(i), got)
		}
	}
}

// TestPagination_PerPageDeadline: RequestTimeout is documented as the deadline
// for each individual call, so every page must get its own budget rather than all
// pages splitting one. Sharing a single deadline across pages would make a slow
// multi-page catalog fail partway and — through reconList's best-effort path —
// report an EMPTY catalog, a worse answer than the truncated enumeration the
// pagination helper exists to avoid.
//
// The server below delays every response, so the pages together take longer than
// one RequestTimeout while each page comfortably fits inside one.
func TestPagination_PerPageDeadline(t *testing.T) {
	t.Parallel()

	const (
		perRequestDelay = 350 * time.Millisecond
		toolCount       = 8 // 8 pages at PageSize 1 => ~2.8s total, well past the 2s budget
		requestTimeout  = 2 * time.Second
	)

	handler := mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server {
		srv := mcpsdk.NewServer(
			&mcpsdk.Implementation{Name: "augustus-slow-paginated-server", Version: "v0"},
			&mcpsdk.ServerOptions{PageSize: 1},
		)
		for i := range toolCount {
			mcpsdk.AddTool(srv, &mcpsdk.Tool{Name: toolPageName(i), Description: "slow page"},
				func(_ context.Context, _ *mcpsdk.CallToolRequest, _ toolInput) (*mcpsdk.CallToolResult, any, error) {
					return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: "ok"}}}, nil, nil
				})
		}
		return srv
	}, nil)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(perRequestDelay)
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)

	inv := newGen(t, registry.Config{
		"transport":       "http",
		"endpoint":        ts.URL,
		"request_timeout": 2, // seconds; must bound each page, not the whole walk
	}).(types.ToolInvoker)

	tools, err := inv.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools: %v (a per-page deadline should not have expired)", err)
	}
	if len(tools) != toolCount {
		t.Errorf("ListTools returned %d tools, want %d — pages appear to be sharing one %v budget",
			len(tools), toolCount, requestTimeout)
	}
}

// TestPagination_WholeWalkIsTimeBounded: pageCtx gives every page its own
// RequestTimeout, so maxListPages caps the page COUNT but nothing caps total
// wall-clock. Both --timeout and --probe-timeout default to no timeout and the
// recon phase sets no deadline, so without walkCtx a hostile server answering
// each page just under the per-page deadline could stall a scan for hours.
//
// Exhausting the walk budget must degrade to truncation — a partial catalog plus
// a warning — and never to an error or an empty result, so a merely slow server
// still yields the pages it did serve.
func TestPagination_WholeWalkIsTimeBounded(t *testing.T) {
	t.Parallel()

	const (
		requestTimeout = 0.5                    // seconds => 500ms per page, 5s whole walk
		perPageDelay   = 200 * time.Millisecond // 2.5x headroom under the per-page budget
		toolCount      = 40                     // 8s of pages against a 5s walk budget
	)

	handler := mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server {
		srv := mcpsdk.NewServer(
			&mcpsdk.Implementation{Name: "augustus-stalling-server", Version: "v0"},
			&mcpsdk.ServerOptions{PageSize: 1},
		)
		for i := range toolCount {
			mcpsdk.AddTool(srv, &mcpsdk.Tool{Name: toolPageName(i), Description: "stalling page"},
				func(_ context.Context, _ *mcpsdk.CallToolRequest, _ toolInput) (*mcpsdk.CallToolResult, any, error) {
					return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: "ok"}}}, nil, nil
				})
		}
		return srv
	}, nil)

	// Delay only the paginated listing, so connect/handshake keeps its own budget
	// and the test isolates the walk bound rather than racing the handshake.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, err := io.ReadAll(r.Body); err == nil {
			r.Body = io.NopCloser(bytes.NewReader(body))
			if bytes.Contains(body, []byte("tools/list")) {
				time.Sleep(perPageDelay)
			}
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)

	inv := newGen(t, registry.Config{
		"transport":       "http",
		"endpoint":        ts.URL,
		"request_timeout": requestTimeout,
	}).(types.ToolInvoker)

	start := time.Now()
	tools, err := inv.ListTools(context.Background())
	elapsed := time.Since(start)

	// A spent walk budget is classified as TRUNCATION, not a transport failure, which
	// ListTools then surfaces to its caller as a fail-closed error. Both halves matter:
	// the classification is what keeps the partial catalog (rather than collapsing it
	// to empty), and the error is what stops a probe scoring that partial as clean.
	if !errors.Is(err, errListTruncated) {
		t.Fatalf("ListTools err = %v, want it to wrap errListTruncated", err)
	}

	// The bound itself, asserted on page count rather than elapsed time: the
	// server-side delay means an unbounded walk MUST serve all 40 pages, so this
	// check is exact and machine-independent. An elapsed-time assertion would
	// overlap the 5s bound too closely to survive a loaded or parallel CI box.
	if len(tools) == toolCount {
		t.Errorf("enumerated all %d pages in %v, so the walk budget never applied", toolCount, elapsed)
	}

	// Graceful degradation: truncation keeps what was served rather than discarding it.
	if len(tools) == 0 {
		t.Error("walk budget exhaustion emptied the catalog; the pages already served must be kept")
	}
}

// TestListAll_PropagatesCallerCancellation: a cancelled CALLER context means the
// scan is being torn down (shutdown, --timeout, Ctrl-C). That is not truncation —
// reporting it as such would have callers log "results may be incomplete" and
// carry on against a catalog they were told to stop building. The cancellation
// must surface so the caller unwinds.
func TestListAll_PropagatesCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := listAll(ctx, testLimits, func(_ context.Context, _ string) ([]int, string, error) {
		t.Error("list should not be called once the caller has cancelled")
		return nil, "", nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("listAll err = %v, want context.Canceled (not masked as truncation)", err)
	}
	if errors.Is(err, errListTruncated) {
		t.Error("caller cancellation was reported as truncation")
	}
}

// TestListAll_WalkBudgetIsTruncationNotCancellation: the mirror of the test above.
// Our own walk budget expiring IS truncation — partial results plus a warning —
// and must not be confused with the caller cancelling.
func TestListAll_WalkBudgetIsTruncationNotCancellation(t *testing.T) {
	t.Parallel()

	// One page is served, then the budget is gone. It has to be spent AFTER a page:
	// a budget exhausted before any request reaches the server is a configuration
	// problem, reported separately (see TestListAll_StarvedWalkIsNotBlamedOnTheServer).
	lim := walkLimits{Walk: 60 * time.Millisecond, Page: time.Second}
	calls := 0
	items, err := listAll(context.Background(), lim, func(_ context.Context, _ string) ([]int, string, error) {
		calls++
		time.Sleep(70 * time.Millisecond) // outlives the walk budget
		return []int{calls}, fmt.Sprintf("cursor-%d", calls), nil
	})
	if !errors.Is(err, errListTruncated) {
		t.Fatalf("listAll err = %v, want errListTruncated for a spent walk budget", err)
	}
	if len(items) == 0 {
		t.Error("the page that was served before the budget expired must be kept")
	}
}

// newSlowToolsTarget starts a paginating MCP server that delays ONLY tools/list,
// one tool per page. With a short request_timeout the tools walk exhausts its
// budget and truncates, while the resource and prompt catalogs answer instantly.
func newSlowToolsTarget(t *testing.T, delay time.Duration, count int) string {
	t.Helper()

	handler := mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server {
		srv := mcpsdk.NewServer(
			&mcpsdk.Implementation{Name: "augustus-slow-tools-server", Version: "v0"},
			&mcpsdk.ServerOptions{PageSize: 1},
		)
		for i := range count {
			mcpsdk.AddTool(srv, &mcpsdk.Tool{Name: toolPageName(i), Description: "slow tool page"},
				func(_ context.Context, _ *mcpsdk.CallToolRequest, _ toolInput) (*mcpsdk.CallToolResult, any, error) {
					return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: "ok"}}}, nil, nil
				})
			srv.AddResource(
				&mcpsdk.Resource{URI: fmt.Sprintf("file:///res-%02d.txt", i), Name: fmt.Sprintf("res-%02d", i)},
				func(_ context.Context, _ *mcpsdk.ReadResourceRequest) (*mcpsdk.ReadResourceResult, error) {
					return &mcpsdk.ReadResourceResult{}, nil
				})
			srv.AddPrompt(
				&mcpsdk.Prompt{Name: fmt.Sprintf("prompt-%02d", i)},
				func(_ context.Context, _ *mcpsdk.GetPromptRequest) (*mcpsdk.GetPromptResult, error) {
					return &mcpsdk.GetPromptResult{}, nil
				})
		}
		return srv
	}, nil)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, err := io.ReadAll(r.Body); err == nil {
			r.Body = io.NopCloser(bytes.NewReader(body))
			if bytes.Contains(body, []byte("tools/list")) {
				time.Sleep(delay)
			}
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

// TestListTools_DoesNotMemoizeTruncatedCatalog: the tools cache lives for the
// whole session, so a known-incomplete catalog must never be stored — otherwise
// every later probe silently reuses the partial tool surface with no further
// warning. Serve the truncated set to this caller, but leave the cache empty so
// the next caller gets a fresh walk.
func TestListTools_DoesNotMemoizeTruncatedCatalog(t *testing.T) {
	t.Parallel()

	const toolCount = 40
	g := newGen(t, registry.Config{
		"transport":       "http",
		"endpoint":        newSlowToolsTarget(t, 100*time.Millisecond, toolCount),
		"request_timeout": 0.2, // 200ms per page, 2s whole walk => 40 pages truncate
	}).(*MCP)

	tools, err := g.ListTools(context.Background())
	// A truncated enumeration fails closed: probes must skip the target rather than
	// scan a partial prefix and report clean. The partial catalog is still returned
	// alongside the error for a caller that deliberately wants best-effort data.
	if !errors.Is(err, errListTruncated) {
		t.Fatalf("ListTools err = %v, want errListTruncated on a truncated walk", err)
	}
	if len(tools) == 0 || len(tools) == toolCount {
		t.Fatalf("expected a truncated walk, got %d of %d tools", len(tools), toolCount)
	}

	g.toolsMu.Lock()
	cached := g.toolsCache
	g.toolsMu.Unlock()
	if cached != nil {
		t.Errorf("a truncated catalog (%d of %d tools) was memoized for the session", len(cached), toolCount)
	}
}

// TestMCPInventory_WalkBudgetIsPerCatalog: each catalog enumeration gets its own
// walk budget. Sharing one across tools/resources/prompts would let a slow or
// deliberately stalling tools/list exhaust it and force every later catalog to
// come back EMPTY — hiding hostile resource and prompt definitions behind a slow
// tool list, which is the opposite of what this bound is for.
func TestMCPInventory_WalkBudgetIsPerCatalog(t *testing.T) {
	t.Parallel()

	const count = 40
	rec := newGen(t, registry.Config{
		"transport":       "http",
		"endpoint":        newSlowToolsTarget(t, 100*time.Millisecond, count),
		"request_timeout": 0.2, // tools/list will burn its 2s budget; the rest are instant
	}).(types.MCPReconnaissance)

	inv, err := rec.MCPInventory(context.Background())
	if err != nil {
		t.Fatalf("MCPInventory: %v", err)
	}

	if len(inv.Tools) == count {
		t.Fatalf("tools catalog was not truncated (%d of %d); the test premise no longer holds", len(inv.Tools), count)
	}
	if len(inv.Resources) != count {
		t.Errorf("resources = %d, want %d — a slow tools/list starved a later catalog", len(inv.Resources), count)
	}
	if len(inv.Prompts) != count {
		t.Errorf("prompts = %d, want %d — a slow tools/list starved a later catalog", len(inv.Prompts), count)
	}
}

// TestListTools_RawResponseCarriesEveryPage: LastRawResponse documents "the most
// recent tool list", and runtime hooks write it to a file and inspect it. Storing
// each page as it arrived would leave only the FINAL page visible, so a hook
// scanning a paginated catalog would see one tool where the target advertised
// several — a silent fidelity loss for anything reading the raw surface.
func TestListTools_RawResponseCarriesEveryPage(t *testing.T) {
	t.Parallel()

	g := newGen(t, registry.Config{
		"transport": "http",
		"endpoint":  newPaginatedTarget(t),
	}).(*MCP)

	if _, err := g.ListTools(context.Background()); err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	raw := string(g.LastRawResponse())
	if raw == "" {
		t.Fatal("LastRawResponse is empty after a tools/list walk")
	}
	for i := range paginatedToolCount {
		if !strings.Contains(raw, toolPageName(i)) {
			t.Errorf("LastRawResponse is missing %q; it holds only part of the catalog:\n%s",
				toolPageName(i), raw)
		}
	}
}

// TestGenerate_ListToolsMode_MarksTruncatedCatalog: the rendered catalog IS the
// artifact a detector scores on the mode:list_tools path, so a truncated walk must
// say so there and not only in the operator log — otherwise a detector judges a
// partial tool surface as if it were the target's whole one and reports clean.
// The notice must be absent on a complete walk, so normal output stays untouched.
func TestGenerate_ListToolsMode_MarksTruncatedCatalog(t *testing.T) {
	t.Parallel()

	const toolCount = 40
	truncating := newGen(t, registry.Config{
		"transport":       "http",
		"endpoint":        newSlowToolsTarget(t, 100*time.Millisecond, toolCount),
		"request_timeout": 0.2, // 200ms per page, 2s whole walk => truncates
		"mode":            "list_tools",
	})

	got := generate(t, truncating, "ignored prompt")
	if !strings.Contains(got, truncationNotice) {
		t.Errorf("truncated catalog rendered with no incompleteness notice:\n%s", got)
	}

	// A complete walk must NOT carry the notice: scanner metadata in the detector's
	// input is only justified when it is true.
	complete := newGen(t, registry.Config{
		"transport": "http",
		"endpoint":  newPaginatedTarget(t),
		"mode":      "list_tools",
	})
	if out := generate(t, complete, "ignored prompt"); strings.Contains(out, truncationNotice) {
		t.Errorf("a fully enumerated catalog was marked truncated:\n%s", out)
	}
}

// TestListTools_FailsClosedOnTruncation: returning a knowingly partial catalog with
// a nil error would reproduce this branch's own bug one layer up — a server can halt
// the walk after a benign prefix, and every mcptool.* probe would scan that prefix,
// find nothing, and report the target clean. An honest error beats a false pass.
func TestListTools_FailsClosedOnTruncation(t *testing.T) {
	t.Parallel()

	const toolCount = 40
	inv := newGen(t, registry.Config{
		"transport":       "http",
		"endpoint":        newSlowToolsTarget(t, 100*time.Millisecond, toolCount),
		"request_timeout": 0.2,
	}).(types.ToolInvoker)

	tools, err := inv.ListTools(context.Background())
	if err == nil {
		t.Fatal("a truncated catalog was returned with a nil error; probes would score a partial surface as clean")
	}
	if !errors.Is(err, errListTruncated) {
		t.Errorf("err = %v, want it to wrap errListTruncated so callers can classify it", err)
	}
	// Best-effort data still travels with the error, for a caller that wants it.
	if len(tools) == 0 {
		t.Error("the pages that were enumerated should still be returned alongside the error")
	}
}

// TestMCPInventory_MarksIncompleteCatalogs: the inventory must carry a
// machine-readable completeness marker. Without it, a truncated catalog is
// indistinguishable from a small one, and context-aware probes reuse it as though it
// described the target's whole surface.
func TestMCPInventory_MarksIncompleteCatalogs(t *testing.T) {
	t.Parallel()

	const count = 40
	rec := newGen(t, registry.Config{
		"transport":       "http",
		"endpoint":        newSlowToolsTarget(t, 100*time.Millisecond, count),
		"request_timeout": 0.2, // tools/list truncates; resources and prompts are instant
	}).(types.MCPReconnaissance)

	inv, err := rec.MCPInventory(context.Background())
	if err != nil {
		t.Fatalf("MCPInventory: %v", err)
	}

	if inv.IsComplete() {
		t.Error("a truncated tools catalog was reported as a complete inventory")
	}
	if !slices.Contains(inv.Incomplete, "tools") {
		t.Errorf("Incomplete = %v, want it to name \"tools\"", inv.Incomplete)
	}
	// Only the catalog that actually truncated is marked — the marker has to be
	// precise, or a consumer cannot tell which part of the surface it is missing.
	for _, complete := range []string{"resources", "prompts"} {
		if slices.Contains(inv.Incomplete, complete) {
			t.Errorf("%q was marked incomplete but enumerated fully", complete)
		}
	}
}

// TestMCPInventory_CompleteWalkHasNoMarker: the marker must stay absent on a full
// enumeration, so it serializes away and a complete inventory is byte-identical to
// what earlier versions emitted.
func TestMCPInventory_CompleteWalkHasNoMarker(t *testing.T) {
	t.Parallel()

	rec := newGen(t, registry.Config{
		"transport": "http",
		"endpoint":  newPaginatedTarget(t),
	}).(types.MCPReconnaissance)

	inv, err := rec.MCPInventory(context.Background())
	if err != nil {
		t.Fatalf("MCPInventory: %v", err)
	}
	if !inv.IsComplete() {
		t.Errorf("a fully enumerated inventory was marked incomplete: %v", inv.Incomplete)
	}

	raw, err := json.Marshal(inv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "incomplete") {
		t.Errorf("the completeness marker leaked into a complete inventory's JSON:\n%s", raw)
	}
}

// TestConfig_ClampsNonPositiveRequestTimeout: 0 means "no timeout" elsewhere in
// Augustus, but as a deadline it is already expired — every page would fail instantly
// and the scan would report an empty tool surface instead of an error.
func TestConfig_ClampsNonPositiveRequestTimeout(t *testing.T) {
	t.Parallel()

	def := DefaultConfig().RequestTimeout
	for _, v := range []any{0, -5, 0.0} {
		cfg, err := ConfigFromMap(registry.Config{"endpoint": "http://example.invalid/mcp", "request_timeout": v})
		if err != nil {
			t.Fatalf("ConfigFromMap(request_timeout=%v): %v", v, err)
		}
		if cfg.RequestTimeout != def {
			t.Errorf("request_timeout=%v gave %v, want the %v default (a non-positive deadline expires instantly)", v, cfg.RequestTimeout, def)
		}
	}
}

// TestListAll_PageDeadlineIsBoundedByWalkBudget: each page's deadline must be
// min(Page, walk remaining). Deriving it from the caller instead would let a page
// that starts just before the walk budget expires run a further full Page timeout,
// so the advertised whole-walk bound could be overrun by up to one request_timeout.
//
// Asserted on the deadline the page actually receives rather than on elapsed time:
// the overshoot is at most 10% of the walk budget (Walk is 10x Page), which is far
// too small for a timing assertion to catch reliably.
func TestListAll_PageDeadlineIsBoundedByWalkBudget(t *testing.T) {
	t.Parallel()

	// A Page allowance far larger than Walk: the walk bound must dominate.
	lim := walkLimits{Walk: 100 * time.Millisecond, Page: 10 * time.Second}
	start := time.Now()

	var pageDeadlines []time.Time
	_, _ = listAll(context.Background(), lim, func(pctx context.Context, _ string) ([]int, string, error) {
		dl, ok := pctx.Deadline()
		if !ok {
			t.Error("page context carries no deadline")
			return nil, "", nil
		}
		pageDeadlines = append(pageDeadlines, dl)
		// A genuinely fresh cursor each time, so the walk really does run until a bound
		// stops it rather than tripping the cursor-repeat check after two pages.
		return []int{1}, fmt.Sprintf("cursor-%d", len(pageDeadlines)), nil
	})

	if len(pageDeadlines) == 0 {
		t.Fatal("list was never called")
	}
	walkDeadline := start.Add(lim.Walk)
	for i, dl := range pageDeadlines {
		if dl.After(walkDeadline.Add(5 * time.Millisecond)) {
			t.Errorf("page %d deadline is %v past the walk deadline; a page can overrun the whole-walk bound",
				i, dl.Sub(walkDeadline))
		}
	}
}

// TestListAll_PageDeadlineWalkBoundRunsManyPages guards the premise of the test
// above: with fresh cursors the walk is stopped by a bound, not by cursor-repeat
// detection, so the deadline assertion is exercised across many pages.
func TestListAll_PageDeadlineWalkBoundRunsManyPages(t *testing.T) {
	t.Parallel()

	calls := 0
	_, err := listAll(context.Background(), walkLimits{Walk: 50 * time.Millisecond, Page: time.Minute},
		func(_ context.Context, _ string) ([]int, string, error) {
			calls++
			return []int{calls}, fmt.Sprintf("cursor-%d", calls), nil
		})
	if !errors.Is(err, errListTruncated) {
		t.Fatalf("err = %v, want errListTruncated from a bound", err)
	}
	if calls < 3 {
		t.Errorf("only %d pages walked; the walk ended too early to exercise the deadline bound", calls)
	}
}

// TestReconList_PropagatesCallerCancellation: listAll classifies a caller abort as a
// cancellation rather than truncation, but that only matters if the consumer honours
// it. reconList's best-effort "leave the catalog empty" contract exists for a
// partially reachable SERVER; applying it to a Ctrl-C or an expired --timeout would
// let MCPInventory hand back a successful-looking inventory whose empty catalogs are
// indistinguishable from a target that simply advertises nothing.
//
// Asserted directly on reconList rather than through MCPInventory: a context that is
// already cancelled fails at session acquisition, so an end-to-end test would pass
// without ever reaching this code path.
func TestReconList_PropagatesCallerCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	items, truncated, err := reconList(ctx, testLimits, "tools", func(_ context.Context, _ string) ([]int, string, error) {
		t.Error("list should not be called once the caller has cancelled")
		return nil, "", nil
	})
	if err == nil {
		t.Fatal("reconList swallowed a caller cancellation; MCPInventory would report a successful empty inventory")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want it to wrap context.Canceled", err)
	}
	if items != nil {
		t.Errorf("items = %v, want nil on cancellation", items)
	}
	if truncated {
		t.Error("cancellation was reported as pagination truncation; they are distinct outcomes")
	}
}

// TestReconList_ListFailureStaysBestEffort: the counterpart. A failing list call is
// NOT a cancellation — the inventory contract deliberately leaves that catalog empty
// so a partially reachable server still yields a usable fingerprint, rather than
// failing the whole inventory.
func TestReconList_ListFailureStaysBestEffort(t *testing.T) {
	t.Parallel()

	items, truncated, err := reconList(context.Background(), testLimits, "tools",
		func(_ context.Context, _ string) ([]int, string, error) {
			return nil, "", errors.New("server said no")
		})
	if err != nil {
		t.Errorf("err = %v, want nil: a failed list call stays best-effort, not fatal", err)
	}
	if items != nil {
		t.Errorf("items = %v, want nil for a failed catalog", items)
	}
	if !truncated {
		t.Error("a failed enumeration must be marked incomplete, not reported as complete")
	}
}

// TestErrListTruncated_IsRecognisableAcrossPackages: the internal sentinel must wrap
// the exported one. Consumers in internal/recon and internal/probes cannot test an
// unexported error, so if this chain breaks their fail-closed handling stops firing —
// silently, with no compile error and no failing assertion anywhere else. That is the
// worst shape of bug for this branch, so it gets its own guard.
func TestErrListTruncated_IsRecognisableAcrossPackages(t *testing.T) {
	t.Parallel()

	if !errors.Is(errListTruncated, types.ErrCatalogTruncated) {
		t.Error("errListTruncated no longer wraps types.ErrCatalogTruncated; cross-package truncation handling is now dead code")
	}

	// And through the wrapping ListTools actually performs.
	wrapped := fmt.Errorf("mcp: refusing to report a partial tool catalog as complete (%d tools enumerated): %w", 3, errListTruncated)
	if !errors.Is(wrapped, types.ErrCatalogTruncated) {
		t.Error("ListTools' error does not surface types.ErrCatalogTruncated to callers")
	}
	if !errors.Is(wrapped, errListTruncated) {
		t.Error("ListTools' error no longer matches the internal sentinel either")
	}
}

// TestListAll_ChargesRateLimiterPerPage: withSession waits on the limiter once per
// session, so before this a paginated walk could fire up to maxListPages requests
// back-to-back and blow straight through a configured request rate — against a
// customer's production MCP server, in a tool whose entire job is to be pointed at
// infrastructure someone else owns.
func TestListAll_ChargesRateLimiterPerPage(t *testing.T) {
	t.Parallel()

	const pages = 4
	waits := 0
	lim := walkLimits{
		Walk: time.Minute, Page: 10 * time.Second,
		BeforePage: func(context.Context) error { waits++; return nil },
	}

	n := 0
	_, err := listAll(context.Background(), lim, func(_ context.Context, _ string) ([]int, string, error) {
		n++
		if n >= pages {
			return []int{n}, "", nil // last page
		}
		return []int{n}, fmt.Sprintf("cursor-%d", n), nil
	})
	if err != nil {
		t.Fatalf("listAll: %v", err)
	}
	// pages-1: page 0 rides on withSession's charge, so a one-page catalog costs one
	// token. Anything less than this means later pages are bursting past the rate.
	if waits != pages-1 {
		t.Errorf("limiter charged %d times for %d pages; want %d (page 0 rides on withSession's token)", waits, pages, pages-1)
	}
}

// TestListAll_RateLimiterErrorPropagates: a limiter wait cut short by the caller must
// not be laundered into truncation — same distinction the page path already makes.
func TestListAll_RateLimiterErrorPropagates(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("limiter cancelled")
	calls := 0
	// Page 0 is not charged, so the walk must advance to page 1 for the limiter to be
	// consulted at all — hence the fresh cursor.
	_, err := listAll(context.Background(), walkLimits{
		Walk: time.Minute, Page: time.Second,
		BeforePage: func(context.Context) error { return sentinel },
	}, func(_ context.Context, _ string) ([]int, string, error) {
		calls++
		if calls > 1 {
			t.Error("list was called again after the limiter wait failed")
		}
		return []int{calls}, "cursor-1", nil
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want the limiter error to propagate", err)
	}
	if errors.Is(err, errListTruncated) {
		t.Error("a limiter failure was misreported as truncation")
	}
}

// TestListAll_BoundsTotalItems: the page cap bounds the number of REQUESTS, not the
// volume. A hostile server returning large pages can drive the scanner into memory
// exhaustion well inside the page and wall-clock bounds, so an oversized catalog must
// degrade to a marked-partial result rather than an OOM.
func TestListAll_BoundsTotalItems(t *testing.T) {
	t.Parallel()

	// 600 items per page: the cap falls mid-page, so the check cannot rely on landing
	// exactly on a page boundary. Fresh cursors each time, or cursor-repeat detection
	// would stop the walk at two pages and the item bound would never be reached.
	page := make([]int, 600)
	n := 0
	items, err := listAll(context.Background(), testLimits, func(_ context.Context, _ string) ([]int, string, error) {
		n++
		return page, fmt.Sprintf("cursor-%d", n), nil
	})
	if !errors.Is(err, errListTruncated) {
		t.Fatalf("err = %v, want errListTruncated once the item bound is hit", err)
	}
	if len(items) < maxListItems {
		t.Errorf("stopped at %d items, expected to collect at least the %d bound", len(items), maxListItems)
	}
	if len(items) > maxListItems+len(page) {
		t.Errorf("collected %d items, more than one page past the %d bound", len(items), maxListItems)
	}
}

// TestWalkLimits_WiresTheRateLimiter: TestListAll_ChargesRateLimiterPerPage proves
// listAll CALLS BeforePage, but it supplies its own hook, so it cannot catch the
// generator failing to wire the limiter in. This asserts the wiring itself — and that
// the hook really throttles, not merely that it is non-nil.
func TestWalkLimits_WiresTheRateLimiter(t *testing.T) {
	t.Parallel()

	g := newGen(t, registry.Config{
		"transport":  "http",
		"endpoint":   "http://example.invalid/mcp",
		"rate_limit": 5.0, // 5/s, bucket capacity 5
	}).(*MCP)

	lim := g.walkLimits()
	if lim.BeforePage == nil {
		t.Fatal("walkLimits did not wire the rate limiter; pagination would burst past the configured rate")
	}

	// Capacity is 5, so the first 5 charges are free and the next 3 must wait ~3/5s.
	// Asserting a floor, never a ceiling — a slow box can only make this slower.
	start := time.Now()
	for i := range 8 {
		if err := lim.BeforePage(context.Background()); err != nil {
			t.Fatalf("charge %d: %v", i, err)
		}
	}
	if elapsed := time.Since(start); elapsed < 300*time.Millisecond {
		t.Errorf("8 charges against a 5/s limit took only %v; the hook is not actually throttling", elapsed)
	}
}

// TestListAllTools_TruncationDoesNotEscapeToSessionRetry pins the invariant behind a
// round-5 review finding that turned out to be a false positive.
//
// withSession retries its callback once when the callback returns a non-context
// error, on the assumption a reused persistent session went stale. So a truncation
// error must never be returned FROM that callback: if it were, a truncated walk would
// be silently repeated after a reconnect, doubling attacker-controlled work and
// potentially masking the first truncation behind a second, different catalog.
//
// It does not escape today — listAllTools reports truncation via its bool and keeps
// err nil, and ListTools builds the fail-closed error only after withSession has
// returned. This test exists so that stays true: moving the error inside the callback
// would be an easy and invisible refactor to get wrong.
func TestListAllTools_TruncationDoesNotEscapeToSessionRetry(t *testing.T) {
	t.Parallel()

	g := newGen(t, registry.Config{
		"transport":       "http",
		"endpoint":        newSlowToolsTarget(t, 100*time.Millisecond, 40),
		"request_timeout": 0.2, // walk budget 2s => the 40-page walk truncates
	}).(*MCP)

	sess, _, release, err := g.acquireSession(context.Background())
	if err != nil {
		t.Fatalf("acquireSession: %v", err)
	}
	defer release()

	tools, truncated, err := g.listAllTools(context.Background(), sess)
	if !truncated {
		t.Fatalf("expected a truncated walk (got %d tools); the test premise no longer holds", len(tools))
	}
	if err != nil {
		t.Errorf("listAllTools returned err = %v on truncation; withSession would treat it as a stale session and repeat the whole walk", err)
	}
	if errors.Is(err, errListTruncated) {
		t.Error("the truncation sentinel reached the withSession callback boundary")
	}
}

// TestListAll_ItemBoundHoldsAgainstOneHugePage: the volume bound must cap the total,
// not the total-plus-one-page. A server returning a single oversized page — terminal
// or not — must not slip past the cap, and dropping items makes the result truncated
// even when the server claimed that page was the last.
func TestListAll_ItemBoundHoldsAgainstOneHugePage(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		next string
	}{
		{"nonterminal huge page", "more"},
		{"terminal huge page", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			huge := make([]int, maxListItems*3)
			items, err := listAll(context.Background(), testLimits,
				func(_ context.Context, _ string) ([]int, string, error) {
					return huge, tc.next, nil
				})
			if !errors.Is(err, errListTruncated) {
				t.Errorf("err = %v, want errListTruncated: items were dropped, so the catalog is incomplete", err)
			}
			if len(items) != maxListItems {
				t.Errorf("collected %d items, want exactly the %d bound", len(items), maxListItems)
			}
		})
	}
}

// TestListTools_LowRateLimitDoesNotFabricateTruncation reproduces the round-5 Codex
// scenario. A configured rate below one request per second floors the token bucket at
// a single token; withSession spends it, so charging the first page again meant
// waiting for a refill that outlasts the whole walk budget. The walk then died with
// zero pages and was reported as truncation — a fail-closed error on a perfectly
// healthy target, caused by our own accounting rather than anything the server did.
//
// The first page must ride on withSession's charge, so a single-page catalog needs no
// refill at all.
func TestListTools_LowRateLimitDoesNotFabricateTruncation(t *testing.T) {
	t.Parallel()

	// A SINGLE-page catalog: the whole point is that one page must cost one token.
	// (A genuinely multi-page catalog under a rate this slow cannot be enumerated
	// inside the budget at all, and truncating there is honest — see walkLimits.)
	url, _ := newHTTPTarget(t)
	inv := newGen(t, registry.Config{
		"transport":       "http",
		"endpoint":        url,
		"request_timeout": 0.5,  // page 500ms, whole walk 5s
		"rate_limit":      0.05, // one token per 20s, bucket capacity floored at 1
	}).(types.ToolInvoker)

	tools, err := inv.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools: %v — a low rate limit must not fabricate truncation on a healthy target", err)
	}
	if len(tools) == 0 {
		t.Error("returned an empty catalog; the first page should ride on withSession's token")
	}
}

// TestListAll_StarvedWalkIsNotBlamedOnTheServer: when the budget expires before a
// single page is fetched, the cause is our own configuration, not the target. Saying
// "truncated" there hands the operator a hostile-server verdict for a config problem.
func TestListAll_StarvedWalkIsNotBlamedOnTheServer(t *testing.T) {
	t.Parallel()

	_, err := listAll(context.Background(), walkLimits{Walk: time.Nanosecond, Page: time.Second},
		func(_ context.Context, _ string) ([]int, string, error) {
			t.Error("list should not be called with the budget already spent")
			return nil, "", nil
		})
	if errors.Is(err, errListTruncated) {
		t.Error("a starved walk was reported as server truncation")
	}
	if err == nil || !strings.Contains(err.Error(), "before the first page was fetched") {
		t.Errorf("err = %v, want it to name the configuration cause", err)
	}
}
