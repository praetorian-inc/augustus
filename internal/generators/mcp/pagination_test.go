package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

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
	got, err := listAll(context.Background(), context.Background(), func(cursor string) ([]int, string, error) {
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
	got, err := listAll(context.Background(), context.Background(), func(_ string) ([]int, string, error) {
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
	_, err := listAll(context.Background(), context.Background(), func(_ string) ([]int, string, error) {
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
	items, err := listAll(context.Background(), context.Background(), func(_ string) ([]int, string, error) {
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

	if err != nil {
		t.Fatalf("ListTools: %v — a spent walk budget must degrade to truncation, not an error", err)
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

	_, err := listAll(ctx, context.Background(), func(_ string) ([]int, string, error) {
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
	walkCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := listAll(context.Background(), walkCtx, func(_ string) ([]int, string, error) {
		t.Error("list should not be called once the walk budget is spent")
		return nil, "", nil
	})
	if !errors.Is(err, errListTruncated) {
		t.Fatalf("listAll err = %v, want errListTruncated for a spent walk budget", err)
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
	if err != nil {
		t.Fatalf("ListTools: %v", err)
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
