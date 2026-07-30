package mcp

import (
	"context"
	"errors"
	"fmt"
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
	got, err := listAll(func(cursor string) ([]int, string, error) {
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
// non-empty cursor forever must not loop indefinitely.
func TestListAll_StopsOnCursorRepeat(t *testing.T) {
	calls := 0
	got, err := listAll(func(_ string) ([]int, string, error) {
		calls++
		return []int{calls}, "loop", nil // always the same next cursor
	})
	if err != nil {
		t.Fatalf("listAll: %v", err)
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
	_, err := listAll(func(_ string) ([]int, string, error) {
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
	items, err := listAll(func(_ string) ([]int, string, error) {
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
