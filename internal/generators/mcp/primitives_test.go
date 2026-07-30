package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// newPrimitiveServer builds an MCP server exposing one resource and two prompt
// templates (one with an argument, one without) so the resources/read and
// prompts/get client methods can be exercised end to end over a real transport.
func newPrimitiveServer() *mcpsdk.Server {
	srv := mcpsdk.NewServer(&mcpsdk.Implementation{Name: "augustus-primitive-server", Version: "v0"}, nil)

	srv.AddResource(
		&mcpsdk.Resource{URI: "file:///notes.txt", Name: "notes", MIMEType: "text/plain"},
		func(_ context.Context, req *mcpsdk.ReadResourceRequest) (*mcpsdk.ReadResourceResult, error) {
			return &mcpsdk.ReadResourceResult{Contents: []*mcpsdk.ResourceContents{
				{URI: req.Params.URI, MIMEType: "text/plain", Text: "first block"},
				{URI: req.Params.URI, MIMEType: "text/plain", Text: "second block"},
			}}, nil
		})

	srv.AddPrompt(
		&mcpsdk.Prompt{
			Name:      "greet",
			Arguments: []*mcpsdk.PromptArgument{{Name: "who", Required: true}},
		},
		func(_ context.Context, req *mcpsdk.GetPromptRequest) (*mcpsdk.GetPromptResult, error) {
			return &mcpsdk.GetPromptResult{
				Description: "greeting template",
				Messages: []*mcpsdk.PromptMessage{
					{Role: "user", Content: &mcpsdk.TextContent{Text: "hello " + req.Params.Arguments["who"]}},
					{Role: "user", Content: &mcpsdk.TextContent{Text: "second message"}},
				},
			}, nil
		})

	return srv
}

func newPrimitiveTarget(t *testing.T) string {
	t.Helper()
	handler := mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server {
		return newPrimitiveServer()
	}, nil)
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts.URL
}

func newPrimitiveGen(t *testing.T) types.MCPPrimitiveReader {
	t.Helper()
	g := newGen(t, registry.Config{"endpoint": newPrimitiveTarget(t), "transport": "http"})
	reader, ok := g.(types.MCPPrimitiveReader)
	if !ok {
		t.Fatalf("mcp.MCP does not implement types.MCPPrimitiveReader")
	}
	return reader
}

// TestReadResource_AssemblesBlocks verifies a multi-block resources/read response
// is flattened into one scannable string while the block count and raw payload
// survive for callers that need them.
func TestReadResource_AssemblesBlocks(t *testing.T) {
	res, err := newPrimitiveGen(t).ReadResource(context.Background(), "file:///notes.txt")
	if err != nil {
		t.Fatalf("ReadResource() error = %v", err)
	}
	if !strings.Contains(res.Text, "first block") || !strings.Contains(res.Text, "second block") {
		t.Errorf("Text did not assemble both blocks: %q", res.Text)
	}
	if res.Blocks != 2 {
		t.Errorf("Blocks = %d, want 2", res.Blocks)
	}
	if res.MIMEType != "text/plain" {
		t.Errorf("MIMEType = %q, want text/plain", res.MIMEType)
	}
	if res.URI != "file:///notes.txt" {
		t.Errorf("URI = %q, want the requested URI", res.URI)
	}
	if len(res.Raw) == 0 {
		t.Error("Raw is empty; the structured payload should be preserved")
	}
}

// TestReadResource_UnknownURIErrors pins the denial contract: resources/read has
// no application-level error flag, so a refused read must surface as a Go error.
// The probes rely on this to tell a refusal apart from an empty body.
func TestReadResource_UnknownURIErrors(t *testing.T) {
	_, err := newPrimitiveGen(t).ReadResource(context.Background(), "file:///etc/passwd")
	if err == nil {
		t.Fatal("ReadResource() on an unserved URI returned nil error; a refusal must be an error")
	}
	if !strings.Contains(err.Error(), "resources/read") {
		t.Errorf("error should name the failing call, got %v", err)
	}
}

// TestGetPrompt_RendersArguments verifies prompts/get passes string arguments
// through and assembles every rendered message.
func TestGetPrompt_RendersArguments(t *testing.T) {
	res, err := newPrimitiveGen(t).GetPrompt(context.Background(), "greet", map[string]string{"who": "world"})
	if err != nil {
		t.Fatalf("GetPrompt() error = %v", err)
	}
	if !strings.Contains(res.Text, "hello world") {
		t.Errorf("Text did not carry the rendered argument: %q", res.Text)
	}
	if !strings.Contains(res.Text, "second message") {
		t.Errorf("Text did not assemble all messages: %q", res.Text)
	}
	if res.Messages != 2 {
		t.Errorf("Messages = %d, want 2", res.Messages)
	}
	if res.Description != "greeting template" {
		t.Errorf("Description = %q, want the server-supplied description", res.Description)
	}
	if res.Name != "greet" {
		t.Errorf("Name = %q, want greet", res.Name)
	}
}

// TestGetPrompt_UnknownNameErrors is the prompts/get half of the denial contract.
func TestGetPrompt_UnknownNameErrors(t *testing.T) {
	_, err := newPrimitiveGen(t).GetPrompt(context.Background(), "nonexistent", nil)
	if err == nil {
		t.Fatal("GetPrompt() on an unknown template returned nil error; a refusal must be an error")
	}
	if !strings.Contains(err.Error(), "prompts/get") {
		t.Errorf("error should name the failing call, got %v", err)
	}
}

// TestMCPInventory_EnumeratesPrimitives confirms the catalog the probes consume
// actually carries the resource and prompt entries this server serves — the
// discovery half that PromptInjection cannot work without.
func TestMCPInventory_EnumeratesPrimitives(t *testing.T) {
	g := newGen(t, registry.Config{"endpoint": newPrimitiveTarget(t), "transport": "http"})
	rec, ok := g.(types.MCPReconnaissance)
	if !ok {
		t.Fatal("mcp.MCP does not implement types.MCPReconnaissance")
	}
	inv, err := rec.MCPInventory(context.Background())
	if err != nil {
		t.Fatalf("MCPInventory() error = %v", err)
	}
	if len(inv.Resources) != 1 || inv.Resources[0].URI != "file:///notes.txt" {
		t.Errorf("Resources = %+v, want the one served resource", inv.Resources)
	}
	if len(inv.Prompts) != 1 || inv.Prompts[0].Name != "greet" {
		t.Errorf("Prompts = %+v, want the one served prompt", inv.Prompts)
	}
	if len(inv.Prompts) == 1 && len(inv.Prompts[0].Arguments) != 1 {
		t.Errorf("prompt arguments = %+v, want the declared 'who' argument", inv.Prompts[0].Arguments)
	}
}
