package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/praetorian-inc/augustus/pkg/types"
)

// Compile-time assertion that MCP can read the non-tool primitives.
var _ types.MCPPrimitiveReader = (*MCP)(nil)

// ReadResource implements types.MCPPrimitiveReader: it fetches one resource by
// URI. Structurally identical to CallTool — it rides the same withSession
// lifecycle, rate limiter, per-call RequestTimeout, proxy/TLS settings and header
// injection — so a resource read inherits every transport guarantee a tool call
// already has.
//
// A server that refuses the URI (unknown resource, denied path) reports it as a
// JSON-RPC error, which surfaces here as a Go error. That is the denial signal:
// callers testing for an unrestricted read sink treat a returned body as
// acceptance and an error as refusal.
func (m *MCP) ReadResource(ctx context.Context, uri string) (types.MCPResourceResult, error) {
	var out types.MCPResourceResult
	err := m.withSession(ctx, func(ctx context.Context, sess *mcpsdk.ClientSession) error {
		callCtx, cancel := context.WithTimeout(ctx, m.cfg.RequestTimeout)
		defer cancel()
		result, err := sess.ReadResource(callCtx, &mcpsdk.ReadResourceParams{URI: uri})
		if err != nil {
			return fmt.Errorf("mcp: resources/read %q failed: %w", uri, err)
		}
		raw, _ := json.Marshal(result)
		m.rawMu.Lock()
		m.lastRawResp = raw
		m.rawMu.Unlock()
		out = types.MCPResourceResult{
			URI:      uri,
			Text:     resourceText(result.Contents),
			MIMEType: firstResourceMIME(result.Contents),
			Raw:      raw,
			Blocks:   len(result.Contents),
		}
		return nil
	})
	if err != nil {
		return types.MCPResourceResult{}, err
	}
	return out, nil
}

// GetPrompt implements types.MCPPrimitiveReader: it renders one prompt template
// with the supplied arguments and returns the assembled message text — what an
// MCP host would place into the model's context.
//
// Arguments are string-typed per the MCP spec (prompts declare argument names,
// not JSON schemas). A render the server rejects surfaces as a Go error.
func (m *MCP) GetPrompt(ctx context.Context, name string, args map[string]string) (types.MCPPromptResult, error) {
	var out types.MCPPromptResult
	err := m.withSession(ctx, func(ctx context.Context, sess *mcpsdk.ClientSession) error {
		callCtx, cancel := context.WithTimeout(ctx, m.cfg.RequestTimeout)
		defer cancel()
		result, err := sess.GetPrompt(callCtx, &mcpsdk.GetPromptParams{Name: name, Arguments: args})
		if err != nil {
			return fmt.Errorf("mcp: prompts/get %q failed: %w", name, err)
		}
		raw, _ := json.Marshal(result)
		m.rawMu.Lock()
		m.lastRawResp = raw
		m.rawMu.Unlock()
		out = types.MCPPromptResult{
			Name:        name,
			Description: result.Description,
			Text:        promptText(result.Messages),
			Raw:         raw,
			Messages:    len(result.Messages),
		}
		return nil
	})
	if err != nil {
		return types.MCPPromptResult{}, err
	}
	return out, nil
}

// resourceText assembles the text of every returned content block. Binary blocks
// (Blob) contribute nothing to the text; callers needing them read Raw.
func resourceText(contents []*mcpsdk.ResourceContents) string {
	var parts []string
	for _, c := range contents {
		if c == nil || c.Text == "" {
			continue
		}
		parts = append(parts, c.Text)
	}
	return strings.Join(parts, "\n")
}

// firstResourceMIME returns the MIME type of the first block that declared one.
func firstResourceMIME(contents []*mcpsdk.ResourceContents) string {
	for _, c := range contents {
		if c != nil && c.MIMEType != "" {
			return c.MIMEType
		}
	}
	return ""
}

// promptText assembles the text of every rendered prompt message, reusing the
// shared content-text helper so a prompt message and a tool result are flattened
// the same way.
func promptText(messages []*mcpsdk.PromptMessage) string {
	var parts []string
	for _, msg := range messages {
		if msg == nil || msg.Content == nil {
			continue
		}
		if text := contentText([]mcpsdk.Content{msg.Content}); text != "" {
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, "\n")
}
