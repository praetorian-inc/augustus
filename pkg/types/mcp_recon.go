package types

import (
	"context"
	"encoding/json"
)

// MCPReconnaissance is an OPTIONAL interface a Generator implements when its
// target is an MCP server whose full attack surface can be enumerated from the
// connected session: declared capabilities, negotiated protocol version, server
// instructions, and the tool / resource / resource-template / prompt catalog.
//
// It is distinct from ToolInvoker: ToolInvoker exposes only the invokable tool
// surface (list + call), whereas MCPReconnaissance reports the whole session
// fingerprint needed for a static attack-surface inventory. A generator may
// implement both. Probes type-assert a Generator to MCPReconnaissance and skip
// the target when the assertion fails, exactly as with ToolInvoker /
// VisionCapable.
//
// The implementation assembles ONLY the raw, descriptive inventory. It never
// renders a verdict — reconnaissance is not a test. Suspicious-pattern analysis
// (tool poisoning, etc.) is a separate test probe's concern.
type MCPReconnaissance interface {
	// MCPInventory reads the connected MCP session and returns the raw
	// attack-surface inventory.
	MCPInventory(ctx context.Context) (*MCPInventory, error)
}

// MCPInventory is a machine-readable, JSON-serializable snapshot of an MCP
// server's attack surface — purely descriptive reconnaissance data.
type MCPInventory struct {
	// Transport is the transport the generator connected over ("http", "sse",
	// "stdio").
	Transport string `json:"transport"`
	// ProtocolVersion is the MCP protocol version the server negotiated.
	ProtocolVersion string `json:"protocol_version,omitempty"`
	// Instructions is the server-provided usage hint (InitializeResult.Instructions).
	Instructions string `json:"instructions,omitempty"`
	// ServerName / ServerVersion identify the server implementation.
	ServerName    string `json:"server_name,omitempty"`
	ServerVersion string `json:"server_version,omitempty"`
	// Capabilities records which capability blocks the server declared.
	Capabilities MCPCapabilities `json:"capabilities"`
	// Tools / Resources / ResourceTemplates / Prompts hold the enumerated catalog.
	Tools             []MCPTool             `json:"tools"`
	Resources         []MCPResource         `json:"resources"`
	ResourceTemplates []MCPResourceTemplate `json:"resource_templates"`
	Prompts           []MCPPrompt           `json:"prompts"`
	// Counts is a convenience roll-up for reporting.
	Counts MCPInventoryCounts `json:"counts"`
}

// ToolMaps renders the inventory's tools in the same wire shape that
// ToolInvoker.ListTools produces — a slice of {name, description, parameters}
// maps — so probes can consume shared reconnaissance instead of enumerating the
// tool surface a second time. The InputSchema raw JSON is decoded into the
// "parameters" key; a tool with no (or malformed) schema simply omits the key.
func (inv *MCPInventory) ToolMaps() []map[string]any {
	out := make([]map[string]any, 0, len(inv.Tools))
	for _, t := range inv.Tools {
		tm := map[string]any{"name": t.Name}
		if t.Description != "" {
			tm["description"] = t.Description
		}
		if len(t.InputSchema) > 0 {
			var schema map[string]any
			if err := json.Unmarshal(t.InputSchema, &schema); err == nil {
				tm["parameters"] = schema
			}
		}
		out = append(out, tm)
	}
	return out
}

// MCPCapabilities records which capability blocks the server advertised in its
// InitializeResult, as booleans plus the raw experimental/extension keys.
type MCPCapabilities struct {
	Tools       bool `json:"tools"`
	Resources   bool `json:"resources"`
	Prompts     bool `json:"prompts"`
	Logging     bool `json:"logging"`
	Completions bool `json:"completions"`
	// Experimental / Extensions list the declared non-standard capability keys.
	Experimental []string `json:"experimental,omitempty"`
	Extensions   []string `json:"extensions,omitempty"`
}

// MCPTool is one advertised tool. InputSchema is the raw JSON schema bytes so it
// stays both JSON-serializable and directly scannable as a string.
type MCPTool struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

// MCPResource is one advertised concrete resource.
type MCPResource struct {
	URI         string `json:"uri"`
	Name        string `json:"name,omitempty"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mime_type,omitempty"`
}

// MCPResourceTemplate is one advertised resource template (a URI pattern).
type MCPResourceTemplate struct {
	URITemplate string `json:"uri_template"`
	Name        string `json:"name,omitempty"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mime_type,omitempty"`
}

// MCPPrompt is one advertised prompt template.
type MCPPrompt struct {
	Name        string              `json:"name"`
	Title       string              `json:"title,omitempty"`
	Description string              `json:"description,omitempty"`
	Arguments   []MCPPromptArgument `json:"arguments,omitempty"`
}

// MCPPromptArgument is a single templating argument of a prompt.
type MCPPromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// MCPInventoryCounts is a roll-up of catalog sizes.
type MCPInventoryCounts struct {
	Tools             int `json:"tools"`
	Resources         int `json:"resources"`
	ResourceTemplates int `json:"resource_templates"`
	Prompts           int `json:"prompts"`
}
