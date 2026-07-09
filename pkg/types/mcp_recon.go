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
	// Transport is the transport the generator connected over ("http" or "sse").
	// For an "auto" target it is the transport auto-detection resolved to, not the
	// literal "auto".
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
// ToolInvoker.ListTools produces — a slice of {name, description, parameters,
// annotations} maps — so probes can consume shared reconnaissance instead of
// enumerating the tool surface a second time. The InputSchema raw JSON is decoded
// into the "parameters" key; a tool with no (or malformed) schema simply omits
// the key. Safety annotations, when present, are exposed under "annotations" as a
// concrete MCPToolAnnotations value — the same type the live ListTools path
// stores — so tool-surface probes can gate destructive tools on either path.
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
		if t.Annotations != nil {
			tm["annotations"] = *t.Annotations
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
	// Annotations holds the server-declared behavioral hints (read-only /
	// destructive), nil when the tool carries none. It is descriptive recon data;
	// the tool-surface probes read it to decide whether calling the tool with
	// adversarial arguments is safe.
	Annotations *MCPToolAnnotations `json:"annotations,omitempty"`
}

// MCPToolAnnotations mirrors the MCP tool behavioral hints. The pointer fields
// distinguish "declared false" from "not declared": per the MCP spec their
// defaults differ from the Go zero value (DestructiveHint and OpenWorldHint
// default to true), so a nil pointer means the server said nothing.
type MCPToolAnnotations struct {
	// ReadOnly: the tool does not modify its environment (spec default false).
	ReadOnly bool `json:"read_only,omitempty"`
	// Destructive: the tool may perform destructive updates; meaningful only when
	// ReadOnly is false (spec default true, hence a pointer).
	Destructive *bool `json:"destructive,omitempty"`
	// Idempotent: repeated calls with the same args have no additional effect
	// (spec default false).
	Idempotent bool `json:"idempotent,omitempty"`
	// OpenWorld: the tool interacts with an open world of external entities (spec
	// default true, hence a pointer).
	OpenWorld *bool `json:"open_world,omitempty"`
	// Title is the human-readable tool title, when the server supplied one.
	Title string `json:"title,omitempty"`
}

// IsDestructive reports whether calling the tool with adversarial arguments is
// potentially state-changing. A read-only tool is never destructive. Otherwise
// it follows the MCP spec default: absent a DestructiveHint, a non-read-only tool
// is assumed destructive.
func (a *MCPToolAnnotations) IsDestructive() bool {
	if a == nil {
		return false // no annotations: unknown, not "known destructive"
	}
	if a.ReadOnly {
		return false
	}
	return a.Destructive == nil || *a.Destructive
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
