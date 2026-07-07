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
// The implementation assembles ONLY raw inventory data. Suspicious-pattern
// analysis (tool poisoning, exfiltration hints, hidden unicode, name shadowing)
// lives in the probe/detector layer, which fills in MCPInventory.Flags.
type MCPReconnaissance interface {
	// MCPInventory reads the connected MCP session and returns the raw
	// attack-surface inventory with Flags left empty.
	MCPInventory(ctx context.Context) (*MCPInventory, error)
}

// MCPInventory is a machine-readable, JSON-serializable snapshot of an MCP
// server's attack surface. It is shared by the generator (which assembles the
// raw fields), the probe (which fills Flags via suspicious-pattern scanning),
// and the detector (which scores from Flags).
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
	// Flags holds suspicious-pattern findings raised by the probe layer. Empty
	// as returned by the generator.
	Flags []MCPSuspiciousFlag `json:"flags,omitempty"`
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

// MCPInventoryCounts is a roll-up of catalog sizes plus the flag count.
type MCPInventoryCounts struct {
	Tools             int `json:"tools"`
	Resources         int `json:"resources"`
	ResourceTemplates int `json:"resource_templates"`
	Prompts           int `json:"prompts"`
	Flags             int `json:"flags"`
}

// Suspicious-pattern flag categories raised over an MCP inventory. Shared by the
// probe (which sets them) and the detector (which scores from them).
const (
	// MCPFlagImperativeInjection marks tool-poisoning imperative/injection
	// phrasing ("ignore previous", "do not tell the user", "you must", "before
	// using any other tool", ...).
	MCPFlagImperativeInjection = "imperative_injection"
	// MCPFlagExfiltration marks data-exfiltration hints (send/upload/forward to,
	// read ~/.ssh or .env, include the api key, ...).
	MCPFlagExfiltration = "exfiltration"
	// MCPFlagEmbeddedURL marks an embedded http/https/ftp URL in a description or
	// schema — a common tool-poisoning callback/exfil channel.
	MCPFlagEmbeddedURL = "embedded_url"
	// MCPFlagHiddenUnicode marks hidden/zero-width or bidirectional-control
	// unicode used to conceal injected instructions.
	MCPFlagHiddenUnicode = "hidden_unicode"
	// MCPFlagToolShadowing marks tool-name shadowing/duplication (case-insensitive
	// name collisions across the catalog).
	MCPFlagToolShadowing = "tool_shadowing"
)

// MCPSuspiciousFlag is one suspicious-pattern finding over the inventory.
type MCPSuspiciousFlag struct {
	// Category is one of the MCPFlag* constants.
	Category string `json:"category"`
	// Tool is the offending tool name (empty for cross-tool findings).
	Tool string `json:"tool,omitempty"`
	// Location is where the pattern was found ("description", "input_schema",
	// "param:<name>", "tool_name").
	Location string `json:"location"`
	// Evidence is the matched snippet (or a rune label like "U+200B").
	Evidence string `json:"evidence,omitempty"`
}
