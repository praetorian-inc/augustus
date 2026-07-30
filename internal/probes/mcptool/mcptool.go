// Package mcptool provides tool-backend security probes for MCP targets.
// Its probes (Injection, SSRF, PathTraversal) invoke REAL tools through
// types.ToolInvoker to test the backend's own behaviour — injection
// sinks, authorization, SSRF, path traversal. This is distinct from the
// model-facing tool probes elsewhere in the tree that only ask whether
// an LLM can be manipulated INTO a tool call: mcptool calls the tools
// itself and observes what actually runs.
//
// Payload construction (computed-arithmetic canaries, shell-command payloads)
// and the out-of-band collector live in internal/mcpprobe, shared with the
// internal/probes/mcpprimitive package that attacks the non-tool primitives.
//
// Sibling package: internal/probes/mcptransport houses transport-layer
// probes (OriginValidation, SSESessionHijack) that bypass the MCP
// protocol entirely and issue raw HTTP. Different attack surface,
// different interface (types.MCPEndpoint), different package.
package mcptool

// paramInfo describes one tool parameter parsed from its JSON-schema.
type paramInfo struct {
	name     string
	typ      string
	required bool
}

// toolParams parses the parameters of a tool in the canonical Conversation.Tools
// wire shape (map with a "parameters" JSON-schema object).
func toolParams(tool map[string]any) []paramInfo {
	schema, ok := tool["parameters"].(map[string]any)
	if !ok {
		return nil
	}
	props, _ := schema["properties"].(map[string]any)

	required := map[string]bool{}
	switch req := schema["required"].(type) {
	case []any:
		for _, r := range req {
			if s, ok := r.(string); ok {
				required[s] = true
			}
		}
	case []string:
		for _, s := range req {
			required[s] = true
		}
	}

	out := make([]paramInfo, 0, len(props))
	for name, raw := range props {
		typ := ""
		if p, ok := raw.(map[string]any); ok {
			typ, _ = p["type"].(string)
		}
		out = append(out, paramInfo{name: name, typ: typ, required: required[name]})
	}
	return out
}

// isStringParam reports whether a param is a viable injection target. An absent
// type is treated as string-injectable (schemas in the wild often omit it).
func isStringParam(typ string) bool {
	return typ == "" || typ == "string"
}

// benignArgs builds a call argument map: the injected payload in injectParam, and
// benign placeholders for every other required param so the call reaches the sink
// instead of failing argument validation.
func benignArgs(params []paramInfo, injectParam, payload string) map[string]any {
	args := map[string]any{injectParam: payload}
	for _, p := range params {
		if p.name == injectParam || !p.required {
			continue
		}
		args[p.name] = benignValue(p.typ)
	}
	return args
}

func benignValue(typ string) any {
	switch typ {
	case "integer", "number":
		return 1
	case "boolean":
		return true
	case "array":
		return []any{}
	case "object":
		return map[string]any{}
	default:
		return "test"
	}
}
