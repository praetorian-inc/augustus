// Package toolsec provides transport-agnostic security probes for MCP
// targets. It covers two adjacent surfaces:
//
//   - Tool-backend probes (Injection, SSRF, PathTraversal) call real tools
//     through types.ToolInvoker to test the backend's own behaviour —
//     injection sinks, authorization, SSRF, path traversal. Distinct from
//     the model-facing tool probes elsewhere in the tree that only ask
//     whether an LLM can be manipulated INTO a tool call.
//
//   - Transport-layer probes (OriginValidation, SSESessionHijack) bypass the
//     MCP protocol layer and issue raw HTTP against the server, borrowing
//     the generator's HTTPClient/AnonymousHTTPClient so proxy, TLS, and
//     header config still flow. They test properties of the HTTP endpoint
//     itself (Origin/Host validation, session-id quality, session
//     lifetime) that no tool-invocation can reach.
package toolsec

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
)

// randToken returns a random 16-hex-char token for canaries/OOB paths.
func randToken() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "augfallback000000"
	}
	return hex.EncodeToString(b)
}

// canary is a computed-arithmetic injection canary. Each payload, if the target
// evaluates it, yields `marker` (the product) in the output. The marker never
// appears literally in any payload, so a tool that merely echoes its input back
// cannot produce a false positive — the failure mode that made the old
// echo-based detectors useless against direct tool calls.
type canary struct {
	marker   string
	payloads []string
}

// payloadFormats render the same multiplication across the injection classes we
// cover: bare expression/eval, template engines (SSTI), and shell.
var payloadFormats = []string{
	"%d*%d",             // bare expression / eval / Python
	"{{%d*%d}}",         // Jinja / Twig / Nunjucks SSTI
	"${%d*%d}",          // JSP EL / Freemarker / shell-ish templates
	"#{%d*%d}",          // Ruby / Thymeleaf EL
	"$((%d*%d))",        // shell arithmetic expansion
	"; expr %d \\* %d",  // command injection via separator
	"$(expr %d \\* %d)", // command substitution
	"`expr %d \\* %d`",  // backtick command substitution
}

// newCanary builds a canary from two random factors. The product is ~9 digits,
// making a coincidental appearance in benign output vanishingly unlikely.
func newCanary() canary {
	a := randInt(100000, 999999)
	b := randInt(101, 999)
	c := canary{marker: strconv.Itoa(a * b)}
	c.payloads = make([]string, len(payloadFormats))
	for i, f := range payloadFormats {
		c.payloads[i] = fmt.Sprintf(f, a, b)
	}
	return c
}

// randInt returns a random int in [min, max). On the (practically impossible)
// RNG failure it falls back to min, which still yields a valid canary.
func randInt(min, max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	if err != nil {
		return min
	}
	return min + int(n.Int64())
}

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
