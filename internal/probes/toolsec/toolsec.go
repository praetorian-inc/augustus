// Package toolsec provides transport-agnostic security probes for targets that
// expose a directly-invokable tool surface via types.ToolInvoker (e.g. the MCP
// generator). Unlike the model-facing tool probes (which test whether an LLM can
// be manipulated into calling a tool), these probes call real tools directly and
// test the tool backend's own behavior — injection sinks, authorization, SSRF.
package toolsec

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"strconv"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
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

// toolPolicy decides which discovered tools a tool-surface probe is allowed to
// invoke with adversarial arguments. The tool-surface probes call REAL tools, so
// against production infrastructure a payload sent to a destructive tool (delete,
// transfer, send) can cause real damage. The policy defaults to a safe posture —
// tools the server annotates as destructive are skipped — and requires an
// explicit opt-in to test them.
//
// Precedence, highest first:
//  1. allow-list: if set, ONLY listed tools are ever tested.
//  2. deny-list: listed tools are never tested.
//  3. destructive gate: unless allow_destructive is set, tools annotated
//     destructive (per MCP tool hints) are skipped. Tools with no annotations are
//     treated as unknown and ARE tested — a scanner's worst outcome is a silent
//     false negative, and most servers ship no hints at all.
type toolPolicy struct {
	allowDestructive bool
	allow            map[string]bool
	deny             map[string]bool
}

// Config keys shared by the tool-surface probes.
const (
	cfgAllowDestructive = "allow_destructive"
	cfgToolAllowlist    = "tool_allowlist"
	cfgToolDenylist     = "tool_denylist"
)

// newToolPolicy reads the shared safety-gate config keys.
func newToolPolicy(cfg registry.Config) toolPolicy {
	return toolPolicy{
		allowDestructive: registry.GetBool(cfg, cfgAllowDestructive, false),
		allow:            toSet(registry.GetStringSlice(cfg, cfgToolAllowlist, nil)),
		deny:             toSet(registry.GetStringSlice(cfg, cfgToolDenylist, nil)),
	}
}

func toSet(names []string) map[string]bool {
	if len(names) == 0 {
		return nil
	}
	s := make(map[string]bool, len(names))
	for _, n := range names {
		s[n] = true
	}
	return s
}

// skip reports whether a tool must not be invoked, with a human-readable reason
// for logging. tm is the tool's ListTools-shaped map (its "annotations" key, when
// present, is a types.MCPToolAnnotations value).
func (p toolPolicy) skip(name string, tm map[string]any) (bool, string) {
	if len(p.allow) > 0 && !p.allow[name] {
		return true, "not in tool_allowlist"
	}
	if p.deny[name] {
		return true, "in tool_denylist"
	}
	if p.allowDestructive {
		return false, ""
	}
	ann, ok := tm["annotations"].(types.MCPToolAnnotations)
	if ok && ann.IsDestructive() {
		return true, "server annotates this tool as destructive; set allow_destructive=true to test it"
	}
	return false, ""
}

// filterTools returns the subset of tools the policy permits, logging each skip
// so a narrowed scan is never silently mistaken for a clean one.
func (p toolPolicy) filterTools(probe string, tools []map[string]any) []map[string]any {
	kept := make([]map[string]any, 0, len(tools))
	for _, tm := range tools {
		name, _ := tm["name"].(string)
		if skip, reason := p.skip(name, tm); skip {
			slog.Warn("toolsec: skipping tool", "probe", probe, "tool", name, "reason", reason)
			continue
		}
		kept = append(kept, tm)
	}
	return kept
}
