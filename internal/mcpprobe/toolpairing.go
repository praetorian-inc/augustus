package mcpprobe

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
)

// ToolPair represents two tools identified as functionally equivalent candidates.
type ToolPair struct {
	ToolA, ToolB string
	Method       string // "name-heuristic" or "llm-semantic"
}

// NearNamePairs identifies candidate tool pairs from the catalog by name
// similarity. It catches singular/plural variants (get_user_role /
// get_user_roles), one differing token (get_user / get_admin), and
// added/dropped qualifiers (list_files / list_files_recursive).
//
// It returns only pairs where both tools accept at least one common parameter
// name, so two tools with similar names but disjoint schemas are not paired.
// Pairs are deterministic and sorted.
func NearNamePairs(tools []map[string]any) []ToolPair {
	type entry struct {
		name   string
		tool   map[string]any
		tokens []string
	}
	entries := make([]entry, 0, len(tools))
	for _, t := range tools {
		name, _ := t["name"].(string)
		if name == "" {
			continue
		}
		entries = append(entries, entry{
			name:   name,
			tool:   t,
			tokens: nameTokens(name),
		})
	}

	var pairs []ToolPair
	seen := map[string]bool{}
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			a, b := entries[i], entries[j]
			if !nearName(a.tokens, b.tokens) {
				continue
			}
			if !shareParameter(a.tool, b.tool) {
				continue
			}
			pa, pb := a.name, b.name
			if pa > pb {
				pa, pb = pb, pa
			}
			key := pa + "\x00" + pb
			if seen[key] {
				continue
			}
			seen[key] = true
			pairs = append(pairs, ToolPair{ToolA: pa, ToolB: pb, Method: "name-heuristic"})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].ToolA != pairs[j].ToolA {
			return pairs[i].ToolA < pairs[j].ToolA
		}
		return pairs[i].ToolB < pairs[j].ToolB
	})
	return pairs
}

// nameTokens splits a tool name into lowercase tokens on underscores, hyphens,
// dots, and camelCase boundaries.
func nameTokens(name string) []string {
	expanded := SplitCamelCase(name)
	var tokens []string
	for _, part := range strings.FieldsFunc(expanded, func(r rune) bool {
		return r == '_' || r == '-' || r == '.' || r == ' '
	}) {
		t := strings.ToLower(part)
		if t != "" {
			tokens = append(tokens, t)
		}
	}
	return tokens
}

// nearName returns true when two token sequences differ by at most one token:
// one added, one removed, or one substituted. Exact matches are excluded (same tool).
func nearName(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	if tokensEqual(a, b) {
		return false
	}

	if len(a) == len(b) {
		diffs := 0
		for i := range a {
			if a[i] != b[i] {
				if isSingularPlural(a[i], b[i]) {
					diffs++
				} else {
					diffs++
				}
			}
		}
		return diffs == 1
	}

	if intAbs(len(a)-len(b)) == 1 {
		short, long := a, b
		if len(a) > len(b) {
			short, long = b, a
		}
		gaps := 0
		si := 0
		for li := 0; li < len(long) && si <= len(short); li++ {
			if si < len(short) && short[si] == long[li] {
				si++
			} else {
				gaps++
			}
		}
		return gaps <= 1 && si == len(short)
	}

	return false
}

func isSingularPlural(a, b string) bool {
	if a == b {
		return false
	}
	return a+"s" == b || b+"s" == a || a+"es" == b || b+"es" == a
}

// shareParameter returns true when two tools share at least one parameter with
// the same leaf name and compatible type.
func shareParameter(a, b map[string]any) bool {
	aParams := leafParams(a)
	bParams := leafParams(b)
	for name, aType := range aParams {
		if bType, ok := bParams[name]; ok {
			if aType == bType || aType == "" || bType == "" {
				return true
			}
		}
	}
	return false
}

func leafParams(tool map[string]any) map[string]string {
	out := map[string]string{}
	for _, sig := range ToolSignatures(tool) {
		for _, p := range sig.Params {
			out[p.Path.Leaf()] = p.Type
		}
	}
	return out
}

func tokensEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func intAbs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// CommonArgs builds the intersection of parameters across two tools' signatures,
// filling each with a benign value. Returns nil if no common parameters exist.
func CommonArgs(toolA, toolB map[string]any) map[string]any {
	aParams := leafParams(toolA)
	bParams := leafParams(toolB)

	args := map[string]any{}
	for name, aType := range aParams {
		if _, ok := bParams[name]; !ok {
			continue
		}
		switch aType {
		case "integer", "number":
			args[name] = 1
		case "boolean":
			args[name] = true
		case "array":
			args[name] = []any{}
		case "object":
			args[name] = map[string]any{}
		default:
			args[name] = "test"
		}
	}
	if len(args) == 0 {
		return nil
	}
	return args
}

// SemanticPairs uses an LLM judge to identify functionally-equivalent tool
// pairs from the catalog by analyzing descriptions and schemas. It is opt-in
// and supplements NearNamePairs.
func SemanticPairs(ctx context.Context, tools []map[string]any, judge generators.Generator, existing []ToolPair) ([]ToolPair, error) {
	if judge == nil || len(tools) < 2 {
		return nil, nil
	}

	var catalog strings.Builder
	for _, t := range tools {
		name, _ := t["name"].(string)
		desc, _ := t["description"].(string)
		params := leafParams(t)
		paramList := make([]string, 0, len(params))
		for p, typ := range params {
			paramList = append(paramList, p+"("+typ+")")
		}
		sort.Strings(paramList)
		fmt.Fprintf(&catalog, "- %s: %s [params: %s]\n", name, desc, strings.Join(paramList, ", "))
	}

	skip := map[string]bool{}
	for _, p := range existing {
		skip[p.ToolA+"\x00"+p.ToolB] = true
		skip[p.ToolB+"\x00"+p.ToolA] = true
	}

	conv := attempt.NewConversation().WithSystem(semanticPairingSystemPrompt)
	conv.AddPrompt(fmt.Sprintf("Here is the tool catalog:\n\n%s\nIdentify functionally-equivalent pairs.", catalog.String()))

	responses, err := judge.Generate(ctx, conv, 1)
	if err != nil {
		return nil, fmt.Errorf("semantic pairing judge: %w", err)
	}
	if len(responses) == 0 {
		return nil, nil
	}

	return parseSemanticPairs(responses[0].Content, tools, skip), nil
}

const semanticPairingSystemPrompt = `You identify functionally-equivalent tool pairs in an MCP server catalog. Two tools are equivalent when they front the SAME operation on the SAME data — for example, singular vs plural variants, or tools with different names that query the same underlying resource with the same parameters.

Do NOT pair tools that legitimately serve different purposes even if their names are similar (e.g., list_files vs list_files_recursive is NOT equivalent — different scope).

Reply with ONLY a JSON array of pairs: [{"a":"tool_name_1","b":"tool_name_2"}]. Empty array if none found.`

func parseSemanticPairs(text string, tools []map[string]any, skip map[string]bool) []ToolPair {
	toolSet := map[string]bool{}
	for _, t := range tools {
		if name, _ := t["name"].(string); name != "" {
			toolSet[name] = true
		}
	}

	var parsed []struct {
		A string `json:"a"`
		B string `json:"b"`
	}
	start := strings.Index(text, "[")
	end := strings.LastIndex(text, "]")
	if start < 0 || end <= start {
		return nil
	}
	if err := json.Unmarshal([]byte(text[start:end+1]), &parsed); err != nil {
		return nil
	}

	var pairs []ToolPair
	for _, p := range parsed {
		a, b := p.A, p.B
		if a > b {
			a, b = b, a
		}
		if !toolSet[a] || !toolSet[b] || a == b {
			continue
		}
		if skip[a+"\x00"+b] {
			continue
		}
		skip[a+"\x00"+b] = true
		pairs = append(pairs, ToolPair{ToolA: a, ToolB: b, Method: "llm-semantic"})
	}
	return pairs
}
