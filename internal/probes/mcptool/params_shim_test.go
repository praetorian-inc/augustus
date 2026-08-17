package mcptool

import (
	"context"

	"github.com/praetorian-inc/augustus/internal/toolsig"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// Test-only shims preserving the pre-signature call shapes.
//
// The existing suite was written against tools with flat schemas, where a tool
// has exactly one call signature and its parameters are the whole surface.
// Keeping these helpers lets that suite run unchanged against the new parser,
// which makes it a regression gate rather than a rewrite: if every one of those
// tests still passes, a flat schema still produces exactly what it did before.
//
// They are deliberately confined to tests. Production code goes through
// toolSignatures, because a tool with conditionals has more than one signature
// and picking the first would silently test a fraction of it.

// toolParams returns the parameters of a tool's first call signature.
func toolParams(tool map[string]any) []paramInfo {
	sigs := toolSignatures(tool, nil)
	if len(sigs) == 0 {
		return nil
	}
	return sigs[0].params
}

// benignArgs builds arguments for a tool's first signature with payload in the
// named parameter.
func benignArgs(params []paramInfo, injectParam, payload string) map[string]any {
	var inject paramInfo
	found := false
	for _, p := range params {
		if p.name == injectParam || string(p.path) == injectParam {
			inject, found = p, true
			break
		}
	}
	if !found {
		inject = paramInfo{name: injectParam, path: toolsig.Path(injectParam)}
	}
	ts := toolSig{params: params}
	args := map[string]any{}
	for _, p := range params {
		if p.path == inject.path || !p.required {
			continue
		}
		args[string(p.path)] = benignValue(p)
	}
	args[string(inject.path)] = payload
	_ = ts
	return args
}

// discoverToolValues runs value discovery over a flat parameter list.
func discoverToolValues(ctx context.Context, inv types.ToolInvoker, tool string, params []paramInfo) []paramInfo {
	ts := sigOf(params)
	ts.tool = tool
	return ts.discoverValues(ctx, inv, tool).params
}

// sigOf wraps a flat parameter list as a single signature, deriving the schema
// side from the probe side so Build has parameters to fill. Production never
// needs this: toolSignatures always produces both halves together.
func sigOf(params []paramInfo) toolSig {
	out := make([]paramInfo, len(params))
	copy(out, params)
	sig := toolsig.Signature{Select: map[string]any{}}
	for i := range out {
		if out[i].path == "" {
			out[i].path = toolsig.Path(out[i].name)
		}
		sig.Params = append(sig.Params, toolsig.Param{
			Path:     out[i].path,
			Type:     out[i].typ,
			Required: out[i].required,
		})
	}
	return toolSig{sig: sig, params: out}
}
