package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/praetorian-inc/augustus/internal/observed"
	"github.com/praetorian-inc/augustus/internal/recon/llm"
	"github.com/praetorian-inc/augustus/internal/toolpolicy"
	"github.com/praetorian-inc/augustus/internal/toolsig"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/output"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// ObservationTypeIdentifiers is the stable slug for the per-identity object
// identifier observation.
const ObservationTypeIdentifiers = "mcp.identifiers"

func init() {
	recon.Register("recon.MCPIdentifiers", NewIdentifiers)
}

// Compile-time assertions: embedding llm.Base supplies SetContext, so the module
// is both a Recon and a ContextAwareRecon.
var (
	_ recon.Recon             = (*MCPIdentifiers)(nil)
	_ recon.ContextAwareRecon = (*MCPIdentifiers)(nil)
)

// Default keyword vocabularies for the DETERMINISTIC fallback classifier (the
// LLM navigator is the primary path). Each list is operator-extendable or
// replaceable via config, mirroring Hunter's ResolveMitigationPhrases pattern
// (base.ResolveMitigationPhrases, LAB-4664):
//   - id_param_patterns / id_param_extra_patterns     — which arg/key is an id
//   - getter_name_patterns / getter_name_extra_patterns — which tools are getters
//   - enum_name_patterns / enum_name_extra_patterns     — which tools enumerate
//
// so a target the defaults miss (e.g. "sku"/"isbn" ids, oddly-named tools) is a
// config edit, not a code change.
var (
	defaultIDParamWords = []string{"id", "uuid", "guid", "key", "ref", "number", "order", "ticket", "account", "user"}
	defaultGetterWords  = []string{"get", "read", "fetch", "retrieve", "show", "view", "describe"}
	defaultEnumWords    = []string{"list", "search", "find", "query", "all", "enumerate", "browse"}
)

// MCPIdentifiers is the recon module that discovers, per identity, the object
// identifiers a target's getter tools will return objects for. It embeds
// llm.Base for the navigator LLM (the PRIMARY classifier) and access to prior
// observations; the keyword-heuristic classifier is the deterministic FALLBACK
// used when no navigator is available or it errors. It renders no verdict —
// proving a cross-identity leak is a downstream probe's job.
type MCPIdentifiers struct {
	llm.Base

	identityLabel    string
	victims          []victimConfig
	getTools         []string
	enumerationTools []string
	idParams         map[string]string
	useNavigator     bool
	maxIDsPerTool    int

	// values holds what the target has already handed back, partitioned by the
	// identity that saw it. Delivered by the runner via SetContext.
	values *observed.Store
	// rules are operator-supplied argument values, bound by selector rather than
	// by tool name so one rule covers a value that appears throughout a surface.
	rules []toolsig.Rule

	// policy is the shared destructive-tool safety gate. recon is read-only, so a
	// tool the server annotates destructive (or one an operator denies) must never
	// be classified as a getter or enumerator — it would otherwise be invoked with
	// benign/id args. Replaces the old destructive-NAME regex heuristic.
	policy toolpolicy.Policy

	// Compiled from the (operator-extendable) keyword vocabularies.
	idParamRE *regexp.Regexp
}

// victimConfig describes one non-primary identity session the module builds.
type victimConfig struct {
	label   string
	genType string
	genCfg  registry.Config
	// rules are argument values specific to THIS identity, consulted ahead of the
	// module-wide ones.
	//
	// They exist because not every server carries identity in the transport. A
	// tenant-scoped tool surface commonly takes the tenant as an ARGUMENT on every
	// call, and there the two identities are the same endpoint, the same headers
	// and the same session — differing only in one value. Without per-identity
	// rules such a target cannot be expressed at all: both sessions would send the
	// module-wide tenant, both would enumerate the same objects, and the
	// set-difference that establishes ownership would be empty. BOLA would then
	// report nothing and the surface would read as clean because nothing was ever
	// asked of it.
	rules []toolsig.Rule
}

// NewIdentifiers constructs the module, wiring the embedded navigator base and
// reading the classification hints and identity sessions from config.
func NewIdentifiers(cfg registry.Config) (recon.Recon, error) {
	base, err := llm.NewBase(cfg)
	if err != nil {
		return nil, err
	}
	return &MCPIdentifiers{
		Base:             *base,
		identityLabel:    registry.GetString(cfg, "identity_label", "primary"),
		victims:          parseVictims(cfg),
		getTools:         registry.GetStringSlice(cfg, "get_tools", nil),
		enumerationTools: registry.GetStringSlice(cfg, "enumeration_tools", nil),
		idParams:         parseIDParams(cfg),
		rules:            toolsig.RulesFromConfig(cfg),
		useNavigator:     registry.GetBool(cfg, "use_navigator", true),
		maxIDsPerTool:    registry.GetInt(cfg, "max_ids_per_tool", 5),
		policy:           toolpolicy.New(cfg),
		idParamRE:        wordBoundaryRE(resolvePatterns(cfg, "id_param_patterns", "id_param_extra_patterns", defaultIDParamWords)),
	}, nil
}

// resolvePatterns computes an effective keyword list from operator config,
// falling back to defaults. Mirrors base.ResolveMitigationPhrases: a *_patterns
// key REPLACES the defaults; a *_extra_patterns key APPENDS. Empty/whitespace
// entries are dropped; an all-empty result falls back to defaults so the
// classifier never degenerates.
func resolvePatterns(cfg registry.Config, replaceKey, extraKey string, defaults []string) []string {
	words := defaults
	if override := registry.GetStringSlice(cfg, replaceKey, nil); len(override) > 0 {
		words = override
	}
	if extra := registry.GetStringSlice(cfg, extraKey, nil); len(extra) > 0 {
		words = append(append([]string{}, words...), extra...)
	}
	out := make([]string, 0, len(words))
	for _, w := range words {
		if strings.TrimSpace(w) != "" {
			out = append(out, w)
		}
	}
	if len(out) == 0 {
		return defaults
	}
	return out
}

// wordBoundaryRE builds a case-insensitive regex matching any of the given words
// as a delimited segment of a name/key (start/end or _, -, space boundaries).
// Match names through matchWord so camelCase/acronym humps are recognized too.
func wordBoundaryRE(words []string) *regexp.Regexp {
	escaped := make([]string, len(words))
	for i, w := range words {
		escaped[i] = regexp.QuoteMeta(w)
	}
	return regexp.MustCompile(`(?i)(^|[_\- ])(` + strings.Join(escaped, "|") + `)($|[_\- ])`)
}

var (
	camelHumpRE = regexp.MustCompile(`([a-z0-9])([A-Z])`)    // orderId -> order_Id
	acronymRE   = regexp.MustCompile(`([A-Z]+)([A-Z][a-z])`) // HTTPServer -> HTTP_Server
)

// humpSplit inserts underscores at camelCase and acronym boundaries so a
// delimiter-based word matcher recognizes segments like the "id" in "orderId"
// or "userID". Tokenizing (rather than a case-insensitive camel regex) avoids
// false positives such as reading "id" out of "valid".
func humpSplit(s string) string {
	s = camelHumpRE.ReplaceAllString(s, "${1}_${2}")
	s = acronymRE.ReplaceAllString(s, "${1}_${2}")
	return s
}

// matchWord reports whether a keyword regex matches a name, tolerant of
// camelCase/acronym boundaries (via humpSplit) as well as delimiter boundaries.
func matchWord(re *regexp.Regexp, s string) bool {
	return re.MatchString(humpSplit(s))
}

// Name returns the fully qualified module name.
func (m *MCPIdentifiers) Name() string { return "recon.MCPIdentifiers" }

// identitySession pairs an identity label with its invokable session.
type identitySession struct {
	label string
	inv   types.ToolInvoker
	// chain supplies argument values for this identity's calls.
	chain toolsig.Chain
}

// SetContext implements recon.ContextAwareRecon, receiving the shared
// assessment state before this module runs.
//
// It must delegate to the embedded Base, which is what wires the observation
// store this module reads its tool inventory from; overriding without
// delegating silently leaves that store nil and sends the module back to a live
// enumeration it did not need.
func (m *MCPIdentifiers) SetContext(pc recon.ProbeContext) {
	m.Base.SetContext(pc)
	m.values = pc.Observed
}

// session builds one identity's session: its invoker wrapped so every response
// is recorded under that identity, and the value chain used to build its calls.
//
// Operator configuration outranks anything scraped from a response. An operator
// who wants the observed value writes no rule; ranking configuration below the
// scrape would leave no way to correct a wrong inference.
func (m *MCPIdentifiers) session(label string, inv types.ToolInvoker, own []toolsig.Rule) identitySession {
	chain := toolsig.Chain{}
	// This identity's own rules outrank the module-wide ones. A value that
	// DISTINGUISHES two identities has to beat a value that is shared by them, or
	// the two sessions send the same arguments and there is no ownership boundary
	// left to test.
	if len(own) > 0 {
		chain = append(chain, toolsig.FromRules("", own))
	}
	if len(m.rules) > 0 {
		chain = append(chain, toolsig.FromRules("", m.rules))
	}
	if m.values != nil {
		chain = append(chain, m.values.Source(label))
	}
	chain = append(chain, valueChain()...)
	return identitySession{
		label: label,
		inv:   observed.Wrap(inv, m.values, label),
		chain: chain,
	}
}

// toolSpec is one classified tool plus its parsed parameters. For getters,
// idParam names the argument that takes the identifier. tm is the original
// ListTools-shaped tool map (carrying any server annotations) so the safety
// policy can be re-asserted at the call site, independently of the upstream
// catalog filter.
type toolSpec struct {
	name string
	// sig is one concrete way the tool can be called. A tool whose parameters
	// vary by discriminator has several, and they are not interchangeable, so
	// each is classified and exercised on its own.
	sig    toolsig.Signature
	params []toolsig.Param
	// idParam is the identifier argument's own name, kept for the observation
	// payload; idPath addresses it within the call, which a name cannot do when
	// the identifier sits inside a nested object.
	idParam string
	idPath  toolsig.Path
	tm      map[string]any
}

// Recon enumerates each identity's own object identifiers and round-trip
// validates them against the getter that accepts them, emitting one observation
// per identity that confirmed at least one object. A non-ToolInvoker primary
// target yields no observations; a failing tool or victim session is skipped,
// never fatal.
func (m *MCPIdentifiers) Recon(ctx context.Context, gen types.Generator) ([]output.Observation, error) {
	tools, err := m.toolCatalog(ctx, gen)
	if err != nil {
		return nil, err
	}
	if len(tools) == 0 {
		return nil, nil
	}

	primary, ok := gen.(types.ToolInvoker)
	if !ok {
		return nil, nil
	}

	specs := m.specs(tools)
	if len(specs) == 0 {
		slog.Warn("recon.MCPIdentifiers: no callable tool signatures on this surface. This is NOT a clean result.",
			"tools", len(tools))
		return nil, nil
	}

	// Each identity's calls are recorded under that identity's label, so the
	// values a target hands out during reconnaissance are available to the probes
	// that follow — and cannot be confused with another identity's.
	sessions := []identitySession{m.session(m.identityLabel, primary, nil)}
	for _, v := range m.victims {
		g, err := generators.Create(v.genType, v.genCfg)
		if err != nil {
			slog.Warn("recon.MCPIdentifiers: create victim session", "label", v.label, "error", err)
			continue
		}
		vi, ok := g.(types.ToolInvoker)
		if !ok {
			slog.Warn("recon.MCPIdentifiers: victim generator is not a ToolInvoker", "label", v.label)
			continue
		}
		sessions = append(sessions, m.session(v.label, vi, v.rules))
	}

	var obs []output.Observation
	for _, s := range sessions {
		refs := m.discover(ctx, s, specs)
		if len(refs) == 0 {
			slog.Warn("recon.MCPIdentifiers: no object identifiers confirmed for this identity — either it owns nothing, or no tool returned an identifier another tool would accept. This is NOT a clean result.",
				"identity", s.label, "signatures", len(specs))
			continue
		}
		payload := types.MCPIdentifiers{Identity: s.label, Objects: refs}
		data, err := json.Marshal(payload)
		if err != nil {
			slog.Warn("recon.MCPIdentifiers: marshal payload", "label", s.label, "error", err)
			continue
		}
		obs = append(obs, output.Observation{
			Type:   ObservationTypeIdentifiers,
			Target: s.label,
			Data:   data,
			Source: m.Name(),
		})
	}
	return obs, nil
}

// toolCatalog prefers a shared MCP inventory observation, falling back to a live
// ListTools enumeration when none is available.
// toolCatalog resolves the tool surface this module classifies, preferring a prior
// recon.MCP inventory over a second live enumeration.
//
// A TRUNCATED tool catalog is refused on both paths, and that matters more here than
// it looks. This module's output is the ownership ground truth mcptool.BOLA replays
// against, and BOLA emits nothing when there are no identifiers. So a partial catalog
// whose prefix happens to omit the real getter or enumerator makes this module
// classify nothing, emit no identifiers, and leave BOLA reporting a clean no-op
// against a surface that was never examined — the partial-as-empty failure this
// branch exists to remove, laundered through two modules.
//
// Reconnaissance renders no verdict, so an unreachable target is still a skip; only a
// truncated enumeration is escalated to an error.
func (m *MCPIdentifiers) toolCatalog(ctx context.Context, gen types.Generator) ([]map[string]any, error) {
	var tools []map[string]any
	for _, inv := range InventoriesFrom(m.Store()) {
		if !inv.IsCatalogComplete(types.MCPCatalogTools) {
			slog.Warn("recon.MCPIdentifiers: ignoring an inventory with an incomplete tools catalog",
				"incomplete_catalogs", inv.Incomplete, "tools_in_inventory", len(inv.Tools))
			continue
		}
		tools = append(tools, inv.ToolMaps()...)
	}
	if len(tools) > 0 {
		return tools, nil
	}
	if ti, ok := gen.(types.ToolInvoker); ok {
		slog.Debug("recon.MCPIdentifiers: no complete prior mcp.inventory; enumerating live (run recon.MCP first to reuse)")
		lt, err := ti.ListTools(ctx)
		if err != nil {
			// Truncation is not an ordinary list failure: swallowing it would emit no
			// identifiers and hand BOLA a clean no-op. Surface it so the scan reports an
			// unenumerable surface instead of an empty one.
			if errors.Is(err, types.ErrCatalogTruncated) {
				return nil, fmt.Errorf("recon.MCPIdentifiers: tool catalog incomplete, refusing to build a partial ownership map: %w", err)
			}
			slog.Warn("recon.MCPIdentifiers: list tools", "error", err)
			return nil, nil
		}
		return lt, nil
	}
	return nil, nil
}

// specs returns every callable signature on the surface.
//
// There is deliberately no classification into "enumerators" and "getters".
// Which tools hand out identifiers and which accept them is a property of the
// SERVER's behaviour, not of its names or its schema, and the module already
// calls tools — so it can find out rather than guess.
//
// Guessing is what broke: deciding the role from a required id-shaped parameter
// meant that on any tenant-scoped surface, where a scope identifier is declared
// on every tool, every tool looked like a getter, nothing was left to enumerate
// from, and a target full of objects reported none.
func (m *MCPIdentifiers) specs(tools []map[string]any) []toolSpec {
	var out []toolSpec
	for _, tool := range tools {
		out = append(out, specsOf(tool)...)
	}
	// Operator hints order the work so the tools most likely to yield
	// identifiers are called first. They are a hint, never a gate: a tool left
	// out of them is still tried, because a wrong hint should cost time, not
	// coverage.
	first := toSet(m.enumerationTools)
	sort.SliceStable(out, func(i, j int) bool {
		return first[out[i].name] && !first[out[j].name]
	})
	return out
}

// idCandidates returns the parameters of a signature that could carry an object
// identifier.
//
// An explicit id_params entry wins outright. Otherwise EVERY id-shaped string
// parameter is a candidate — not one chosen in advance. Choosing meant deciding,
// from a name alone, which of several id-shaped parameters names the object,
// and that question has no answer in a schema. Trying each and keeping what the
// server actually honours does have one.
func (m *MCPIdentifiers) idCandidates(spec toolSpec) []toolsig.Param {
	if p, ok := m.idParams[spec.name]; ok {
		for _, cand := range spec.params {
			if string(cand.Path) == p || cand.Path.Leaf() == p {
				return []toolsig.Param{cand}
			}
		}
	}
	var out []toolsig.Param
	for _, p := range spec.params {
		if p.Type != "" && p.Type != "string" {
			continue
		}
		if matchWord(m.idParamRE, p.Path.Leaf()) {
			out = append(out, p)
		}
	}
	return out
}

// discover finds the object identifiers one identity owns, by observing the
// server rather than by classifying it.
//
//  1. call every signature once with benign arguments, and keep the
//     identifier-shaped values that come back
//  2. feed each harvested value into each identifier-shaped parameter, and keep
//     the pairs whose answer differs from that slot's not-found answer
//
// Step 2 is what makes a "getter" a getter: not its name, not its schema, but
// the server returning something for this value that it does not return for one
// that cannot exist.
func (m *MCPIdentifiers) discover(ctx context.Context, s identitySession, specs []toolSpec) []types.MCPObjectRef {
	type candidate struct{ id, source string }
	var candidates []candidate
	seen := map[string]bool{}

	for _, spec := range specs {
		if skip, reason := m.policy.Skip(spec.name, spec.tm); skip {
			slog.Warn("recon.MCPIdentifiers: not invoking tool (call-site policy gate)", "tool", spec.name, "reason", reason)
			continue
		}
		res, err := s.inv.CallTool(ctx, spec.name, spec.callArgs(s.chain, ""))
		if err != nil || res.IsError {
			continue
		}
		ids := extractIDs(m.idParamRE, res.Text, res.Raw)
		if len(ids) > m.maxIDsPerTool {
			slog.Warn("recon.MCPIdentifiers: truncating harvested ids to max_ids_per_tool; raise it to widen authorization coverage",
				"tool", spec.name, "identity", s.label, "found", len(ids), "kept", m.maxIDsPerTool)
			ids = ids[:m.maxIDsPerTool]
		}
		for _, id := range ids {
			if seen[id] {
				continue
			}
			seen[id] = true
			candidates = append(candidates, candidate{id: id, source: spec.name})
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	var refs []types.MCPObjectRef
	confirmed := map[string]bool{}
	for _, spec := range specs {
		if skip, _ := m.policy.Skip(spec.name, spec.tm); skip {
			continue
		}
		for _, idParam := range m.idCandidates(spec) {
			slot := spec
			slot.idParam, slot.idPath = idParam.Path.Leaf(), idParam.Path

			// What this slot says about an identifier that cannot exist. Many
			// servers report "not found" as a NORMAL result with an error in the
			// body, so without this every harvested string would confirm.
			baseline, haveBaseline := m.notFoundBaseline(ctx, s, slot)

			// The value this identity's own chain already puts in this slot is not
			// an object it OWNS — it is the scope it operates in. A tenant-scoped
			// surface hands its tenant back in every response, so the tenant is
			// harvested as a candidate, fed into the tenant argument, and confirmed
			// against a not-found baseline it obviously differs from. The result was
			// recorded as an object, and mcptool.BOLA then "attacked" it by sending
			// the victim's own tenant to the victim's own tenant argument — a call
			// that any correct server serves, reported as a cross-tenant read.
			scope := ""
			if v, _, ok := s.chain.Value(idParam); ok {
				scope = fmt.Sprint(v)
			}

			for _, cand := range candidates {
				if scope != "" && cand.id == scope {
					slog.Debug("recon.MCPIdentifiers: candidate equals this identity's own value for the slot; it names the scope, not an object it owns",
						"identity", s.label, "tool", slot.name, "param", string(slot.idPath))
					continue
				}
				key := slot.name + "|" + string(slot.idPath) + "|" + cand.id
				if confirmed[key] {
					continue
				}
				args := slot.callArgs(s.chain, cand.id)
				res, err := s.inv.CallTool(ctx, slot.name, args)
				if err != nil || res.IsError || strings.TrimSpace(res.Text) == "" {
					continue
				}
				if haveBaseline && sameAsBaseline(res.Text, cand.id, baseline.text, baseline.id) {
					continue // indistinguishable from asking for something that does not exist
				}
				confirmed[key] = true
				refs = append(refs, types.MCPObjectRef{
					Tool:      slot.name,
					Param:     slot.idParam,
					ParamPath: string(slot.idPath),
					ID:        cand.id,
					Source:    cand.source,
					Args:      args,
				})
			}
		}
	}
	return refs
}

// notFoundResponse is a getter's answer for an identifier that cannot exist.
type notFoundResponse struct {
	id   string
	text string
}

// notFoundBaseline asks a getter for a deliberately nonexistent identifier and
// records what it says, so that a real answer can be told apart from a refusal
// dressed as a normal result.
//
// One call per getter. A failure to obtain it is not fatal: the caller falls
// back to the weaker IsError/emptiness check rather than discarding candidates
// it cannot adjudicate.
func (m *MCPIdentifiers) notFoundBaseline(ctx context.Context, s identitySession, g toolSpec) (notFoundResponse, bool) {
	nxID := "aug-nonexistent-" + strconv.Itoa(len(g.name)*7+13)
	res, err := s.inv.CallTool(ctx, g.name, g.callArgs(s.chain, nxID))
	if err != nil || strings.TrimSpace(res.Text) == "" {
		return notFoundResponse{}, false
	}
	return notFoundResponse{id: nxID, text: res.Text}, true
}

// sameAsBaseline reports whether a getter's answer for a candidate is the same
// answer it gives for an identifier that does not exist, once identifiers have
// been masked out of both. Servers echo the id they were asked about, so without
// masking every response would look distinct.
//
// BOTH identifiers are masked in BOTH responses, not each in its own. A
// candidate value can appear in the baseline's response as well — a tenant
// identifier harvested as a candidate is still echoed as the tenant of the
// baseline call — and masking only each response's own id leaves that occurrence
// behind, making two identical refusals compare unequal.
func sameAsBaseline(candText, candID, baseText, baseID string) bool {
	const mask = "\x00AUGID\x00"
	norm := func(s string) string {
		if candID != "" {
			s = strings.ReplaceAll(s, candID, mask)
		}
		if baseID != "" {
			s = strings.ReplaceAll(s, baseID, mask)
		}
		return s
	}
	return norm(candText) == norm(baseText)
}

// --- deterministic helpers -------------------------------------------------

// specsOf parses a tool into one spec per call signature.
//
// Parsing lives in internal/toolsig, shared with the probe packages. Recon used
// to keep its own copy that read only a schema's top-level properties, which
// meant an identifier nested inside an object was invisible and a discriminator
// was filled with a placeholder the server rejected — so a tool that hands out
// identifiers all day yielded none.
func specsOf(tool map[string]any) []toolSpec {
	name, _ := tool["name"].(string)
	schema, ok := tool["parameters"].(map[string]any)
	if !ok {
		return nil
	}
	raw, err := json.Marshal(schema)
	if err != nil {
		return nil
	}
	sigs, err := toolsig.Signatures(name, raw)
	if err != nil {
		return nil
	}
	out := make([]toolSpec, 0, len(sigs))
	for _, sig := range sigs {
		out = append(out, toolSpec{name: name, sig: sig, params: sig.Params, tm: tool})
	}
	return out
}

// valueChain supplies arguments for a recon call: what the schema declares
// first, then a type-shaped placeholder for anything left.
//
// The schema half is what recon previously lacked entirely. A discriminator
// declaring enum ["get","search","list"] was filled with "test", the server
// rejected the call before the tool ran, and no identifiers came back — a
// failure that looked like a target with nothing to find.
func valueChain() toolsig.Chain {
	return toolsig.Chain{toolsig.FromSchema(), placeholderFiller{}}
}

// placeholderFiller supplies a type-shaped value for a REQUIRED parameter the
// schema does not determine, so the call reaches the tool instead of failing
// argument validation. Optional parameters are left unset, as before, so the
// tool applies its own defaults.
type placeholderFiller struct{}

func (placeholderFiller) Name() string { return "placeholder" }

func (placeholderFiller) Value(p toolsig.Param) (any, bool) {
	if !p.Required {
		return nil, false
	}
	switch p.Type {
	case "integer", "number":
		return 1, true
	case "boolean":
		return true, true
	case "array":
		return []any{}, true
	case "object":
		return map[string]any{}, true
	default:
		return "test", true
	}
}

// callArgs builds the arguments for one call to a spec, with id placed at the
// spec's identifier path when one is given.
func (t toolSpec) callArgs(chain toolsig.Chain, id string) map[string]any {
	call, _ := t.sig.Build(chain)
	if t.idPath != "" {
		call.Set(t.idPath, id)
	}
	return call.Args()
}

// extractIDs walks a tool result's JSON and collects the scalar values of every
// key matching objectIDParamRE, de-duplicated and in a deterministic order.
func extractIDs(idRE *regexp.Regexp, text string, raw []byte) []string {
	root, ok := decodeJSONValue(raw, text)
	if !ok {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	// underIDKey is true when walking the elements of an array whose parent key
	// matched the id matcher, so an enumerator returning an array of SCALAR ids
	// (e.g. {"userIds":["1","2"]}) is harvested rather than dropped.
	var walk func(v any, underIDKey bool)
	walk = func(v any, underIDKey bool) {
		switch t := v.(type) {
		case map[string]any:
			for _, k := range sortedMapKeys(t) {
				val := t[k]
				keyMatch := matchWord(idRE, k)
				if keyMatch {
					add(scalarString(val))
				}
				walk(val, keyMatch)
			}
		case []any:
			for _, e := range t {
				if underIDKey {
					add(scalarString(e))
				}
				walk(e, underIDKey)
			}
		}
	}
	walk(root, false)
	return out
}

// decodeJSONValue decodes the tool's output into a generic JSON value. It
// prefers Text (the assembled tool payload) over Raw: for a real MCP result Raw
// is the protocol envelope with the payload nested as an escaped string, so
// walking it would miss the object's own keys. Raw is only a fallback for the
// rare case Text is empty but Raw holds a bare payload.
func decodeJSONValue(raw []byte, text string) (any, bool) {
	var root any
	if strings.TrimSpace(text) != "" {
		if err := json.Unmarshal([]byte(text), &root); err == nil {
			return root, true
		}
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &root); err == nil {
			return root, true
		}
	}
	return nil, false
}

// scalarString renders a JSON scalar as a string, skipping composite values.
func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	default:
		return ""
	}
}

// --- config parsing --------------------------------------------------------

func parseVictims(cfg registry.Config) []victimConfig {
	raw, ok := cfg["victims"]
	if !ok {
		return nil
	}
	var list []any
	switch v := raw.(type) {
	case []any:
		list = v
	case []map[string]any:
		for _, m := range v {
			list = append(list, m)
		}
	default:
		return nil
	}

	var out []victimConfig
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		mc := registry.Config(m)
		vc := victimConfig{
			label:   registry.GetString(mc, "label", ""),
			genType: registry.GetString(mc, "generator_type", ""),
			genCfg:  registry.Config{},
		}
		if gc, ok := m["generator_config"].(map[string]any); ok {
			vc.genCfg = registry.Config(gc)
		}
		// Read the same "values:" shape the module reads for the primary identity,
		// so an operator writes one form of rule regardless of which identity it
		// belongs to.
		vc.rules = toolsig.RulesFromConfig(mc)
		if vc.label != "" && vc.genType != "" {
			out = append(out, vc)
		}
	}
	return out
}

func parseIDParams(cfg registry.Config) map[string]string {
	raw, ok := cfg["id_params"].(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for k, v := range raw {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

func toSet(ss []string) map[string]bool {
	if len(ss) == 0 {
		return nil
	}
	out := make(map[string]bool, len(ss))
	for _, s := range ss {
		out[s] = true
	}
	return out
}

func sortedMapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
