package mcptool

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/internal/toolpolicy"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("mcptool.SQLInjection", NewSQLInjection)
}

var (
	_ types.ProbeMetadata     = (*SQLInjection)(nil)
	_ recon.ContextAwareProbe = (*SQLInjection)(nil)
	_ types.RiskDescriber     = (*SQLInjection)(nil)
)

// sqlQueryParamRE matches parameter names likely to feed a database lookup —
// search, query, filter, name, etc. Applied via matchesSQLQueryParam() which
// normalises camelCase first so `searchQuery`, `userName`, `findById` match.
var sqlQueryParamRE = regexp.MustCompile(`(?i)(^|[_\- ])(search|query|q|keyword|term|filter|find|lookup|select|fetch|where|name|title|user|username|email|id|identifier)($|[_\- ])`)

// sqlBooleanPayloads are AND-true / AND-false pairs appended to a benign value.
// AND-true (e.g. ' AND '1'='1) is a no-op in SQL: it does not change the WHERE
// clause's selectivity. AND-false (e.g. ' AND '1'='2) falsifies the entire
// clause and returns zero rows.
//
// Finding condition: AND-true shape == baseline AND AND-false shape != baseline.
// This proves SQL context because a non-SQL search engine (Elasticsearch
// query_string, Jira JQL) interprets AND as a keyword search operator, so
// AND-true produces a DIFFERENT result from baseline (extra search terms). Only
// real SQL treats AND TRUE as a no-op.
var sqlBooleanPayloads = []struct {
	andTrue  string
	andFalse string
}{
	{`' AND '1'='1`, `' AND '1'='2`},
	{`" AND "1"="1`, `" AND "1"="2`},
	{` AND 1=1-- `, ` AND 1=2-- `},
}

// sqlErrorPayloads elicit database error messages without modifying data.
// Only unbalanced quotes — no statement terminators or comment sequences,
// which could truncate a WHERE clause on a mutating tool.
var sqlErrorPayloads = []string{
	`'`,
	`"`,
}

// dbErrorRE matches database engine error signatures leaked in a response.
// Each alternative is tightened to avoid matching non-SQL error messages:
//   - sqlite: "unrecognized token" and "sqlite3.OperationalError" are unique
//   - mysql/mariadb: "you have an error in your SQL syntax" (canonical 1064),
//     or "mysql"/"mariadb" adjacent to "syntax" or "error"
//   - postgres: "pq:" (colon-required), "psycopg2", "pgadmin", "pgx" driver
//     prefixes; "unterminated quoted string" is a pg-specific parser message
//   - oracle: ORA-##### is a unique oracle error format
//   - mssql: "sql server", "microsoft ole db", "unclosed quotation mark"
//   - generic: SQLSTATE followed by bracket or space+alphanumeric (covers
//     SQLSTATE[42000], SQLSTATE[HY000], and pgx-style "SQLSTATE 42601")
var dbErrorRE = regexp.MustCompile(`(?i)(` +
	`unrecognized token` +
	`|sqlite3?\.OperationalError` +
	`|you have an error in your SQL syntax` +
	`|mysql.*syntax.*error|mysql.*error.*syntax` +
	`|\b(?:pq:|psycopg2|pgadmin|pgx)[\s:.]+` +
	`|\bora-\d{5}` +
	`|microsoft.*ole db` +
	`|sql server.*(?:error|native client)` +
	`|mariadb.*error` +
	`|SQLSTATE[\[\s][0-9A-Z]` +
	`|quoted string not properly terminated` +
	`|unterminated quoted string` +
	`|unclosed quotation mark` +
	`)`)

// SQLInjection tests a directly-invokable tool surface for SQL injection via
// two independent oracles:
//
//   - Boolean differential: for each SQL-query-intent parameter on a read-intent
//     tool, sends a baseline call, then AND-true and AND-false payloads and
//     compares response shapes. AND-true (AND '1'='1) is a no-op in SQL, so it
//     must match baseline. AND-false (AND '1'='2) falsifies the WHERE clause, so
//     it must differ from baseline. This asymmetry proves the parameter feeds an
//     unparameterised SQL query. Non-SQL search engines (Elasticsearch, JQL) treat
//     AND as a keyword operator and produce a different result for AND-true vs
//     baseline, so they do not trigger. Tools without positive read-intent (from
//     annotations or name/description) are skipped.
//   - Database error: sends an unbalanced quote and checks the response for
//     database engine error signatures. A match indicates the backend leaks SQL
//     error details — partial evidence (scored 0.5, routed to REVIEW) since a
//     parameterised query can also throw on type mismatches.
//
// All payloads are read-only. No DROP, DELETE, INSERT, UPDATE, ALTER, CREATE,
// TRUNCATE, UNION SELECT, statement terminators, or time-based oracles.
type SQLInjection struct {
	reconContext
	policy toolpolicy.Policy
}

// NewSQLInjection constructs the probe with the tool-safety policy.
func NewSQLInjection(cfg registry.Config) (probes.Prober, error) {
	probe := &SQLInjection{
		policy: toolpolicy.New(cfg),
	}
	probe.configure(cfg)
	return probe, nil
}

func (p *SQLInjection) Name() string { return "mcptool.SQLInjection" }

func (p *SQLInjection) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description:    "A directly-invokable MCP tool passes attacker-controlled arguments into an SQL query without parameterisation, allowing arbitrary query manipulation.",
		Impact:         "A caller who can invoke the tool can read, modify, or delete database records beyond the intended scope, potentially exfiltrating the entire database or escalating privileges.",
		Recommendation: "Use parameterised queries (prepared statements) for all database access. Never concatenate user input into SQL strings. Apply least-privilege database users so the tool's connection cannot access tables beyond its scope.",
		References:     "https://cwe.mitre.org/data/definitions/89.html\nhttps://owasp.org/www-community/attacks/SQL_Injection",
		Taxonomies:     "- cwe: 89",
		CVSSVector:     "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		Verification: "## How this is confirmed\n\n" +
			"Augustus tests each SQL-query-intent parameter with two independent oracles:\n\n" +
			"- Boolean differential: a baseline call, then AND-true (`' AND '1'='1`) and AND-false (`' AND '1'='2`). When AND-true matches baseline (SQL no-op) and AND-false differs (SQL falsification), the parameter feeds an unparameterised SQL query. Only tested on tools with positive read-intent to avoid widening destructive clauses.\n" +
			"- Database error: an unbalanced quote (`'`) is sent and the response is checked for database engine error signatures (sqlite, mysql, postgres, etc). A match is partial evidence (the backend leaks SQL error details, but parameterised queries can also produce type errors).\n\n" +
			"## Reproduce\n\n" +
			"Re-run the `mcptool.SQLInjection` probe against the affected endpoint via the `mcp.MCP` generator (`mode: list_tools`).",
	}
}

func (p *SQLInjection) Description() string {
	return "Tests directly-invokable tools for SQL injection via boolean-differential and database-error oracles, using read-only payloads only"
}

func (p *SQLInjection) Goal() string {
	return "Determine whether any directly-invokable tool passes arguments into unparameterised SQL queries"
}

func (p *SQLInjection) GetPrimaryDetector() string { return "mcptool.SQLInjection" }

func (p *SQLInjection) GetPrompts() []string {
	var out []string
	for _, bp := range sqlBooleanPayloads {
		out = append(out, "test"+bp.andTrue, "test"+bp.andFalse)
	}
	out = append(out, sqlErrorPayloads...)
	return out
}

// hasSQLQueryParam reports whether this tool exposes at least one string
// parameter this probe would actually inject into. Used to gate discoverValues
// so tools with no SQL-query-intent parameter never receive a live call.
func hasSQLQueryParam(params []paramInfo) bool {
	for _, p := range params {
		if isStringParam(p.typ) && matchesSQLQueryParam(p.name) {
			return true
		}
	}
	return false
}

// matchesSQLQueryParam tests a parameter name against sqlQueryParamRE after
// camelCase normalisation (same approach as pathtraversal.go's matchesPathParam).
func matchesSQLQueryParam(name string) bool {
	normalised := camelCaseBoundaryRE.ReplaceAllString(name, "${1}_${2}")
	return sqlQueryParamRE.MatchString(normalised)
}

// sqlExtraStrip computes extra strings to pass to responseTemplate so that
// every boolean-differential response is shape-compared symmetrically:
//
//   - JSON-escaped variants of the prompt (tools that echo JSON-encoded input)
//   - The base value and its JSON-escaped variants (so "test" is stripped from
//     AND-true responses whose prompt is "test' AND '1'='1", matching baseline
//     where prompt="test" is already stripped)
func sqlExtraStrip(prompt, baseValue string) []string {
	var extras []string
	for _, s := range []string{prompt, baseValue} {
		if s == "" {
			continue
		}
		if e := strings.ReplaceAll(s, `"`, `\"`); e != s {
			extras = append(extras, e)
		}
		if e := strings.ReplaceAll(s, `'`, `\'`); e != s {
			extras = append(extras, e)
		}
	}
	if baseValue != "" && baseValue != prompt {
		extras = append(extras, baseValue)
	}
	return extras
}

// sqlIsRead checks whether a tool should receive boolean differential payloads.
// It checks MCP annotations first (the strongest signal), then falls back to
// readIntent for name/description inference.
func sqlIsRead(tool map[string]any, params []paramInfo) bool {
	if ann, ok := tool["annotations"].(types.MCPToolAnnotations); ok {
		if ann.ReadOnly {
			return true
		}
		if ann.IsDestructive() {
			return false
		}
	}
	return readIntent(tool, params)
}

// sqlUsableResponse reports whether an attempt's response is a genuine tool
// answer suitable for shape comparison. It rejects error status, IsError tool
// results, and tool refusals (MetadataKeyTargetRefused) — a refusal message is
// evidence that the tool validated its input, not that the SQL clause changed.
func sqlUsableResponse(a *attempt.Attempt) bool {
	if a.Status != attempt.StatusComplete {
		return false
	}
	if v, _ := a.Metadata["mcptool.tool_is_error"].(bool); v {
		return false
	}
	if v, _ := a.Metadata[attempt.MetadataKeyTargetRefused].(bool); v {
		return false
	}
	return true
}

// Probe discovers the target's tools and runs both SQL injection oracles against
// each qualifying string parameter. Returns an error for non-ToolInvoker targets.
func (p *SQLInjection) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	inv, ok := p.invoker(gen)
	if !ok {
		return nil, fmt.Errorf("mcptool.SQLInjection: target %q does not support direct tool invocation; this probe requires a tool-surface generator such as mcp.MCP", gen.Name())
	}

	tools, err := p.resolveTools(ctx, gen)
	if err != nil {
		return nil, fmt.Errorf("mcptool.SQLInjection: list tools: %w", err)
	}
	tools = p.policy.Filter(p.Name(), tools)
	if len(tools) == 0 {
		return nil, nil
	}

	var attempts []*attempt.Attempt

	for _, tool := range tools {
		name, _ := tool["name"].(string)
		if name == "" {
			continue
		}
		for _, ts := range toolSignatures(tool, p.valueChain(ctx, name)) {
			p.warnBroadRules(name, ts.sig.Params)
			if hasSQLQueryParam(ts.params) {
				ts = ts.withShape(p.shapeMode()).discoverValues(ctx, inv, name)
			}
			isRead := sqlIsRead(tool, ts.params)
			for _, param := range ts.params {
				if !isStringParam(param.typ) {
					continue
				}
				if !matchesSQLQueryParam(param.name) {
					continue
				}
				if ctx.Err() != nil {
					return attempts, nil
				}
				if isRead {
					attempts = append(attempts, p.runBooleanDifferential(ctx, inv, name, param, ts)...)
				} else {
					a := attempt.New("")
					a.Probe = p.Name()
					a.Detector = p.GetPrimaryDetector()
					a.Metadata["mcptool.tool"] = name
					a.Metadata["mcptool.param"] = string(param.path)
					mcpprobe.MarkNotTested(a, "boolean differential skipped: tool is not read-intent")
					a.Complete()
					attempts = append(attempts, a)
				}
				attempts = append(attempts, p.runErrorOracle(ctx, inv, name, param, ts)...)
			}
		}
	}
	return attempts, nil
}

// runBooleanDifferential sends one baseline call (deduplicated across payload
// pairs), then AND-true and AND-false for each pair, and records the comparison
// verdict. The finding condition is:
//
//	AND-true shape == baseline (AND TRUE is a no-op in SQL)
//	AND-false shape != baseline (AND FALSE falsifies the WHERE clause)
//
// This proves SQL context: a non-SQL search engine treats AND as a keyword
// operator, so AND-true produces a DIFFERENT result from baseline (extra search
// terms), and the finding condition does not fire. Echo tools are rejected
// because all shapes are identical after stripping the echoed payload. Constant
// and dynamic tools are rejected by the baseline stability check.
func (p *SQLInjection) runBooleanDifferential(ctx context.Context, inv types.ToolInvoker, tool string, param paramInfo, ts toolSig) []*attempt.Attempt {
	baseValue := p.baselineValue(param, ts)
	baseExtras := sqlExtraStrip(baseValue, baseValue)

	baseline1 := p.callSQLI(ctx, inv, tool, param, ts, baseValue)
	baseline1.Metadata[attempt.MetadataKeySQLInjectionOracle] = "boolean_differential"
	baseline2 := p.callSQLI(ctx, inv, tool, param, ts, baseValue)
	baseline2.Metadata[attempt.MetadataKeySQLInjectionOracle] = "boolean_differential"
	allAttempts := []*attempt.Attempt{baseline1, baseline2}

	// Check status before shapes — a failed or refused baseline is not usable.
	if !sqlUsableResponse(baseline1) || !sqlUsableResponse(baseline2) {
		mcpprobe.MarkNotTested(baseline1, "boolean differential skipped: baseline call failed")
		mcpprobe.MarkNotTested(baseline2, "boolean differential skipped: baseline call failed")
		return allAttempts
	}

	shape1 := responseTemplate(baseline1, baseExtras...)
	shape2 := responseTemplate(baseline2, baseExtras...)
	if shape1 != shape2 {
		mcpprobe.MarkNotTested(baseline1, "boolean differential skipped: unstable baseline response")
		mcpprobe.MarkNotTested(baseline2, "boolean differential skipped: unstable baseline response")
		return allAttempts
	}

	baselineShape := shape1
	if baselineShape == "" {
		mcpprobe.MarkNotTested(baseline1, "boolean differential skipped: empty baseline response")
		mcpprobe.MarkNotTested(baseline2, "boolean differential skipped: empty baseline response")
		return allAttempts
	}

	var anyDiscriminated, anyConfirmed, anyUsablePair bool
	for _, bp := range sqlBooleanPayloads {
		if ctx.Err() != nil {
			break
		}

		andTruePayload := baseValue + bp.andTrue
		andFalsePayload := baseValue + bp.andFalse

		andTrueAttempt := p.callSQLI(ctx, inv, tool, param, ts, andTruePayload)
		andTrueAttempt.Metadata[attempt.MetadataKeySQLInjectionOracle] = "boolean_differential"
		allAttempts = append(allAttempts, andTrueAttempt)

		andFalseAttempt := p.callSQLI(ctx, inv, tool, param, ts, andFalsePayload)
		andFalseAttempt.Metadata[attempt.MetadataKeySQLInjectionOracle] = "boolean_differential"
		allAttempts = append(allAttempts, andFalseAttempt)

		// Symmetric shape comparison: strip both payload and base value from all
		// responses so "test user" in baseline (prompt="test") and AND-true
		// (prompt="test' AND '1'='1") both reduce to "Result: user".
		andTrueShape := responseTemplate(andTrueAttempt, sqlExtraStrip(andTruePayload, baseValue)...)
		andFalseShape := responseTemplate(andFalseAttempt, sqlExtraStrip(andFalsePayload, baseValue)...)

		usableTrue := sqlUsableResponse(andTrueAttempt)
		usableFalse := sqlUsableResponse(andFalseAttempt)
		if usableTrue && usableFalse {
			anyUsablePair = true
		}

		// Track whether any payload pair produced discrimination (the tool
		// responded differently to at least one payload). When no pair does,
		// the oracle is inconclusive rather than negative.
		if usableTrue && usableFalse &&
			(andTrueShape != baselineShape || andFalseShape != baselineShape) {
			anyDiscriminated = true
		}

		// Exclude attempts where the tool returned IsError or refused the call
		// — a rejection is not the same as a SQL WHERE-clause falsification.
		differential := sqlUsableResponse(andTrueAttempt) &&
			sqlUsableResponse(andFalseAttempt) &&
			andTrueShape != "" &&
			andTrueShape == baselineShape &&
			andFalseShape != baselineShape

		// Confirm: repeat AND-false to guard against transient differences
		// (rate limits, timestamps on the Nth call, etc.).
		if differential {
			confirm := p.callSQLI(ctx, inv, tool, param, ts, andFalsePayload)
			confirm.Metadata[attempt.MetadataKeySQLInjectionOracle] = "boolean_differential"
			allAttempts = append(allAttempts, confirm)

			confirmShape := responseTemplate(confirm, sqlExtraStrip(andFalsePayload, baseValue)...)
			if !sqlUsableResponse(confirm) || confirmShape != andFalseShape {
				differential = false
			}
		}

		// Post-confirmation baseline re-check: verify the tool's behaviour
		// hasn't changed persistently (rate-limit, session expiry, quota
		// exhaustion returned as ordinary tool text).
		if differential {
			postCheck := p.callSQLI(ctx, inv, tool, param, ts, baseValue)
			postCheck.Metadata[attempt.MetadataKeySQLInjectionOracle] = "boolean_differential"
			allAttempts = append(allAttempts, postCheck)

			postShape := responseTemplate(postCheck, baseExtras...)
			if !sqlUsableResponse(postCheck) || postShape != baselineShape {
				differential = false
			}
		}

		if differential {
			anyConfirmed = true
			andTrueAttempt.Metadata[attempt.MetadataKeySQLInjectionBooleanDifferential] = true
			andTrueAttempt.Metadata[attempt.MetadataKeySQLInjectionBaselineResponse] = strings.Join(baseline1.Outputs, "\n")
			andTrueAttempt.Metadata[attempt.MetadataKeySQLInjectionTautologyResponse] = strings.Join(andTrueAttempt.Outputs, "\n")
			andTrueAttempt.Metadata[attempt.MetadataKeySQLInjectionContradictionResponse] = strings.Join(andFalseAttempt.Outputs, "\n")
		}
	}

	// When no payload pair produced a confirmed finding AND no pair
	// discriminated, the oracle is inconclusive. Distinguish two cases:
	//   - All payload pairs were refused/IsError (no usable pair): the tool
	//     validated input, which is a negative test, not a coverage gap.
	//   - Usable pairs all produced identical shapes: likely because the base
	//     value matches zero rows. Mark ALL attempts as not-tested per
	//     AGENTS.md "skip is not clean".
	if !anyConfirmed && !anyDiscriminated && anyUsablePair {
		reason := "boolean differential inconclusive: tool responded identically to all payload pairs; consider supplying a values: rule that returns rows"
		for _, a := range allAttempts {
			mcpprobe.MarkNotTested(a, reason)
		}
	}

	return allAttempts
}

// baselineValue picks the best benign value for a parameter: from the value
// chain (operator config, hooks, recon observed values) via the Call's flat
// kv store, falling back to declaredValue, then a hardcoded "test".
func (p *SQLInjection) baselineValue(param paramInfo, ts toolSig) string {
	call, _ := ts.sig.Build(ts.chain())
	if v, ok := call.Get(param.path); ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	if v, ok := declaredValue(param); ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return "test"
}

// runErrorOracle sends payloads that elicit database error messages and checks
// the response for engine-specific error signatures. A benign-value baseline
// is sent first as a negative control: signatures already present in normal
// output (log search results, tool names containing DB prefixes) are excluded.
// The error oracle is partial evidence: a parameterised query can also throw on
// type mismatches, so database-error-only findings score InconclusiveScore (0.5)
// in the detector.
func (p *SQLInjection) runErrorOracle(ctx context.Context, inv types.ToolInvoker, tool string, param paramInfo, ts toolSig) []*attempt.Attempt {
	baseValue := p.baselineValue(param, ts)
	benign := p.callSQLI(ctx, inv, tool, param, ts, baseValue)
	benign.Metadata[attempt.MetadataKeySQLInjectionOracle] = "database_error"

	// Collect DB-error signatures present in the benign response so we can
	// exclude them from payload responses (negative control).
	benignSigs := make(map[string]bool)
	for _, out := range benign.Outputs {
		for _, m := range dbErrorRE.FindAllString(out, -1) {
			benignSigs[m] = true
		}
	}
	if benign.Error != "" {
		for _, m := range dbErrorRE.FindAllString(benign.Error, -1) {
			benignSigs[m] = true
		}
	}

	attempts := []*attempt.Attempt{benign}
	for _, payload := range sqlErrorPayloads {
		if ctx.Err() != nil {
			break
		}
		a := p.callSQLI(ctx, inv, tool, param, ts, payload)
		a.Metadata[attempt.MetadataKeySQLInjectionOracle] = "database_error"
		attempts = append(attempts, a)

		for _, out := range a.Outputs {
			if m := dbErrorRE.FindString(out); m != "" && !benignSigs[m] {
				a.Metadata[attempt.MetadataKeySQLInjectionDatabaseError] = true
				a.Metadata[attempt.MetadataKeySQLInjectionErrorPattern] = m
				break
			}
		}
		// MCP servers may surface SQL exceptions as JSON-RPC error messages
		// (e.g. -32603 internal error) with empty outputs — check a.Error too.
		// When found, promote from StatusError to StatusComplete so the finding
		// surfaces as REVIEW, not buried under "error" in the summary.
		if _, found := a.Metadata[attempt.MetadataKeySQLInjectionDatabaseError]; !found && a.Error != "" {
			if m := dbErrorRE.FindString(a.Error); m != "" && !benignSigs[m] {
				a.Metadata[attempt.MetadataKeySQLInjectionDatabaseError] = true
				a.Metadata[attempt.MetadataKeySQLInjectionErrorPattern] = m
				delete(a.Metadata, attempt.MetadataKeyNotTested)
				delete(a.Metadata, attempt.MetadataKeyNotTestedReason)
				a.AddOutput(a.Error)
				a.Complete()
			}
		}
	}
	return attempts
}

// callSQLI invokes a single (tool, param, payload) and records the attempt.
func (p *SQLInjection) callSQLI(ctx context.Context, inv types.ToolInvoker, tool string, param paramInfo, ts toolSig, payload string) *attempt.Attempt {
	a := attempt.New(payload)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata["mcptool.tool"] = tool
	a.Metadata["mcptool.param"] = string(param.path)

	args := ts.args(param, payload)
	res, err := inv.CallTool(ctx, tool, args)
	if err != nil {
		ts.recordCallFailure(a, param, args, err)
		return a
	}
	if res.IsError {
		a.Metadata["mcptool.tool_is_error"] = true
	}
	a.AddOutput(res.Text)
	a.Complete()
	return a
}
