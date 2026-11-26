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
	{` AND 1=1--`, ` AND 1=2--`},
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
//   - sqlite: "unrecognized token" is unique to sqlite's parser
//   - mysql: requires "mysql" adjacent to "syntax" or "error"
//   - postgres: requires the "pq:" or "psycopg2" or "pgadmin" prefix, not bare "pg"
//   - oracle: ORA-##### is a unique oracle error format
//   - mssql: "sql server" or "microsoft ole db" are specific identifiers
//   - generic: SQLSTATE[ is the standard SQL error state prefix
var dbErrorRE = regexp.MustCompile(`(?i)(` +
	`unrecognized token` +
	`|sqlite3?\.OperationalError` +
	`|mysql.*syntax.*error|mysql.*error.*syntax` +
	`|\b(?:pq|psycopg2|pgadmin)[\s:.]+.*error` +
	`|\bora-\d{5}` +
	`|microsoft.*ole db` +
	`|sql server.*error` +
	`|mariadb.*error` +
	`|SQLSTATE\[` +
	`|quoted string not properly terminated` +
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

// sqlResponseTemplate extends responseTemplate with additional stripping for
// escaped variants of the payload. Tools that JSON-encode or repr()-escape
// their arguments would otherwise produce different shapes for different
// payloads even though the semantic content is identical.
func sqlResponseTemplate(a *attempt.Attempt) string {
	if a == nil || len(a.Outputs) == 0 {
		return ""
	}
	s := strings.Join(a.Outputs, "\n")
	if a.Prompt != "" {
		s = strings.ReplaceAll(s, a.Prompt, " ")
		jsonEscaped := strings.ReplaceAll(a.Prompt, `"`, `\"`)
		s = strings.ReplaceAll(s, jsonEscaped, " ")
		jsonEscaped2 := strings.ReplaceAll(a.Prompt, `'`, `\'`)
		s = strings.ReplaceAll(s, jsonEscaped2, " ")
	}
	s = strings.NewReplacer("'", " ", `"`, " ", "`", " ").Replace(s)
	return strings.Join(strings.Fields(s), " ")
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

	// Issue baseline twice and verify stability: two identical calls must produce
	// the same shape, otherwise the tool has dynamic fields (timestamps, request
	// IDs) that make the differential unreliable.
	baseline1 := p.callSQLI(ctx, inv, tool, param, ts, baseValue)
	baseline1.Metadata[attempt.MetadataKeySQLInjectionOracle] = "boolean_differential"
	baseline2 := p.callSQLI(ctx, inv, tool, param, ts, baseValue)
	baseline2.Metadata[attempt.MetadataKeySQLInjectionOracle] = "boolean_differential"

	shape1 := sqlResponseTemplate(baseline1)
	shape2 := sqlResponseTemplate(baseline2)
	allAttempts := []*attempt.Attempt{baseline1, baseline2}
	if shape1 != shape2 {
		mcpprobe.MarkNotTested(baseline1, "boolean differential skipped: unstable baseline response")
		return allAttempts
	}
	if baseline1.Status != attempt.StatusComplete {
		mcpprobe.MarkNotTested(baseline1, "boolean differential skipped: baseline call failed")
		return allAttempts
	}

	baselineShape := shape1

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

		andTrueShape := sqlResponseTemplate(andTrueAttempt)
		andFalseShape := sqlResponseTemplate(andFalseAttempt)

		// Finding condition:
		//   AND-true must EQUAL baseline (AND TRUE is a no-op in SQL)
		//   AND-false must DIFFER from baseline (AND FALSE returns nothing)
		// This proves SQL context because a non-SQL search engine interprets
		// AND as a keyword operator and "test' AND '1'='1" produces a different
		// search than "test".
		differential := andTrueShape != "" &&
			andTrueAttempt.Status == attempt.StatusComplete &&
			andFalseAttempt.Status == attempt.StatusComplete &&
			andTrueShape == baselineShape &&
			andFalseShape != baselineShape

		if differential {
			andTrueAttempt.Metadata[attempt.MetadataKeySQLInjectionBooleanDifferential] = true
			andTrueAttempt.Metadata[attempt.MetadataKeySQLInjectionBaselineResponse] = strings.Join(baseline1.Outputs, "\n")
			andTrueAttempt.Metadata[attempt.MetadataKeySQLInjectionTautologyResponse] = strings.Join(andTrueAttempt.Outputs, "\n")
			andTrueAttempt.Metadata[attempt.MetadataKeySQLInjectionContradictionResponse] = strings.Join(andFalseAttempt.Outputs, "\n")
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
// the response for engine-specific error signatures. The error oracle is
// partial evidence: a parameterised query can also throw on type mismatches,
// so database-error-only findings score InconclusiveScore (0.5) in the detector.
func (p *SQLInjection) runErrorOracle(ctx context.Context, inv types.ToolInvoker, tool string, param paramInfo, ts toolSig) []*attempt.Attempt {
	var attempts []*attempt.Attempt
	for _, payload := range sqlErrorPayloads {
		if ctx.Err() != nil {
			break
		}
		a := p.callSQLI(ctx, inv, tool, param, ts, payload)
		a.Metadata[attempt.MetadataKeySQLInjectionOracle] = "database_error"

		if a.Status != attempt.StatusComplete {
			continue
		}
		for _, out := range a.Outputs {
			if m := dbErrorRE.FindString(out); m != "" {
				a.Metadata[attempt.MetadataKeySQLInjectionDatabaseError] = true
				a.Metadata[attempt.MetadataKeySQLInjectionErrorPattern] = m
				break
			}
		}
		attempts = append(attempts, a)
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
