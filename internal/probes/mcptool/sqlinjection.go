package mcptool

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

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

// sqlBooleanPayloads are pairs of tautology/contradiction suffixes appended to a
// benign value. The differential between the three calls (baseline, tautology,
// contradiction) proves unparameterised SQL if the shapes diverge predictably.
// All payloads are READ-ONLY: no stacked statements, no schema modification.
var sqlBooleanPayloads = []struct {
	tautology     string
	contradiction string
}{
	{`' OR '1'='1`, `' AND '1'='2`},
	{`" OR "1"="1`, `" AND "1"="2`},
	{` OR 1=1--`, ` AND 1=2--`},
}

// sqlErrorPayloads elicit database error messages without modifying data.
var sqlErrorPayloads = []string{
	`'`,
	`"`,
	`' OR '`,
	`'; --`,
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
	`|(?:pq|psycopg2|pgadmin)[\s:.]+.*error` +
	`|ora-\d{5}` +
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
//     tool, sends a baseline call, then tautology and contradiction payloads and
//     compares response shapes via responseTemplate. The tautology must differ
//     from baseline (more data returned) while the contradiction must NOT differ
//     from baseline (both return the same empty/narrow shape). This asymmetry
//     proves the parameter feeds an unparameterised SQL query. Tools without
//     positive read-intent are skipped — a tautology on a mutating tool
//     (DELETE WHERE ...) could widen a destructive clause.
//   - Database error: sends an unbalanced quote and checks the response for
//     database engine error signatures. A match means the backend leaks SQL
//     error details — itself a finding. This oracle runs on all tools regardless
//     of read-intent since the error payload is a single quote that cannot
//     modify data.
//
// All payloads are read-only. No DROP, DELETE, INSERT, UPDATE, ALTER, CREATE,
// TRUNCATE, UNION SELECT, or time-based oracles.
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
			"- Boolean differential: a baseline call, then tautology (`' OR '1'='1`) and contradiction (`' AND '1'='2`). When the tautology produces a materially different (wider) response shape than baseline while the contradiction matches baseline (both return the same narrow/empty shape), the parameter feeds an unparameterised SQL query. Only tested on tools with positive read-intent to avoid widening destructive clauses.\n" +
			"- Database error: an unbalanced quote (`'`) is sent and the response is checked for database engine error signatures (sqlite, mysql, postgres, etc). A match proves the backend leaks SQL error details.\n\n" +
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
		out = append(out, "test"+bp.tautology, "test"+bp.contradiction)
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
// escaped variants of the payload. responseTemplate only strips the literal
// a.Prompt, but tools that JSON-encode, URL-encode, or repr()-escape their
// arguments will not match. This function strips common escaped forms so a
// tool that echoes {"query": "test' OR '1'='1"} does not produce a different
// template from {"query": "test"}.
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
			isRead := readIntent(tool, ts.params)
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
					slog.Debug("mcptool.SQLInjection: skipping boolean differential on non-read-intent tool",
						"tool", name, "param", param.name)
				}
				attempts = append(attempts, p.runErrorOracle(ctx, inv, name, param, ts)...)
			}
		}
	}
	return attempts, nil
}

// runBooleanDifferential sends one baseline call (deduplicated across payload
// pairs), then tautology and contradiction for each pair, and records the
// comparison verdict. The finding condition is asymmetric:
//
//	tautology != baseline (the tautology changed something)
//	tautology != contradiction (the two payloads have different effects)
//	len(tautology) > len(contradiction) (tautology returned more data)
//
// This catches both the zero-row-baseline case (baseline=empty, tautology=all,
// contradiction=empty) and the some-row case (baseline=Alice, tautology=all,
// contradiction=empty). It rejects echo tools (identical shapes after stripping
// the echoed payload), constant tools, and dynamic tools (filtered by baseline
// stability check).
func (p *SQLInjection) runBooleanDifferential(ctx context.Context, inv types.ToolInvoker, tool string, param paramInfo, ts toolSig) []*attempt.Attempt {
	baseValue := p.baselineValue(param, ts)

	// Issue baseline once and verify stability: two identical calls must produce
	// the same shape, otherwise the tool has dynamic fields (timestamps, request
	// IDs) that make the differential unreliable.
	baseline1 := p.callSQLI(ctx, inv, tool, param, ts, baseValue)
	baseline1.Metadata[attempt.MetadataKeySQLInjectionOracle] = "boolean_differential"
	baseline2 := p.callSQLI(ctx, inv, tool, param, ts, baseValue)
	baseline2.Metadata[attempt.MetadataKeySQLInjectionOracle] = "boolean_differential"

	shape1 := sqlResponseTemplate(baseline1)
	shape2 := sqlResponseTemplate(baseline2)
	allAttempts := []*attempt.Attempt{baseline1}
	if shape1 == "" || shape1 != shape2 {
		return allAttempts
	}

	baselineShape := shape1

	for _, bp := range sqlBooleanPayloads {
		if ctx.Err() != nil {
			break
		}

		tautologyPayload := baseValue + bp.tautology
		contradictionPayload := baseValue + bp.contradiction

		tautologyAttempt := p.callSQLI(ctx, inv, tool, param, ts, tautologyPayload)
		tautologyAttempt.Metadata[attempt.MetadataKeySQLInjectionOracle] = "boolean_differential"
		allAttempts = append(allAttempts, tautologyAttempt)

		contradictionAttempt := p.callSQLI(ctx, inv, tool, param, ts, contradictionPayload)
		contradictionAttempt.Metadata[attempt.MetadataKeySQLInjectionOracle] = "boolean_differential"
		allAttempts = append(allAttempts, contradictionAttempt)

		tautologyShape := sqlResponseTemplate(tautologyAttempt)
		contradictionShape := sqlResponseTemplate(contradictionAttempt)

		// The finding condition is asymmetric:
		//   tautology must DIFFER from baseline (it widened the query)
		//   tautology must DIFFER from contradiction (the two payloads have different effects)
		//   tautology must be LONGER than contradiction (wider result set, more data)
		// This rejects: echo tools (shapes are identical after stripping the echoed
		// payload), uniform/constant tools (all same shape), dynamic tools (filtered
		// by baseline stability check above). The zero-row-baseline case works
		// because contradiction is empty like baseline while tautology is full.
		differential := tautologyShape != "" &&
			contradictionShape != "" &&
			tautologyShape != baselineShape &&
			tautologyShape != contradictionShape &&
			len(tautologyShape) > len(contradictionShape)

		if differential {
			tautologyAttempt.Metadata[attempt.MetadataKeySQLInjectionBooleanDifferential] = true
			tautologyAttempt.Metadata[attempt.MetadataKeySQLInjectionBaselineResponse] = strings.Join(baseline1.Outputs, "\n")
			tautologyAttempt.Metadata[attempt.MetadataKeySQLInjectionTautologyResponse] = strings.Join(tautologyAttempt.Outputs, "\n")
			tautologyAttempt.Metadata[attempt.MetadataKeySQLInjectionContradictionResponse] = strings.Join(contradictionAttempt.Outputs, "\n")
		}
	}
	return allAttempts
}

// baselineValue picks the best benign value for a parameter: from the value
// chain (operator config, hooks, recon observed values) via benignArgsFor,
// falling back to declaredValue, then a hardcoded "test".
func (p *SQLInjection) baselineValue(param paramInfo, ts toolSig) string {
	benign := ts.benignArgsFor()
	if v, ok := benign[string(param.path)]; ok {
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
// the response for engine-specific error signatures.
func (p *SQLInjection) runErrorOracle(ctx context.Context, inv types.ToolInvoker, tool string, param paramInfo, ts toolSig) []*attempt.Attempt {
	var attempts []*attempt.Attempt
	for _, payload := range sqlErrorPayloads {
		if ctx.Err() != nil {
			break
		}
		a := p.callSQLI(ctx, inv, tool, param, ts, payload)
		a.Metadata[attempt.MetadataKeySQLInjectionOracle] = "database_error"

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
	a.AddOutput(res.Text)
	a.Complete()
	return a
}
