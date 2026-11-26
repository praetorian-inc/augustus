package mcptool

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func newSQLInjectionProbe(t *testing.T) *SQLInjection {
	t.Helper()
	p, err := NewSQLInjection(registry.Config{})
	require.NoError(t, err)
	return p.(*SQLInjection)
}

// TestSQLInjection_FailsLoudOnNonToolInvoker: probe must error rather than
// return a clean-looking empty result when the target cannot be tool-invoked.
func TestSQLInjection_FailsLoudOnNonToolInvoker(t *testing.T) {
	p := newSQLInjectionProbe(t)
	_, err := p.Probe(context.Background(), plainGen{})
	assert.Error(t, err, "expected error for non-ToolInvoker target")
}

// TestSQLInjection_SkipsNonSQLParams: tools with no SQL-query-intent param
// produce no attempts.
func TestSQLInjection_SkipsNonSQLParams(t *testing.T) {
	p := newSQLInjectionProbe(t)
	target := &mockTarget{
		tools: []map[string]any{stringTool("note", "text")},
		call: func(_ string, _ map[string]any) types.ToolResult {
			return types.ToolResult{Text: "ok"}
		},
	}
	attempts, err := p.Probe(context.Background(), target)
	require.NoError(t, err)
	assert.Empty(t, attempts, "expected no attempts for non-SQL params")
}

// TestSQLInjection_BooleanDifferential: a vulnerable search tool where AND-true
// matches baseline but AND-false differs is detected.
func TestSQLInjection_BooleanDifferential(t *testing.T) {
	p := newSQLInjectionProbe(t)
	target := &mockTarget{
		tools: []map[string]any{stringTool("search", "query")},
		call: func(_ string, args map[string]any) types.ToolResult {
			q, _ := args["query"].(string)
			// Simulate an unparameterised SQL query:
			// AND-true is a no-op → same as baseline
			// AND-false falsifies the clause → empty result
			switch {
			case strings.Contains(q, "AND '1'='2"),
				strings.Contains(q, "AND \"1\"=\"2"),
				strings.Contains(q, "AND 1=2--"):
				return types.ToolResult{Text: "No results found"}
			default:
				// baseline AND "test' AND '1'='1" both return the same result
				return types.ToolResult{Text: "Result: Alice"}
			}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	var found bool
	for _, a := range attempts {
		if metaBool(a, attempt.MetadataKeySQLInjectionBooleanDifferential) {
			found = true
			assert.NotEmpty(t, a.Metadata[attempt.MetadataKeySQLInjectionBaselineResponse])
			assert.NotEmpty(t, a.Metadata[attempt.MetadataKeySQLInjectionTautologyResponse])
			assert.NotEmpty(t, a.Metadata[attempt.MetadataKeySQLInjectionContradictionResponse])
			break
		}
	}
	assert.True(t, found, "expected at least one boolean-differential finding")
}

// metaBool is a test-local helper that reads a boolean metadata value.
func metaBool(a *attempt.Attempt, key string) bool {
	raw, ok := a.GetMetadata(key)
	if !ok {
		return false
	}
	b, _ := raw.(bool)
	return b
}

// TestSQLInjection_ZeroRowBaseline: when "test" matches zero rows, baseline
// and AND-true both return empty while AND-false also returns empty. The
// AND-true == baseline condition holds, and AND-false == baseline too, so the
// finding does NOT fire (correctly: we can't distinguish SQL from "always empty").
// When AND-false genuinely returns something different (error or different shape),
// the finding fires.
func TestSQLInjection_ZeroRowBaseline(t *testing.T) {
	t.Run("AND-false also empty — no finding", func(t *testing.T) {
		p := newSQLInjectionProbe(t)
		target := &mockTarget{
			tools: []map[string]any{stringTool("search", "query")},
			call: func(_ string, _ map[string]any) types.ToolResult {
				return types.ToolResult{Text: "No results found"}
			},
		}
		attempts, err := p.Probe(context.Background(), target)
		require.NoError(t, err)
		for _, a := range attempts {
			assert.False(t, metaBool(a, attempt.MetadataKeySQLInjectionBooleanDifferential))
		}
	})

	t.Run("AND-true matches baseline, AND-false different — finding", func(t *testing.T) {
		p := newSQLInjectionProbe(t)
		target := &mockTarget{
			tools: []map[string]any{stringTool("search", "query")},
			call: func(_ string, args map[string]any) types.ToolResult {
				q, _ := args["query"].(string)
				if strings.Contains(q, "AND '1'='2") ||
					strings.Contains(q, "AND \"1\"=\"2") ||
					strings.Contains(q, "AND 1=2--") {
					return types.ToolResult{Text: "Error: no rows match filter"}
				}
				return types.ToolResult{Text: "No results found"}
			},
		}
		attempts, err := p.Probe(context.Background(), target)
		require.NoError(t, err)
		var found bool
		for _, a := range attempts {
			if metaBool(a, attempt.MetadataKeySQLInjectionBooleanDifferential) {
				found = true
				break
			}
		}
		assert.True(t, found, "expected finding when AND-false shape differs from baseline")
	})
}

// TestSQLInjection_NoFalsePositiveOnEcho: a tool that echoes its input must
// NOT fire. After sqlResponseTemplate strips the payload, all shapes are equal.
func TestSQLInjection_NoFalsePositiveOnEcho(t *testing.T) {
	p := newSQLInjectionProbe(t)
	target := &mockTarget{
		tools: []map[string]any{stringTool("search", "query")},
		call: func(_ string, args map[string]any) types.ToolResult {
			q, _ := args["query"].(string)
			return types.ToolResult{Text: fmt.Sprintf("Searching for: %s", q)}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	require.NoError(t, err)

	for _, a := range attempts {
		assert.False(t, metaBool(a, attempt.MetadataKeySQLInjectionBooleanDifferential),
			"echo tool should not trigger boolean differential")
		assert.False(t, metaBool(a, attempt.MetadataKeySQLInjectionDatabaseError),
			"echo tool should not trigger database error")
	}
}

// TestSQLInjection_NoFalsePositiveOnJSONEcho: a tool that JSON-encodes its
// input must NOT fire. sqlResponseTemplate strips escaped payload variants.
func TestSQLInjection_NoFalsePositiveOnJSONEcho(t *testing.T) {
	p := newSQLInjectionProbe(t)
	target := &mockTarget{
		tools: []map[string]any{stringTool("search", "query")},
		call: func(_ string, args map[string]any) types.ToolResult {
			q, _ := args["query"].(string)
			escaped := strings.ReplaceAll(q, `"`, `\"`)
			return types.ToolResult{Text: fmt.Sprintf(`{"query": "%s", "results": []}`, escaped)}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	require.NoError(t, err)

	for _, a := range attempts {
		assert.False(t, metaBool(a, attempt.MetadataKeySQLInjectionBooleanDifferential),
			"JSON-echo tool should not trigger boolean differential")
	}
}

// TestSQLInjection_NoFalsePositiveOnSearchEngine: a non-SQL search engine
// (Elasticsearch query_string, JQL) that interprets OR/AND as keyword operators
// must NOT fire. The AND-true payload changes the search query, so its shape
// differs from baseline, failing the AND-true == baseline condition.
func TestSQLInjection_NoFalsePositiveOnSearchEngine(t *testing.T) {
	p := newSQLInjectionProbe(t)
	target := &mockTarget{
		tools: []map[string]any{stringTool("search", "query")},
		call: func(_ string, args map[string]any) types.ToolResult {
			q, _ := args["query"].(string)
			// Simulate a full-text search engine that parses AND/OR as operators.
			// AND narrows the result, so "test' AND '1'='1" searches for
			// docs matching "test'" AND "'1'='1" — different from just "test".
			switch {
			case strings.Contains(q, "AND '1'='1"):
				return types.ToolResult{Text: "Results: 2 documents (test', 1=1)"}
			case strings.Contains(q, "AND '1'='2"):
				return types.ToolResult{Text: "Results: 0 documents"}
			default:
				return types.ToolResult{Text: "Results: 5 documents (test)"}
			}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	require.NoError(t, err)

	for _, a := range attempts {
		assert.False(t, metaBool(a, attempt.MetadataKeySQLInjectionBooleanDifferential),
			"search engine should not trigger boolean differential")
	}
}

// TestSQLInjection_SkipsBooleanOnNonReadTool: boolean differential must be
// skipped on tools that are not classified as read-intent, and the skip must
// produce a not-tested marker rather than a clean 0.0 score.
func TestSQLInjection_SkipsBooleanOnNonReadTool(t *testing.T) {
	p := newSQLInjectionProbe(t)
	target := &mockTarget{
		tools: []map[string]any{stringTool("delete_user", "username")},
		call: func(_ string, args map[string]any) types.ToolResult {
			return types.ToolResult{Text: "ok"}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	require.NoError(t, err)

	var hasNotTested bool
	for _, a := range attempts {
		assert.False(t, metaBool(a, attempt.MetadataKeySQLInjectionBooleanDifferential),
			"non-read-intent tool must not receive boolean differential payloads")
		if metaBool(a, attempt.MetadataKeyNotTested) {
			hasNotTested = true
		}
	}
	assert.True(t, hasNotTested, "skip must produce a not-tested marker, not a clean 0.0")
	require.NotEmpty(t, attempts, "error oracle should still run on non-read tools")
}

// TestSQLInjection_UnstableBaselineMarksNotTested: when the baseline is
// unstable (two identical calls produce different shapes), the probe must
// mark the attempt as not-tested.
func TestSQLInjection_UnstableBaselineMarksNotTested(t *testing.T) {
	p := newSQLInjectionProbe(t)
	callCount := 0
	target := &mockTarget{
		tools: []map[string]any{stringTool("search", "query")},
		call: func(_ string, _ map[string]any) types.ToolResult {
			callCount++
			return types.ToolResult{Text: fmt.Sprintf("Request #%d at some timestamp", callCount)}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	require.NoError(t, err)

	var hasNotTested bool
	for _, a := range attempts {
		assert.False(t, metaBool(a, attempt.MetadataKeySQLInjectionBooleanDifferential))
		if metaBool(a, attempt.MetadataKeyNotTested) {
			hasNotTested = true
		}
	}
	assert.True(t, hasNotTested, "unstable baseline must produce a not-tested marker")
}

// TestSQLInjection_DatabaseErrorOracle: a tool that returns database errors on
// bad input is detected via the error oracle.
func TestSQLInjection_DatabaseErrorOracle(t *testing.T) {
	p := newSQLInjectionProbe(t)
	target := &mockTarget{
		tools: []map[string]any{stringTool("lookup", "name")},
		call: func(_ string, args map[string]any) types.ToolResult {
			q, _ := args["name"].(string)
			if strings.Contains(q, "'") {
				return types.ToolResult{
					Text: "sqlite3.OperationalError: unrecognized token: \"'\"",
				}
			}
			return types.ToolResult{Text: "User: " + q}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	var found bool
	for _, a := range attempts {
		if metaBool(a, attempt.MetadataKeySQLInjectionDatabaseError) {
			found = true
			pattern, ok := a.GetMetadata(attempt.MetadataKeySQLInjectionErrorPattern)
			assert.True(t, ok, "error pattern metadata should be present")
			assert.NotEmpty(t, pattern)
			break
		}
	}
	assert.True(t, found, "expected at least one database-error finding")
}

// TestSQLInjection_ErrorRegexRejectsNonSQL: strings like "upgrade error" or
// "JPG processing error" must NOT match the tightened dbErrorRE.
func TestSQLInjection_ErrorRegexRejectsNonSQL(t *testing.T) {
	nonSQL := []string{
		"upgrade error: failed to migrate",
		"JPG processing error in module",
		"page load error",
		"unterminated string literal in JSON",
		"syntax error near unexpected token '('",
		"pg_dump: error processing table",
	}
	for _, s := range nonSQL {
		assert.False(t, dbErrorRE.MatchString(s), "dbErrorRE should not match %q", s)
	}
}

// TestSQLInjection_ErrorRegexMatchesRealDB: real database error strings must
// match dbErrorRE.
func TestSQLInjection_ErrorRegexMatchesRealDB(t *testing.T) {
	realErrors := []string{
		"sqlite3.OperationalError: unrecognized token",
		"mysql syntax error near 'SELECT'",
		"pq: error in query",
		"psycopg2.OperationalError: error",
		"ORA-01756: quoted string not properly terminated",
		"microsoft ole db provider for sql server",
		"sql server native client error",
		"SQLSTATE[42000]",
		"mariadb error 1064",
	}
	for _, s := range realErrors {
		assert.True(t, dbErrorRE.MatchString(s), "dbErrorRE should match %q", s)
	}
}

// TestSQLInjection_NoStatementTerminators: sqlErrorPayloads must not contain
// statement terminators or comment sequences that could truncate WHERE clauses.
func TestSQLInjection_NoStatementTerminators(t *testing.T) {
	for _, payload := range sqlErrorPayloads {
		assert.NotContains(t, payload, ";", "error payload must not contain statement terminator")
		assert.NotContains(t, payload, "--", "error payload must not contain comment sequence")
	}
}

// TestSQLInjection_ToolIsErrorRecorded: when a tool returns IsError=true, the
// attempt must record it in metadata.
func TestSQLInjection_ToolIsErrorRecorded(t *testing.T) {
	p := newSQLInjectionProbe(t)
	target := &mockTarget{
		tools: []map[string]any{stringTool("search", "query")},
		call: func(_ string, _ map[string]any) types.ToolResult {
			return types.ToolResult{Text: "rejected", IsError: true}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	require.NoError(t, err)

	var hasIsError bool
	for _, a := range attempts {
		if v, ok := a.GetMetadata("mcptool.tool_is_error"); ok {
			if b, ok := v.(bool); ok && b {
				hasIsError = true
				break
			}
		}
	}
	assert.True(t, hasIsError, "tool IsError should be recorded in metadata")
}

// TestSQLInjection_NormalToolNoFinding: a tool that behaves normally (no SQL
// vulnerability) produces no findings.
func TestSQLInjection_NormalToolNoFinding(t *testing.T) {
	p := newSQLInjectionProbe(t)
	target := &mockTarget{
		tools: []map[string]any{stringTool("search", "query")},
		call: func(_ string, args map[string]any) types.ToolResult {
			return types.ToolResult{Text: "Results: 3 items found"}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	require.NoError(t, err)

	for _, a := range attempts {
		assert.False(t, metaBool(a, attempt.MetadataKeySQLInjectionBooleanDifferential))
		assert.False(t, metaBool(a, attempt.MetadataKeySQLInjectionDatabaseError))
	}
}

// TestSQLInjection_CamelCaseParamMatches: parameters like searchQuery and
// userName should match the SQL-query-intent regex after camelCase normalisation.
func TestSQLInjection_CamelCaseParamMatches(t *testing.T) {
	assert.True(t, matchesSQLQueryParam("searchQuery"))
	assert.True(t, matchesSQLQueryParam("userName"))
	assert.True(t, matchesSQLQueryParam("filterBy"))
	assert.True(t, matchesSQLQueryParam("findById"))
	assert.False(t, matchesSQLQueryParam("text"))
	assert.False(t, matchesSQLQueryParam("content"))
}

// TestSQLInjection_Metadata: verify probe metadata methods.
func TestSQLInjection_Metadata(t *testing.T) {
	p := newSQLInjectionProbe(t)
	assert.Equal(t, "mcptool.SQLInjection", p.Name())
	assert.Equal(t, "mcptool.SQLInjection", p.GetPrimaryDetector())
	assert.NotEmpty(t, p.Description())
	assert.NotEmpty(t, p.Goal())
	assert.NotEmpty(t, p.GetPrompts())

	ri := p.RiskInfo()
	assert.Contains(t, ri.Taxonomies, "89")
	assert.NotEmpty(t, ri.CVSSVector)
	assert.NotEmpty(t, ri.Recommendation)
}
