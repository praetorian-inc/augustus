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

// TestSQLInjection_BooleanDifferential: a vulnerable search tool that returns
// different results for baseline, tautology, and contradiction is detected.
func TestSQLInjection_BooleanDifferential(t *testing.T) {
	p := newSQLInjectionProbe(t)
	target := &mockTarget{
		tools: []map[string]any{stringTool("search", "query")},
		call: func(_ string, args map[string]any) types.ToolResult {
			q, _ := args["query"].(string)
			switch {
			case strings.Contains(q, "OR '1'='1"),
				strings.Contains(q, "OR \"1\"=\"1"),
				strings.Contains(q, "OR 1=1--"):
				return types.ToolResult{Text: "Result: Alice, Bob, Charlie, Dave, Eve"}
			case strings.Contains(q, "AND '1'='2"),
				strings.Contains(q, "AND \"1\"=\"2"),
				strings.Contains(q, "AND 1=2--"):
				return types.ToolResult{Text: "No results found"}
			default:
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

// TestSQLInjection_ZeroRowBaseline: when "test" matches zero rows, the
// baseline and contradiction are both empty while the tautology returns all
// rows. The asymmetric check must still fire.
func TestSQLInjection_ZeroRowBaseline(t *testing.T) {
	p := newSQLInjectionProbe(t)
	target := &mockTarget{
		tools: []map[string]any{stringTool("search", "query")},
		call: func(_ string, args map[string]any) types.ToolResult {
			q, _ := args["query"].(string)
			switch {
			case strings.Contains(q, "OR '1'='1"),
				strings.Contains(q, "OR \"1\"=\"1"),
				strings.Contains(q, "OR 1=1--"):
				return types.ToolResult{Text: "Result: Alice, Bob, Charlie, Dave, Eve"}
			default:
				return types.ToolResult{Text: "No results found"}
			}
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
	assert.True(t, found, "expected boolean-differential finding even with zero-row baseline")
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

// TestSQLInjection_SkipsBooleanOnNonReadTool: boolean differential must be
// skipped on tools that are not classified as read-intent, to avoid widening
// a mutating clause (DELETE WHERE ... OR '1'='1').
func TestSQLInjection_SkipsBooleanOnNonReadTool(t *testing.T) {
	p := newSQLInjectionProbe(t)
	target := &mockTarget{
		tools: []map[string]any{stringTool("delete_user", "username")},
		call: func(_ string, args map[string]any) types.ToolResult {
			q, _ := args["username"].(string)
			switch {
			case strings.Contains(q, "OR '1'='1"):
				return types.ToolResult{Text: "Deleted: all users"}
			case strings.Contains(q, "AND '1'='2"):
				return types.ToolResult{Text: "No users deleted"}
			default:
				return types.ToolResult{Text: "Deleted: 1 user"}
			}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	require.NoError(t, err)

	for _, a := range attempts {
		assert.False(t, metaBool(a, attempt.MetadataKeySQLInjectionBooleanDifferential),
			"non-read-intent tool must not receive boolean differential payloads")
	}
	// Error oracle still runs — single-quote payloads can't widen destructive clauses.
	require.NotEmpty(t, attempts, "error oracle should still run on non-read tools")
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
