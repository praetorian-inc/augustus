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
			// Simulate an unparameterised SQL query:
			// tautology gets more results, contradiction gets nothing.
			switch {
			case strings.Contains(q, "OR '1'='1"):
				return types.ToolResult{Text: "Result: Alice, Bob, Charlie, Dave, Eve"}
			case strings.Contains(q, "AND '1'='2"):
				return types.ToolResult{Text: "No results found"}
			case strings.Contains(q, "OR \"1\"=\"1"):
				return types.ToolResult{Text: "Result: Alice, Bob, Charlie, Dave, Eve"}
			case strings.Contains(q, "AND \"1\"=\"2"):
				return types.ToolResult{Text: "No results found"}
			case strings.Contains(q, "OR 1=1--"):
				return types.ToolResult{Text: "Result: Alice, Bob, Charlie, Dave, Eve"}
			case strings.Contains(q, "AND 1=2--"):
				return types.ToolResult{Text: "No results found"}
			default:
				return types.ToolResult{Text: "Result: Alice"}
			}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// At least one attempt should have the boolean differential confirmed.
	var found bool
	for _, a := range attempts {
		if metaBool(a, attempt.MetadataKeySQLInjectionBooleanDifferential) {
			found = true
			// Verify evidence metadata is present.
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

// TestSQLInjection_NoFalsePositiveOnEcho: a tool that echoes its input and
// reports success must NOT fire. The echo response has the same shape regardless
// of injection, so the boolean differential does not trigger.
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

// TestSQLInjection_NormalToolNoFinding: a tool that behaves normally (no SQL
// vulnerability) produces no findings.
func TestSQLInjection_NormalToolNoFinding(t *testing.T) {
	p := newSQLInjectionProbe(t)
	target := &mockTarget{
		tools: []map[string]any{stringTool("search", "query")},
		call: func(_ string, args map[string]any) types.ToolResult {
			// Always returns the same shape regardless of input.
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

	sds := p.GetSecondaryDetectors()
	require.Len(t, sds, 1)
	assert.Equal(t, "mcpsecrets.Credential", sds[0].Name)
}
