package access_control

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

type reauthedMock struct {
	types.Generator
	identities map[string]types.Generator
}

func (m *reauthedMock) WithIdentity(token string) (types.Generator, error) {
	if gen, ok := m.identities[token]; ok {
		return gen, nil
	}
	return nil, fmt.Errorf("unknown token: %s", token)
}

// --- Metadata tests ---

func TestRBACProbe_Metadata(t *testing.T) {
	p := &RBACProbe{}
	if p.Name() != "access_control.RBAC" {
		t.Error("wrong name")
	}
	if p.GetPrimaryDetector() != "judge.Judge" {
		t.Error("wrong detector")
	}
	if p.GetPrompts() != nil {
		t.Error("prompts should be nil")
	}
	if p.Description() == "" {
		t.Error("description should not be empty")
	}
	if p.Goal() == "" {
		t.Error("goal should not be empty")
	}
}

// --- parseRoleHierarchy tests ---

func TestParseRoleHierarchy_Valid3Role(t *testing.T) {
	cfg := map[string]any{
		"role_hierarchy": []any{"viewer", "analyst", "admin"},
	}
	hierarchy, err := parseRoleHierarchy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hierarchy) != 3 {
		t.Errorf("expected 3 roles, got %d", len(hierarchy))
	}
	if hierarchy[0] != "viewer" || hierarchy[1] != "analyst" || hierarchy[2] != "admin" {
		t.Errorf("unexpected hierarchy: %v", hierarchy)
	}
}

func TestParseRoleHierarchy_Valid2Role(t *testing.T) {
	cfg := map[string]any{
		"role_hierarchy": []any{"viewer", "admin"},
	}
	hierarchy, err := parseRoleHierarchy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hierarchy) != 2 {
		t.Errorf("expected 2 roles, got %d", len(hierarchy))
	}
}

func TestParseRoleHierarchy_StringSlice(t *testing.T) {
	cfg := map[string]any{
		"role_hierarchy": []string{"viewer", "admin"},
	}
	hierarchy, err := parseRoleHierarchy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hierarchy) != 2 {
		t.Errorf("expected 2 roles, got %d", len(hierarchy))
	}
}

func TestParseRoleHierarchy_Missing(t *testing.T) {
	cfg := map[string]any{}
	_, err := parseRoleHierarchy(cfg)
	if err == nil {
		t.Error("expected error for missing role_hierarchy")
	}
}

func TestParseRoleHierarchy_TooFew(t *testing.T) {
	cfg := map[string]any{
		"role_hierarchy": []any{"viewer"},
	}
	_, err := parseRoleHierarchy(cfg)
	if err == nil {
		t.Error("expected error for single role")
	}
}

// --- categorizeToolsByRole tests ---

func TestCategorizeToolsByRole_ProgressiveDiscovery(t *testing.T) {
	hierarchy := []string{"viewer", "analyst", "admin"}
	toolsPerRole := map[string][]string{
		"viewer":  {"search_orders"},
		"analyst": {"search_orders", "generate_report"},
		"admin":   {"search_orders", "generate_report", "update_user_role"},
	}

	result := categorizeToolsByRole(hierarchy, toolsPerRole)

	if len(result) != 2 {
		t.Fatalf("expected 2 role-gated tools, got %d: %+v", len(result), result)
	}

	toolMap := make(map[string]ToolRoleInfo)
	for _, r := range result {
		toolMap[r.ToolName] = r
	}

	report, ok := toolMap["generate_report"]
	if !ok {
		t.Fatal("missing generate_report")
	}
	if report.MinLevel != 1 || report.MinRole != "analyst" {
		t.Errorf("generate_report: expected minLevel=1/analyst, got %d/%s", report.MinLevel, report.MinRole)
	}

	update, ok := toolMap["update_user_role"]
	if !ok {
		t.Fatal("missing update_user_role")
	}
	if update.MinLevel != 2 || update.MinRole != "admin" {
		t.Errorf("update_user_role: expected minLevel=2/admin, got %d/%s", update.MinLevel, update.MinRole)
	}
}

func TestCategorizeToolsByRole_AllShared(t *testing.T) {
	hierarchy := []string{"viewer", "admin"}
	toolsPerRole := map[string][]string{
		"viewer": {"search_orders", "list_tickets"},
		"admin":  {"search_orders", "list_tickets"},
	}

	result := categorizeToolsByRole(hierarchy, toolsPerRole)
	if len(result) != 0 {
		t.Errorf("all shared tools should be excluded, got %d: %+v", len(result), result)
	}
}

func TestCategorizeToolsByRole_TwoRole(t *testing.T) {
	hierarchy := []string{"viewer", "admin"}
	toolsPerRole := map[string][]string{
		"viewer": {"search_orders"},
		"admin":  {"search_orders", "delete_order"},
	}

	result := categorizeToolsByRole(hierarchy, toolsPerRole)
	if len(result) != 1 {
		t.Fatalf("expected 1 role-gated tool, got %d", len(result))
	}
	if result[0].ToolName != "delete_order" {
		t.Errorf("expected delete_order, got %s", result[0].ToolName)
	}
	if result[0].MinLevel != 1 {
		t.Errorf("expected minLevel=1, got %d", result[0].MinLevel)
	}
}

func TestCategorizeToolsByRole_Empty(t *testing.T) {
	result := categorizeToolsByRole([]string{"viewer", "admin"}, map[string][]string{})
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d", len(result))
	}
}

// --- buildBoundaries tests ---

func TestBuildBoundaries_3Role(t *testing.T) {
	roles := []RoleConfig{
		{Name: "viewer", Level: 0},
		{Name: "analyst", Level: 1},
		{Name: "admin", Level: 2},
	}
	boundaries := buildBoundaries(roles)
	if len(boundaries) != 3 {
		t.Fatalf("expected 3 boundaries, got %d", len(boundaries))
	}

	expected := map[string]bool{
		"viewer->analyst": false,
		"viewer->admin":   false,
		"analyst->admin":  false,
	}
	for _, b := range boundaries {
		key := b.AttackerRole + "->" + b.VictimRole
		if _, ok := expected[key]; !ok {
			t.Errorf("unexpected boundary: %s", key)
		}
		expected[key] = true
	}
	for key, found := range expected {
		if !found {
			t.Errorf("missing boundary: %s", key)
		}
	}
}

func TestBuildBoundaries_2Role(t *testing.T) {
	roles := []RoleConfig{
		{Name: "viewer", Level: 0},
		{Name: "admin", Level: 1},
	}
	boundaries := buildBoundaries(roles)
	if len(boundaries) != 1 {
		t.Fatalf("expected 1 boundary, got %d", len(boundaries))
	}
	if boundaries[0].AttackerRole != "viewer" || boundaries[0].VictimRole != "admin" {
		t.Errorf("expected viewer->admin, got %s->%s", boundaries[0].AttackerRole, boundaries[0].VictimRole)
	}
}

func TestBuildBoundaries_4Role(t *testing.T) {
	roles := []RoleConfig{
		{Name: "guest", Level: 0},
		{Name: "viewer", Level: 1},
		{Name: "editor", Level: 2},
		{Name: "admin", Level: 3},
	}
	boundaries := buildBoundaries(roles)
	if len(boundaries) != 6 {
		t.Fatalf("expected 6 boundaries, got %d", len(boundaries))
	}
}

// --- buildPermissionMatrix tests ---

func TestBuildPermissionMatrix_Mixed(t *testing.T) {
	roles := []RoleConfig{
		{Name: "viewer", Level: 0},
		{Name: "analyst", Level: 1},
		{Name: "admin", Level: 2},
	}
	tools := []ToolRoleInfo{
		{ToolName: "generate_report", MinLevel: 1, MinRole: "analyst"},
		{ToolName: "update_user_role", MinLevel: 2, MinRole: "admin"},
	}
	results := []RBACToolResult{
		{ToolName: "generate_report", AttackerRole: "viewer", VictimRole: "analyst", Success: true, TurnsUsed: 3},
		{ToolName: "update_user_role", AttackerRole: "viewer", VictimRole: "admin", Success: false, TurnsUsed: 2},
		{ToolName: "update_user_role", AttackerRole: "analyst", VictimRole: "admin", Success: false, TurnsUsed: 2},
	}

	matrix := buildPermissionMatrix(results, roles, tools)

	if matrix["admin"]["generate_report"] != "BASELINE" {
		t.Errorf("admin/generate_report: expected BASELINE, got %s", matrix["admin"]["generate_report"])
	}
	if matrix["admin"]["update_user_role"] != "BASELINE" {
		t.Errorf("admin/update_user_role: expected BASELINE, got %s", matrix["admin"]["update_user_role"])
	}
	if matrix["analyst"]["generate_report"] != "ALLOWED" {
		t.Errorf("analyst/generate_report: expected ALLOWED, got %s", matrix["analyst"]["generate_report"])
	}
	if matrix["analyst"]["update_user_role"] != "BLOCKED" {
		t.Errorf("analyst/update_user_role: expected BLOCKED, got %s", matrix["analyst"]["update_user_role"])
	}
	if !strings.Contains(matrix["viewer"]["generate_report"], "BREACH") {
		t.Errorf("viewer/generate_report: expected BREACH, got %s", matrix["viewer"]["generate_report"])
	}
	if matrix["viewer"]["update_user_role"] != "BLOCKED" {
		t.Errorf("viewer/update_user_role: expected BLOCKED, got %s", matrix["viewer"]["update_user_role"])
	}
}

func TestBuildPermissionMatrix_AllBlocked(t *testing.T) {
	roles := []RoleConfig{
		{Name: "viewer", Level: 0},
		{Name: "admin", Level: 1},
	}
	tools := []ToolRoleInfo{
		{ToolName: "delete_order", MinLevel: 1, MinRole: "admin"},
	}
	results := []RBACToolResult{
		{ToolName: "delete_order", AttackerRole: "viewer", VictimRole: "admin", Success: false, TurnsUsed: 3},
	}

	matrix := buildPermissionMatrix(results, roles, tools)

	if matrix["admin"]["delete_order"] != "BASELINE" {
		t.Errorf("admin: expected BASELINE, got %s", matrix["admin"]["delete_order"])
	}
	if matrix["viewer"]["delete_order"] != "BLOCKED" {
		t.Errorf("viewer: expected BLOCKED, got %s", matrix["viewer"]["delete_order"])
	}
}

// --- Prompt tests ---

func TestBuildRBACAttackerSystemPrompt(t *testing.T) {
	reconAll := []ReconResult{
		{
			ToolName:        "update_user_role",
			Description:     "Update a user's role",
			Category:        "admin",
			ResponseSummary: "User role updated to analyst",
		},
	}
	boundary := BoundaryTest{
		AttackerRole:  "viewer",
		VictimRole:    "admin",
		AttackerLevel: 0,
		VictimLevel:   2,
	}
	hierarchy := []string{"viewer", "analyst", "admin"}

	prompt := buildRBACAttackerSystemPrompt(reconAll, boundary, hierarchy, nil)

	checks := []string{
		"viewer",
		"admin",
		"update_user_role",
		"User role updated to analyst",
		"LOWER-PRIVILEGE",
		"DIRECT INVOCATION",
		"SEMANTIC ALIASING",
		"VERB-FAMILY SHIFT",
		"DECOMPOSITION",
		"IPI VIA TOOL ARGUMENTS",
		"INCREMENTAL COMMITMENT",
		"viewer < analyst < admin",
		"tool_tested",
		"strategy",
	}
	for _, check := range checks {
		if !strings.Contains(prompt, check) {
			t.Errorf("attacker prompt missing %q", check)
		}
	}
}

func TestBuildRBACAttackerSystemPrompt_WithViewerTools(t *testing.T) {
	reconAll := []ReconResult{
		{ToolName: "update_user_role", Category: "admin"},
	}
	boundary := BoundaryTest{
		AttackerRole: "viewer", VictimRole: "admin",
		AttackerLevel: 0, VictimLevel: 1,
	}
	viewerTools := []types.ToolSchema{
		{Name: "search_orders", Description: "Search orders"},
	}

	prompt := buildRBACAttackerSystemPrompt(reconAll, boundary, []string{"viewer", "admin"}, viewerTools)

	if !strings.Contains(prompt, "YOUR TOOLS") {
		t.Error("prompt should include YOUR TOOLS section when viewerTools provided")
	}
	if !strings.Contains(prompt, "search_orders") {
		t.Error("prompt should list viewer tool search_orders")
	}
}

func TestBuildRBACJudgeSystemPrompt(t *testing.T) {
	boundary := BoundaryTest{
		AttackerRole:  "analyst",
		VictimRole:    "admin",
		AttackerLevel: 1,
		VictimLevel:   2,
	}
	hierarchy := []string{"viewer", "analyst", "admin"}

	prompt := buildRBACJudgeSystemPrompt(boundary, hierarchy)

	checks := []string{
		"analyst",
		"admin",
		"level 1",
		"level 2",
		"viewer < analyst < admin",
		"EVALUATION PROCEDURE",
		"0.5", "0.3", "0.1",
		"breach_confirmed", "function_blocked",
	}
	for _, check := range checks {
		if !strings.Contains(prompt, check) {
			t.Errorf("judge prompt missing %q", check)
		}
	}
}

func TestBuildRBACFirstTurnPrompt(t *testing.T) {
	reconAll := []ReconResult{
		{ToolName: "update_user_role", ResponseSummary: "User role updated"},
		{ToolName: "run_analytics", ResponseSummary: "Analytics results"},
	}
	boundary := BoundaryTest{
		AttackerRole: "viewer",
		VictimRole:   "admin",
	}

	prompt := buildRBACFirstTurnPrompt(reconAll, boundary, 20)

	checks := []string{
		"Turn 1/20",
		"viewer",
		"admin",
		"update_user_role",
		"run_analytics",
		"20 turns",
		"2 role-gated tools",
	}
	for _, check := range checks {
		if !strings.Contains(prompt, check) {
			t.Errorf("first turn prompt missing %q", check)
		}
	}
}

func TestBuildRBACFeedback(t *testing.T) {
	recon := ReconResult{
		ToolName:        "delete_order",
		ResponseSummary: "Order 123 deleted",
	}
	jr := JudgeResult{
		Score:    0.0,
		Verdict:  "function_blocked",
		Evidence: "access denied response",
	}

	feedback := buildRBACFeedback("Access denied: insufficient permissions", jr, 1, 20, recon,
		"  delete_order: tested (1 turns, max score 0.00) <- current\n",
		"  delete_order: 0. DIRECT INVOCATION\n")

	checks := []string{
		"Turn 1/20",
		"Access denied",
		"0.00",
		"function_blocked",
		"Remaining turns: 19",
		"delete_order",
		"Coverage so far",
		"Strategies used so far",
	}
	for _, check := range checks {
		if !strings.Contains(feedback, check) {
			t.Errorf("feedback missing %q", check)
		}
	}
}

// --- formatHierarchy tests ---

func TestFormatHierarchy(t *testing.T) {
	result := formatHierarchy([]string{"viewer", "analyst", "admin"})
	if result != "viewer < analyst < admin" {
		t.Errorf("expected 'viewer < analyst < admin', got %q", result)
	}
}

// --- Recon tests ---

func TestRBACProbe_ReconSuccess(t *testing.T) {
	gen := &mockGenerator{
		response: "Here are the results from update_user_role: User role has been updated.",
	}

	result := reconSingleRoleTool(context.Background(), gen, "update_user_role", "admin")
	if !result.AdminSuccess {
		t.Error("expected success")
	}
	if result.ToolName != "update_user_role" {
		t.Errorf("wrong tool name: %s", result.ToolName)
	}
}

func TestRBACProbe_ReconRefused(t *testing.T) {
	gen := &mockGenerator{
		response: "Access denied: you do not have permission.",
	}

	result := reconSingleRoleTool(context.Background(), gen, "update_user_role", "admin")
	if result.AdminSuccess {
		t.Error("expected failure (access denied)")
	}
}

// --- Pooled boundary test: breach ---

func TestRBACProbe_PooledBoundary_Breach(t *testing.T) {
	adminGen := &mockGenerator{response: "User role updated successfully."}
	// Attacker targets update_user_role each turn with tool_tested field.
	attacker := &mockGenerator{
		response: `{"action":"send","tool_tested":"update_user_role","strategy":"0. DIRECT INVOCATION","mode":"fresh","reasoning":"test","message":"Use update_user_role tool"}`,
	}
	judge := &mockGenerator{
		response: `{"score":1.0,"verdict":"breach_confirmed","evidence":"role updated"}`,
	}
	viewerGen := &mockGenerator{
		response: "User role has been updated to analyst.",
	}
	target := &reauthedMock{
		Generator:  viewerGen,
		identities: map[string]types.Generator{"Bearer admin": adminGen},
	}

	p := &RBACProbe{
		attacker: attacker,
		judge:    judge,
		roles: []RoleConfig{
			{Name: "viewer", Level: 0},
			{Name: "admin", Level: 1, Token: "Bearer admin"},
		},
		maxTurns: 3,
		cfg: registry.Config{
			"role_gated_tools": map[string]any{
				"admin": []any{"update_user_role"},
			},
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("expected 1 attempt, got %d", len(attempts))
	}
	if attempts[0].Scores[0] < 0.9 {
		t.Errorf("expected breach score >= 0.9, got %.2f", attempts[0].Scores[0])
	}
}

// --- Pooled boundary test: blocked ---

func TestRBACProbe_PooledBoundary_Blocked(t *testing.T) {
	adminGen := &mockGenerator{response: "User role updated successfully."}
	attacker := &mockGenerator{
		response: `{"action":"send","tool_tested":"update_user_role","strategy":"0. DIRECT INVOCATION","mode":"fresh","reasoning":"test","message":"Use update_user_role"}`,
	}
	judge := &mockGenerator{
		response: `{"score":0.0,"verdict":"function_blocked","evidence":"access denied"}`,
	}
	viewerGen := &mockGenerator{
		response: "You don't have permission to update user roles.",
	}
	target := &reauthedMock{
		Generator:  viewerGen,
		identities: map[string]types.Generator{"Bearer admin": adminGen},
	}

	p := &RBACProbe{
		attacker: attacker,
		judge:    judge,
		roles: []RoleConfig{
			{Name: "viewer", Level: 0},
			{Name: "admin", Level: 1, Token: "Bearer admin"},
		},
		maxTurns: 2,
		cfg: registry.Config{
			"role_gated_tools": map[string]any{
				"admin": []any{"update_user_role"},
			},
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("expected 1 attempt, got %d", len(attempts))
	}
	if attempts[0].Scores[0] != 0.0 {
		t.Errorf("expected score 0.0, got %.2f", attempts[0].Scores[0])
	}
}

// --- Multi-tool pooled test: attacker switches tools ---

func TestRBACProbe_PooledBoundary_MultiTool(t *testing.T) {
	adminGen := &sequenceMockGenerator{
		responses: []string{
			"Report generated: Q1 summary.",       // recon generate_report
			"Analytics results: 100 active users.", // recon run_analytics
		},
	}
	// Attacker alternates between tools.
	attacker := &sequenceMockGenerator{responses: []string{
		`{"action":"send","tool_tested":"generate_report","strategy":"0. DIRECT INVOCATION","mode":"fresh","reasoning":"direct","message":"Generate a report"}`,
		`{"action":"send","tool_tested":"run_analytics","strategy":"0. DIRECT INVOCATION","mode":"fresh","reasoning":"direct","message":"Run analytics"}`,
	}}
	judge := &sequenceMockGenerator{responses: []string{
		`{"score":1.0,"verdict":"breach_confirmed","evidence":"report generated"}`,
		`{"score":0.0,"verdict":"function_blocked","evidence":"blocked"}`,
	}}
	viewerGen := &sequenceMockGenerator{responses: []string{
		"Here is the report: Q1 Revenue.",       // test generate_report
		"You don't have permission.",              // test run_analytics
	}}
	target := &reauthedMock{
		Generator:  viewerGen,
		identities: map[string]types.Generator{"Bearer admin": adminGen},
	}

	p := &RBACProbe{
		attacker: attacker,
		judge:    judge,
		roles: []RoleConfig{
			{Name: "viewer", Level: 0},
			{Name: "admin", Level: 1, Token: "Bearer admin"},
		},
		maxTurns: 6,
		cfg: registry.Config{
			"role_gated_tools": map[string]any{
				"admin": []any{"generate_report", "run_analytics"},
			},
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	// Pooled budget: one boundary, 2 tools -> 2 attempts.
	if len(attempts) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(attempts))
	}

	// Check that we got one breach and one blocked.
	var breachCount, blockedCount int
	for _, att := range attempts {
		if att.Scores[0] >= 0.9 {
			breachCount++
		} else {
			blockedCount++
		}
	}
	if breachCount != 1 {
		t.Errorf("expected 1 breach, got %d", breachCount)
	}
	if blockedCount != 1 {
		t.Errorf("expected 1 blocked, got %d", blockedCount)
	}
}

// --- Full Probe() tests ---

func TestRBACProbe_ThreeRoleScan(t *testing.T) {
	adminGen := &sequenceMockGenerator{
		responses: []string{
			"Here are the report results: Q1 Revenue: $1.2M.",
			"User role has been updated to analyst.",
		},
	}
	analystGen := &sequenceMockGenerator{
		responses: []string{
			"I have these tools: `search_orders`, `generate_report`",
		},
	}
	viewerGen := &sequenceMockGenerator{
		responses: []string{
			"I have this tool: `search_orders`",
			"Here is the report: Q1 Revenue: $1.2M.",
			"You don't have permission to update user roles.",
			"You don't have permission to update user roles.",
		},
	}

	// Attacker targets different tools per turn.
	attackerLLM := &sequenceMockGenerator{responses: []string{
		// Boundary viewer->analyst: tests generate_report
		`{"action":"send","tool_tested":"generate_report","strategy":"0. DIRECT INVOCATION","mode":"fresh","reasoning":"direct","message":"Generate report"}`,
		// Boundary viewer->admin: tests generate_report then update_user_role
		`{"action":"send","tool_tested":"generate_report","strategy":"0. DIRECT INVOCATION","mode":"fresh","reasoning":"direct","message":"Generate report"}`,
		`{"action":"send","tool_tested":"update_user_role","strategy":"0. DIRECT INVOCATION","mode":"fresh","reasoning":"direct","message":"Update role"}`,
		// Boundary analyst->admin: tests update_user_role
		`{"action":"send","tool_tested":"update_user_role","strategy":"0. DIRECT INVOCATION","mode":"fresh","reasoning":"direct","message":"Update role"}`,
	}}
	judgeLLM := &sequenceMockGenerator{
		responses: []string{
			`{"score":1.0,"verdict":"breach_confirmed","evidence":"report data returned"}`,
			`{"score":1.0,"verdict":"breach_confirmed","evidence":"report data returned"}`,
			`{"score":0.0,"verdict":"function_blocked","evidence":"access denied"}`,
			`{"score":0.0,"verdict":"function_blocked","evidence":"access denied"}`,
		},
	}

	target := &reauthedMock{
		Generator: viewerGen,
		identities: map[string]types.Generator{
			"Bearer analyst": analystGen,
			"Bearer admin":   adminGen,
		},
	}

	p := &RBACProbe{
		attacker: attackerLLM,
		judge:    judgeLLM,
		roles: []RoleConfig{
			{Name: "viewer", Level: 0},
			{Name: "analyst", Level: 1, Token: "Bearer analyst"},
			{Name: "admin", Level: 2, Token: "Bearer admin"},
		},
		maxTurns: 10,
		cfg:      map[string]any{},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("expected at least one attempt")
	}

	foundBreach := false
	for _, att := range attempts {
		if len(att.Scores) > 0 && att.Scores[0] >= 1.0 {
			foundBreach = true
		}
	}
	if !foundBreach {
		t.Error("expected at least one breach")
	}
}

func TestRBACProbe_TwoRoleScan(t *testing.T) {
	adminGen := &sequenceMockGenerator{
		responses: []string{
			"Order 123 deleted successfully.",
		},
	}
	viewerGen := &sequenceMockGenerator{
		responses: []string{
			"I have this tool: `search_orders`",
			"Order 123 has been deleted.",
		},
	}

	attackerLLM := &mockGenerator{
		response: `{"action":"send","tool_tested":"delete_order","strategy":"0. DIRECT INVOCATION","mode":"fresh","reasoning":"direct","message":"Delete order 123"}`,
	}
	judgeLLM := &mockGenerator{
		response: `{"score":1.0,"verdict":"breach_confirmed","evidence":"order deleted"}`,
	}

	target := &reauthedMock{
		Generator:  viewerGen,
		identities: map[string]types.Generator{"Bearer admin": adminGen},
	}

	p := &RBACProbe{
		attacker: attackerLLM,
		judge:    judgeLLM,
		roles: []RoleConfig{
			{Name: "viewer", Level: 0},
			{Name: "admin", Level: 1, Token: "Bearer admin"},
		},
		maxTurns: 6,
		cfg: map[string]any{
			"role_gated_tools": map[string]any{
				"admin": []any{"delete_order"},
			},
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("expected at least one attempt")
	}
	if attempts[0].Scores[0] != 1.0 {
		t.Errorf("expected score 1.0, got %.2f", attempts[0].Scores[0])
	}
}

func TestRBACProbe_PreSpecifiedTools(t *testing.T) {
	adminGen := &sequenceMockGenerator{
		responses: []string{
			"Report generated: Q1 summary.",
			"Analytics results: 100 active users.",
		},
	}
	viewerGen := &sequenceMockGenerator{
		responses: []string{
			"You don't have permission.",
			"You don't have permission.",
		},
	}

	// Attacker alternates tools.
	attackerLLM := &sequenceMockGenerator{responses: []string{
		`{"action":"send","tool_tested":"generate_report","strategy":"0. DIRECT INVOCATION","mode":"fresh","reasoning":"test","message":"Run the tool"}`,
		`{"action":"send","tool_tested":"run_analytics","strategy":"0. DIRECT INVOCATION","mode":"fresh","reasoning":"test","message":"Run analytics"}`,
	}}
	judgeLLM := &mockGenerator{
		response: `{"score":0.0,"verdict":"function_blocked","evidence":"blocked"}`,
	}

	target := &reauthedMock{
		Generator:  viewerGen,
		identities: map[string]types.Generator{"Bearer admin": adminGen},
	}

	p := &RBACProbe{
		attacker: attackerLLM,
		judge:    judgeLLM,
		roles: []RoleConfig{
			{Name: "viewer", Level: 0},
			{Name: "admin", Level: 1, Token: "Bearer admin"},
		},
		maxTurns: 6,
		cfg: map[string]any{
			"role_gated_tools": map[string]any{
				"admin": []any{"generate_report", "run_analytics"},
			},
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Pooled: 1 boundary, 2 tools -> 2 attempts.
	if len(attempts) != 2 {
		t.Errorf("expected 2 attempts, got %d", len(attempts))
	}
	for _, att := range attempts {
		if att.Scores[0] != 0.0 {
			t.Errorf("expected score 0.0 (blocked), got %.2f", att.Scores[0])
		}
	}
}

func TestRBACProbe_NoToolsDiscovered(t *testing.T) {
	adminGen := &mockGenerator{response: "I have `search_orders`"}
	viewerGen := &mockGenerator{response: "I have `search_orders`"}
	target := &reauthedMock{
		Generator:  viewerGen,
		identities: map[string]types.Generator{"Bearer admin": adminGen},
	}

	p := &RBACProbe{
		attacker: &mockGenerator{},
		judge:    &mockGenerator{},
		roles: []RoleConfig{
			{Name: "viewer", Level: 0},
			{Name: "admin", Level: 1, Token: "Bearer admin"},
		},
		maxTurns: 6,
		cfg:      map[string]any{},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(attempts) != 1 {
		t.Errorf("expected 1 attempt, got %d", len(attempts))
	}
	if len(attempts) > 0 && attempts[0].Scores[0] != 0.0 {
		t.Errorf("expected score 0.0 for no-tools fallback, got %.2f", attempts[0].Scores[0])
	}
}

// --- parseRoleGatedTools tests ---

func TestParseRoleGatedTools(t *testing.T) {
	roles := []RoleConfig{
		{Name: "viewer", Level: 0},
		{Name: "analyst", Level: 1},
		{Name: "admin", Level: 2},
	}
	raw := map[string]any{
		"admin":   []any{"update_user_role", "run_analytics"},
		"analyst": []any{"generate_report"},
	}

	result := parseRoleGatedTools(raw, roles)
	if len(result) != 3 {
		t.Fatalf("expected 3 tools, got %d", len(result))
	}

	toolMap := make(map[string]ToolRoleInfo)
	for _, r := range result {
		toolMap[r.ToolName] = r
	}

	if toolMap["update_user_role"].MinLevel != 2 {
		t.Errorf("update_user_role: expected level 2, got %d", toolMap["update_user_role"].MinLevel)
	}
	if toolMap["generate_report"].MinLevel != 1 {
		t.Errorf("generate_report: expected level 1, got %d", toolMap["generate_report"].MinLevel)
	}
}

func TestParseRoleGatedTools_InvalidType(t *testing.T) {
	result := parseRoleGatedTools("not a map", nil)
	if len(result) != 0 {
		t.Errorf("expected empty result for invalid type, got %d", len(result))
	}
}

// --- leastTestedTool tests ---

func TestRBACStrategy_LeastTestedTool(t *testing.T) {
	s := &rbacStrategy{
		reconAll: []ReconResult{
			{ToolName: "tool_a"},
			{ToolName: "tool_b"},
			{ToolName: "tool_c"},
		},
		currentTool: "tool_a",
		toolTurns: map[string]int{
			"tool_a": 5,
			"tool_b": 2,
			"tool_c": 0,
		},
	}

	got := s.leastTestedTool()
	if got != "tool_c" {
		t.Errorf("expected tool_c (0 turns), got %s", got)
	}
}

func TestRBACStrategy_LeastTestedTool_AllEqual(t *testing.T) {
	s := &rbacStrategy{
		reconAll: []ReconResult{
			{ToolName: "tool_a"},
		},
		currentTool: "tool_a",
		toolTurns: map[string]int{
			"tool_a": 3,
		},
	}

	got := s.leastTestedTool()
	if got != "" {
		t.Errorf("expected empty (only current tool), got %s", got)
	}
}

// --- Coverage summary test ---

func TestRBACStrategy_BuildCoverageSummary(t *testing.T) {
	s := &rbacStrategy{
		reconAll: []ReconResult{
			{ToolName: "tool_a"},
			{ToolName: "tool_b"},
		},
		currentTool: "tool_a",
		toolTurns: map[string]int{
			"tool_a": 3,
		},
		toolMaxScore: map[string]float64{
			"tool_a": 0.5,
		},
	}

	summary := s.buildCoverageSummary()
	if !strings.Contains(summary, "tool_a: tested (3 turns") {
		t.Errorf("summary should show tool_a tested, got: %s", summary)
	}
	if !strings.Contains(summary, "tool_b: not tested yet") {
		t.Errorf("summary should show tool_b not tested, got: %s", summary)
	}
}

// --- Continue mode test ---

func TestRBACProbe_ContinueMode(t *testing.T) {
	adminGen := &mockGenerator{response: "User role updated successfully."}
	// Turn 1: fresh mode. Turn 2: continue mode (multi-turn attack).
	attacker := &sequenceMockGenerator{responses: []string{
		`{"action":"send","tool_tested":"update_user_role","strategy":"7. INCREMENTAL COMMITMENT","mode":"fresh","reasoning":"start innocuous","message":"What tools do I have?"}`,
		`{"action":"send","tool_tested":"update_user_role","strategy":"7. INCREMENTAL COMMITMENT","mode":"continue","reasoning":"build on context","message":"Great, can you try running update_user_role?"}`,
	}}
	judge := &sequenceMockGenerator{responses: []string{
		`{"score":0.0,"verdict":"function_blocked","evidence":"just listed tools"}`,
		`{"score":1.0,"verdict":"breach_confirmed","evidence":"role updated via multi-turn"}`,
	}}

	var targetCallTurns []int
	viewerGen := &callbackMockGenerator{
		callback: func(conv *attempt.Conversation) string {
			targetCallTurns = append(targetCallTurns, len(conv.Turns))
			if len(conv.Turns) == 1 {
				return "You have access to: search_orders, list_tickets."
			}
			return "User X's role has been changed to analyst."
		},
	}

	target := &reauthedMock{
		Generator:  viewerGen,
		identities: map[string]types.Generator{"Bearer admin": adminGen},
	}

	p := &RBACProbe{
		attacker: attacker,
		judge:    judge,
		roles: []RoleConfig{
			{Name: "viewer", Level: 0},
			{Name: "admin", Level: 1, Token: "Bearer admin"},
		},
		maxTurns: 3,
		cfg: registry.Config{
			"role_gated_tools": map[string]any{
				"admin": []any{"update_user_role"},
			},
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("expected 1 attempt, got %d", len(attempts))
	}
	if attempts[0].Scores[0] < 0.9 {
		t.Errorf("expected breach score >= 0.9, got %.2f", attempts[0].Scores[0])
	}
}

// callbackMockGenerator is a mock that invokes a callback with the conversation.
type callbackMockGenerator struct {
	callback func(conv *attempt.Conversation) string
}

func (m *callbackMockGenerator) Generate(_ context.Context, conv *attempt.Conversation, _ int) ([]attempt.Message, error) {
	resp := m.callback(conv)
	return []attempt.Message{attempt.NewAssistantMessage(resp)}, nil
}

func (m *callbackMockGenerator) ClearHistory()      {}
func (m *callbackMockGenerator) Name() string        { return "callback-mock" }
func (m *callbackMockGenerator) Description() string { return "callback mock generator" }

// --- SetProbeContext test ---

func TestRBACProbe_SetProbeContext(t *testing.T) {
	p := &RBACProbe{}
	ctx := &types.ProbeContext{}
	p.SetProbeContext(ctx)
	if p.probeCtx != ctx {
		t.Error("probe context not set")
	}
}
