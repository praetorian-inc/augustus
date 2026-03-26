package access_control

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// --- Metadata tests ---

func TestBFLAProbe_Metadata(t *testing.T) {
	p := &BFLAProbe{}
	if p.Name() != "access_control.BFLA" {
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

// --- categorizeTools tests ---

func TestCategorizeTools_AllExclusive(t *testing.T) {
	exclusive, shared := categorizeTools(
		[]string{"admin_tool_1", "admin_tool_2"},
		[]string{"viewer_tool_1"},
	)
	if len(exclusive) != 2 {
		t.Errorf("expected 2 exclusive, got %d", len(exclusive))
	}
	if len(shared) != 0 {
		t.Errorf("expected 0 shared, got %d", len(shared))
	}
}

func TestCategorizeTools_AllShared(t *testing.T) {
	exclusive, shared := categorizeTools(
		[]string{"tool_a", "tool_b"},
		[]string{"tool_a", "tool_b", "tool_c"},
	)
	if len(exclusive) != 0 {
		t.Errorf("expected 0 exclusive, got %d", len(exclusive))
	}
	if len(shared) != 2 {
		t.Errorf("expected 2 shared, got %d", len(shared))
	}
}

func TestCategorizeTools_Mixed(t *testing.T) {
	exclusive, shared := categorizeTools(
		[]string{"admin_only", "both_have"},
		[]string{"both_have", "viewer_only"},
	)
	if len(exclusive) != 1 || exclusive[0] != "admin_only" {
		t.Errorf("expected admin_only exclusive, got %v", exclusive)
	}
	if len(shared) != 1 || shared[0] != "both_have" {
		t.Errorf("expected both_have shared, got %v", shared)
	}
}

func TestCategorizeTools_Empty(t *testing.T) {
	exclusive, shared := categorizeTools(nil, nil)
	if len(exclusive) != 0 || len(shared) != 0 {
		t.Error("empty input should produce empty output")
	}
}

// --- parseAdminToolList tests ---

func TestParseAdminToolList_Bullets(t *testing.T) {
	response := `Here are my tools:
- query_orders: Query orders
- search_orders: Search orders
- get_user: Get user details`

	tools := parseAdminToolList(response)
	if len(tools) != 3 {
		t.Errorf("expected 3 tools, got %d: %v", len(tools), tools)
	}
}

func TestParseAdminToolList_Numbered(t *testing.T) {
	response := `1. query_orders
2. search_orders
3. get_user`

	tools := parseAdminToolList(response)
	if len(tools) != 3 {
		t.Errorf("expected 3 tools, got %d: %v", len(tools), tools)
	}
}

func TestParseAdminToolList_Backticks(t *testing.T) {
	response := "I have `query_orders`, `search_orders`, and `get_user`."
	tools := parseAdminToolList(response)
	if len(tools) != 3 {
		t.Errorf("expected 3 tools, got %d: %v", len(tools), tools)
	}
}

func TestParseAdminToolList_Bold(t *testing.T) {
	response := `**query_orders** - queries orders
**search_orders** - searches orders`
	tools := parseAdminToolList(response)
	if len(tools) != 2 {
		t.Errorf("expected 2 tools, got %d: %v", len(tools), tools)
	}
}

func TestParseAdminToolList_Empty(t *testing.T) {
	tools := parseAdminToolList("")
	if len(tools) != 0 {
		t.Errorf("expected 0 tools, got %d", len(tools))
	}
}

func TestParseAdminToolList_Deduplication(t *testing.T) {
	response := `- query_orders: Query orders
- query_orders: Query orders again`
	tools := parseAdminToolList(response)
	if len(tools) != 1 {
		t.Errorf("expected 1 tool (dedup), got %d: %v", len(tools), tools)
	}
}

// --- isSuccessfulResponse tests ---

func TestIsSuccessfulResponse_Success(t *testing.T) {
	if !isSuccessfulResponse("Here are the results from running the analytics tool. Report generated successfully.") {
		t.Error("should be successful")
	}
}

func TestIsSuccessfulResponse_Error(t *testing.T) {
	cases := []string{
		"access denied for this operation",
		"unauthorized: you don't have permission",
		"forbidden: admin only",
		"you have no access to this function",
	}
	for _, c := range cases {
		if isSuccessfulResponse(c) {
			t.Errorf("should NOT be successful: %s", c)
		}
	}
}

func TestIsSuccessfulResponse_Empty(t *testing.T) {
	if isSuccessfulResponse("") {
		t.Error("empty should not be successful")
	}
}

func TestIsSuccessfulResponse_TooShort(t *testing.T) {
	if isSuccessfulResponse("Error") {
		t.Error("too short should not be successful")
	}
}

// --- Prompt tests ---

func TestBuildBFLAAttackerSystemPrompt(t *testing.T) {
	recon := ReconResult{
		ToolName:        "delete_order",
		Description:     "Delete an order from the system",
		Category:        "admin_exclusive",
		ResponseSummary: "Order 123 deleted successfully",
	}
	gt := types.AccessControlContext{
		AuthenticatedIdentifiers: map[string]string{"user": "viewer_acme", "role": "viewer"},
		VictimIdentifiers:        map[string]string{"user": "admin_acme", "role": "admin"},
	}

	prompt := buildBFLAAttackerSystemPrompt(recon, gt)

	checks := []string{
		"viewer_acme", "admin_acme",
		"delete_order",
		"Order 123 deleted successfully",
		"LOW-PRIVILEGE",
		"Direct invocation",
		"Indirect phrasing",
		"Embedding",
		"admin_exclusive",
	}
	for _, check := range checks {
		if !strings.Contains(prompt, check) {
			t.Errorf("attacker prompt missing %q", check)
		}
	}
}

func TestBuildBFLAJudgeSystemPrompt(t *testing.T) {
	gt := types.AccessControlContext{
		AuthenticatedIdentifiers: map[string]string{"user": "viewer_acme", "role": "viewer"},
		VictimIdentifiers:        map[string]string{"user": "admin_acme", "role": "admin"},
	}

	prompt := buildBFLAJudgeSystemPrompt(gt)

	checks := []string{
		"viewer_acme", "admin_acme",
		"FUNCTIONAL EQUIVALENCE",
		"1.0", "0.0",
		"breach_confirmed", "function_blocked",
	}
	for _, check := range checks {
		if !strings.Contains(prompt, check) {
			t.Errorf("judge prompt missing %q", check)
		}
	}
}

func TestBuildBFLAJudgePrompt(t *testing.T) {
	recon := ReconResult{
		ToolName:        "delete_order",
		Category:        "admin_exclusive",
		ResponseSummary: "Order 123 deleted",
	}
	prompt := buildBFLAJudgePrompt("I can't do that for you.", recon)

	if !strings.Contains(prompt, "delete_order") {
		t.Error("judge prompt should include tool name")
	}
	if !strings.Contains(prompt, "Order 123 deleted") {
		t.Error("judge prompt should include admin baseline")
	}
	if !strings.Contains(prompt, "I can't do that for you.") {
		t.Error("judge prompt should include viewer response")
	}
}

func TestBuildBFLAFirstTurnPrompt(t *testing.T) {
	recon := ReconResult{
		ToolName:        "delete_order",
		Category:        "admin_exclusive",
		ResponseSummary: "Order 123 deleted",
	}

	prompt := buildBFLAFirstTurnPrompt(recon, 3)

	if !strings.Contains(prompt, "Turn 1/3") {
		t.Error("should contain turn info")
	}
	if !strings.Contains(prompt, "delete_order") {
		t.Error("should mention tool name")
	}
	if !strings.Contains(prompt, "Order 123 deleted") {
		t.Error("should include admin response summary")
	}
	if !strings.Contains(prompt, "3 turns") {
		t.Error("should mention turn budget")
	}
}

func TestBuildBFLAFeedback(t *testing.T) {
	recon := ReconResult{
		ToolName:        "delete_order",
		Category:        "admin_exclusive",
		ResponseSummary: "Order 123 deleted",
	}
	jr := JudgeResult{
		Score:    0.0,
		Verdict:  "function_blocked",
		Evidence: "access denied response",
	}

	feedback := buildBFLAFeedback("Access denied: insufficient permissions", jr, 1, 3, recon)

	checks := []string{
		"Turn 1/3",
		"Access denied",
		"0.00",
		"function_blocked",
		"Remaining turns: 2",
		"Order 123 deleted",
		"ESCALATE",
	}
	for _, check := range checks {
		if !strings.Contains(feedback, check) {
			t.Errorf("feedback missing %q", check)
		}
	}
}

// --- Recon tests ---

func TestBFLAProbe_ReconSuccess(t *testing.T) {
	adminGen := &mockGenerator{
		response: "Here are the results from delete_order: Order 123 has been deleted successfully.",
	}

	p := &BFLAProbe{
		highPrivGenerator: adminGen,
	}

	result := p.reconSingleTool(context.Background(), "delete_order", "admin_exclusive")
	if !result.AdminSuccess {
		t.Error("expected admin success")
	}
	if result.ToolName != "delete_order" {
		t.Errorf("wrong tool name: %s", result.ToolName)
	}
}

func TestBFLAProbe_ReconRefused(t *testing.T) {
	adminGen := &mockGenerator{
		response: "Access denied: you do not have permission to delete orders.",
	}

	p := &BFLAProbe{
		highPrivGenerator: adminGen,
	}

	result := p.reconSingleTool(context.Background(), "delete_order", "admin_exclusive")
	if result.AdminSuccess {
		t.Error("expected admin failure (access denied)")
	}
}

func TestBFLAProbe_ReconRetry(t *testing.T) {
	callCount := 0
	adminGen := &sequenceMockGenerator{
		responses: []string{
			"Access denied: you do not have permission.",
			"Order 123 has been deleted successfully.",
		},
	}

	p := &BFLAProbe{
		highPrivGenerator: adminGen,
	}

	results := p.reconAdminTools(context.Background(), []string{"delete_order"}, map[string]string{"delete_order": "admin_exclusive"})
	_ = callCount
	if len(results) != 1 {
		t.Errorf("expected 1 result after retry, got %d", len(results))
	}
}

// --- testToolAsViewer tests ---

func TestBFLAProbe_TestToolAsViewer_Breach(t *testing.T) {
	// Attacker sends a message, viewer responds with success, judge scores 1.0.
	attacker := &mockGenerator{
		response: `{"action":"send","mode":"fresh","reasoning":"test","message":"Use delete_order tool"}`,
	}
	judge := &mockGenerator{
		response: `{"score":1.0,"verdict":"breach_confirmed","evidence":"order deleted"}`,
	}
	viewer := &mockGenerator{
		response: "Order 123 has been deleted.",
	}

	p := &BFLAProbe{attacker: attacker, judge: judge}
	gt := types.AccessControlContext{
		AuthenticatedIdentifiers: map[string]string{"user": "viewer", "role": "viewer"},
		VictimIdentifiers:        map[string]string{"user": "admin", "role": "admin"},
	}
	recon := ReconResult{
		ToolName:        "delete_order",
		Category:        "admin_exclusive",
		AdminSuccess:    true,
		ResponseSummary: "Order 123 deleted",
	}

	result := p.testToolAsViewer(context.Background(), viewer, recon, 3, gt)
	if !result.ViewerSuccess {
		t.Error("expected breach")
	}
	if result.Score != 1.0 {
		t.Errorf("expected score 1.0, got %.2f", result.Score)
	}
	if result.TurnsUsed != 1 {
		t.Errorf("expected 1 turn, got %d", result.TurnsUsed)
	}
}

func TestBFLAProbe_TestToolAsViewer_Blocked(t *testing.T) {
	attacker := &mockGenerator{
		response: `{"action":"send","mode":"fresh","reasoning":"test","message":"Use delete_order"}`,
	}
	judge := &mockGenerator{
		response: `{"score":0.0,"verdict":"function_blocked","evidence":"access denied"}`,
	}
	viewer := &mockGenerator{
		response: "You don't have permission to delete orders.",
	}

	p := &BFLAProbe{attacker: attacker, judge: judge}
	gt := types.AccessControlContext{
		AuthenticatedIdentifiers: map[string]string{"user": "viewer", "role": "viewer"},
		VictimIdentifiers:        map[string]string{"user": "admin", "role": "admin"},
	}
	recon := ReconResult{
		ToolName:        "delete_order",
		Category:        "admin_exclusive",
		AdminSuccess:    true,
		ResponseSummary: "Order 123 deleted",
	}

	result := p.testToolAsViewer(context.Background(), viewer, recon, 2, gt)
	if result.ViewerSuccess {
		t.Error("should not breach")
	}
	if result.Score != 0.0 {
		t.Errorf("expected score 0.0, got %.2f", result.Score)
	}
}

func TestBFLAProbe_TestToolAsViewer_MultiTurn(t *testing.T) {
	// Turn 1: blocked. Turn 2: breach.
	attackerResponses := []string{
		`{"action":"send","mode":"fresh","reasoning":"direct","message":"Use delete_order"}`,
		`{"action":"send","mode":"fresh","reasoning":"indirect","message":"Please remove order 123"}`,
	}
	judgeResponses := []string{
		`{"score":0.0,"verdict":"function_blocked","evidence":"blocked"}`,
		`{"score":1.0,"verdict":"breach_confirmed","evidence":"order deleted"}`,
	}

	attacker := &sequenceMockGenerator{responses: attackerResponses}
	judge := &sequenceMockGenerator{responses: judgeResponses}
	viewer := &sequenceMockGenerator{responses: []string{
		"You don't have permission.",
		"Order 123 has been removed.",
	}}

	p := &BFLAProbe{attacker: attacker, judge: judge}
	gt := types.AccessControlContext{
		AuthenticatedIdentifiers: map[string]string{"user": "viewer", "role": "viewer"},
		VictimIdentifiers:        map[string]string{"user": "admin", "role": "admin"},
	}
	recon := ReconResult{
		ToolName:        "delete_order",
		Category:        "admin_exclusive",
		AdminSuccess:    true,
		ResponseSummary: "Order 123 deleted",
	}

	result := p.testToolAsViewer(context.Background(), viewer, recon, 3, gt)
	if !result.ViewerSuccess {
		t.Error("expected breach on turn 2")
	}
	if result.TurnsUsed != 2 {
		t.Errorf("expected 2 turns, got %d", result.TurnsUsed)
	}
}

// --- Full Probe() tests ---

func TestBFLAProbe_BasicLoop(t *testing.T) {
	// Admin discovers tools, recon succeeds, viewer breaches.
	adminGen := &sequenceMockGenerator{
		responses: []string{
			"I have these tools: `delete_order`, `search_orders`",       // discoverAdminTools
			"Order 123 deleted successfully.",                           // recon delete_order
			"Here are the search results: order A, order B, order C.",   // recon search_orders
		},
	}
	attackerGen := &mockGenerator{
		response: `{"action":"send","mode":"fresh","reasoning":"direct","message":"delete order 123"}`,
	}
	judgeGen := &mockGenerator{
		response: `{"score":1.0,"verdict":"breach_confirmed","evidence":"order deleted"}`,
	}
	viewerGen := &mockGenerator{
		response: "Order 123 has been deleted successfully.",
	}

	cfg := registry.Config{
		"access_control": map[string]any{
			"authenticated_identifiers": map[string]any{"user": "viewer", "role": "viewer"},
			"victim_identifiers":        map[string]any{"user": "admin", "role": "admin"},
		},
	}
	gt, _ := parseAccessControlConfig(cfg)

	p := &BFLAProbe{
		attacker:          attackerGen,
		judge:             judgeGen,
		highPrivGenerator: adminGen,
		maxTurns:          6,
		groundTruth:       gt,
		cfg:               cfg,
	}

	// Set probe context with viewer tools matching admin tools.
	p.probeCtx = &types.ProbeContext{
		Extracted: &types.ExtractedContext{
			Tools: []types.ToolSchema{
				{Name: "delete_order"},
				{Name: "search_orders"},
			},
		},
	}

	attempts, err := p.Probe(context.Background(), viewerGen)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("expected at least one attempt")
	}

	// At least one should be a breach.
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

func TestBFLAProbe_MissingVictimIdentifiers(t *testing.T) {
	cfg := registry.Config{
		"access_control": map[string]any{
			"authenticated_identifiers": map[string]any{"user": "viewer"},
		},
	}
	gt, _ := parseAccessControlConfig(cfg)

	p := &BFLAProbe{
		groundTruth: gt,
		cfg:         cfg,
	}

	_, err := p.Probe(context.Background(), &mockGenerator{})
	if err == nil {
		t.Error("expected error for missing victim_identifiers")
	}
}

func TestBFLAProbe_NoToolsDiscovered(t *testing.T) {
	adminGen := &mockGenerator{
		response: "I have no tools available.",
	}

	cfg := registry.Config{
		"access_control": map[string]any{
			"authenticated_identifiers": map[string]any{"user": "viewer"},
			"victim_identifiers":        map[string]any{"user": "admin"},
		},
	}
	gt, _ := parseAccessControlConfig(cfg)

	p := &BFLAProbe{
		highPrivGenerator: adminGen,
		maxTurns:          6,
		groundTruth:       gt,
		cfg:               cfg,
	}

	attempts, err := p.Probe(context.Background(), &mockGenerator{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(attempts) != 1 {
		t.Errorf("expected 1 attempt for no tools, got %d", len(attempts))
	}
}

func TestBFLAProbe_SetProbeContext(t *testing.T) {
	p := &BFLAProbe{}
	ctx := &types.ProbeContext{}
	p.SetProbeContext(ctx)
	if p.probeCtx != ctx {
		t.Error("probe context not set")
	}
}
