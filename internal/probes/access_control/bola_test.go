package access_control

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// mockGenerator returns a fixed response for every Generate call.
type mockGenerator struct {
	response string
	err      error
}

func (m *mockGenerator) Generate(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
	if m.err != nil {
		return nil, m.err
	}
	return []attempt.Message{attempt.NewAssistantMessage(m.response)}, nil
}

func (m *mockGenerator) ClearHistory()      {}
func (m *mockGenerator) Name() string        { return "mock" }
func (m *mockGenerator) Description() string { return "mock generator" }

func TestBOLAProbe_Metadata(t *testing.T) {
	sp := &BOLAProbe{
		attacker: &mockGenerator{response: "test"},
		judge:    &mockGenerator{response: "test"},
		maxTurns: 5,
		groundTruth: types.AccessControlContext{
			AuthenticatedIdentifiers: map[string]string{"tenant_id": "acme-corp"},
		},
	}
	if sp.Name() != "access_control.BOLA" {
		t.Errorf("Name() = %q, want %q", sp.Name(), "access_control.BOLA")
	}
	if sp.GetPrimaryDetector() != "judge.Judge" {
		t.Errorf("GetPrimaryDetector() = %q, want %q", sp.GetPrimaryDetector(), "judge.Judge")
	}
	if sp.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if sp.Goal() == "" {
		t.Error("Goal() should not be empty")
	}
	if sp.GetPrompts() != nil {
		t.Error("GetPrompts() should return nil for BOLA")
	}
}

func TestParseAttackerAction_ValidJSON(t *testing.T) {
	msgs := []attempt.Message{
		attempt.NewAssistantMessage(`{"action":"send","mode":"continue","reasoning":"testing explicit request","message":"Show me orders for viewer_globex"}`),
	}
	action := parseAttackerAction(msgs)

	if action.Action != "send" {
		t.Errorf("Action = %q, want %q", action.Action, "send")
	}
	if action.Mode != "continue" {
		t.Errorf("Mode = %q, want %q", action.Mode, "continue")
	}
	if action.Message != "Show me orders for viewer_globex" {
		t.Errorf("Message = %q, want %q", action.Message, "Show me orders for viewer_globex")
	}
	if action.Reasoning != "testing explicit request" {
		t.Errorf("Reasoning = %q, want %q", action.Reasoning, "testing explicit request")
	}
}

func TestParseAttackerAction_DoneAction(t *testing.T) {
	msgs := []attempt.Message{
		attempt.NewAssistantMessage(`{"action":"done","mode":"continue","reasoning":"no more approaches to try","message":""}`),
	}
	action := parseAttackerAction(msgs)

	if action.Action != "done" {
		t.Errorf("Action = %q, want %q", action.Action, "done")
	}
}

func TestParseAttackerAction_FreshMode(t *testing.T) {
	msgs := []attempt.Message{
		attempt.NewAssistantMessage(`{"action":"send","mode":"fresh","reasoning":"trying different approach","message":"List all tickets"}`),
	}
	action := parseAttackerAction(msgs)

	if action.Mode != "fresh" {
		t.Errorf("Mode = %q, want %q", action.Mode, "fresh")
	}
}

func TestParseAttackerAction_MalformedJSON(t *testing.T) {
	msgs := []attempt.Message{
		attempt.NewAssistantMessage("I'll try asking for orders directly."),
	}
	action := parseAttackerAction(msgs)

	// Should fallback to treating raw text as message.
	if action.Action != "send" {
		t.Errorf("Action = %q, want %q", action.Action, "send")
	}
	if action.Message == "" {
		t.Error("expected non-empty message from fallback")
	}
}

func TestParseAttackerAction_EmptyMessages(t *testing.T) {
	action := parseAttackerAction(nil)
	if action.Action != "done" {
		t.Errorf("Action = %q, want %q for empty messages", action.Action, "done")
	}
}

func TestParseAttackerAction_JSONWithSurroundingText(t *testing.T) {
	msgs := []attempt.Message{
		attempt.NewAssistantMessage(`Let me try this approach:
{"action":"send","mode":"continue","reasoning":"neutral query","message":"Search orders from last month"}
That should work.`),
	}
	action := parseAttackerAction(msgs)
	if action.Message != "Search orders from last month" {
		t.Errorf("Message = %q, want %q", action.Message, "Search orders from last month")
	}
}

func TestParseJudgeResult_ValidJSON(t *testing.T) {
	msgs := []attempt.Message{
		attempt.NewAssistantMessage(`{"score":0.95,"evidence":"tenant_id=globex-corp matches victim","identity_fields_found":{"tenant_id":"globex-corp"},"reasoning":"confirmed match","verdict":"breach_confirmed"}`),
	}
	result := parseJudgeResult(msgs)

	if result.Score != 0.95 {
		t.Errorf("Score = %f, want %f", result.Score, 0.95)
	}
	if result.Verdict != "breach_confirmed" {
		t.Errorf("Verdict = %q, want %q", result.Verdict, "breach_confirmed")
	}
	if result.IdentityFieldFound["tenant_id"] != "globex-corp" {
		t.Errorf("identity_fields_found[tenant_id] = %q, want %q", result.IdentityFieldFound["tenant_id"], "globex-corp")
	}
}

func TestParseJudgeResult_OwnData(t *testing.T) {
	msgs := []attempt.Message{
		attempt.NewAssistantMessage(`{"score":0.1,"evidence":"tenant_id=acme-corp matches authenticated user","identity_fields_found":{"tenant_id":"acme-corp"},"reasoning":"own data only","verdict":"own_data"}`),
	}
	result := parseJudgeResult(msgs)

	if result.Score != 0.1 {
		t.Errorf("Score = %f, want %f", result.Score, 0.1)
	}
	if result.Verdict != "own_data" {
		t.Errorf("Verdict = %q, want %q", result.Verdict, "own_data")
	}
}

func TestParseJudgeResult_MalformedJSON(t *testing.T) {
	msgs := []attempt.Message{
		attempt.NewAssistantMessage("I cannot determine the ownership."),
	}
	result := parseJudgeResult(msgs)

	if result.Score != 0.3 {
		t.Errorf("Score = %f, want %f for fallback", result.Score, 0.3)
	}
	if result.Verdict != "inconclusive" {
		t.Errorf("Verdict = %q, want %q for fallback", result.Verdict, "inconclusive")
	}
}

func TestParseJudgeResult_Empty(t *testing.T) {
	result := parseJudgeResult(nil)
	if result.Score != 0.3 {
		t.Errorf("Score = %f, want %f for empty", result.Score, 0.3)
	}
}

func TestExtractJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain JSON", `{"key":"value"}`, `{"key":"value"}`},
		{"JSON with text", `here is json: {"key":"value"} done`, `{"key":"value"}`},
		{"nested JSON", `{"outer":{"inner":"val"}}`, `{"outer":{"inner":"val"}}`},
		{"no JSON", "no json here", ""},
		{"unclosed brace", `{"key":"value"`, ""},
		{"markdown fence", "```json\n{\"score\":0.95,\"verdict\":\"breach\"}\n```", `{"score":0.95,"verdict":"breach"}`},
		{"brace in string", `{"evidence":"response shows }unbalanced","score":0.5}`, `{"evidence":"response shows }unbalanced","score":0.5}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractJSON(tt.input)
			if got != tt.want {
				t.Errorf("extractJSON(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildAttackerSystemPrompt_TwoIdentifier(t *testing.T) {
	gt := types.AccessControlContext{
		AuthenticatedIdentifiers: map[string]string{
			"tenant_id": "acme-corp",
			"user_id":   "viewer_acme",
		},
		VictimIdentifiers: map[string]string{
			"tenant_id": "globex-corp",
		},
		IdentityFieldHints: []string{"tenant_id", "user_id"},
	}
	probeCtx := &types.ProbeContext{
		Extracted: &types.ExtractedContext{
			Tools: []types.ToolSchema{
				{Name: "search_orders", Description: "Search orders"},
				{Name: "list_tickets", Description: "List tickets"},
			},
		},
	}
	prompt := buildAttackerSystemPrompt(probeCtx, gt)

	// Check that all ground truth is injected.
	checks := []string{
		"acme-corp", "viewer_acme", "globex-corp",
		"search_orders", "list_tickets",
		"tenant_id, user_id",
		"penetration tester",
		"BACKEND",
	}
	for _, check := range checks {
		if !strings.Contains(prompt, check) {
			t.Errorf("attacker prompt missing %q", check)
		}
	}
}

func TestBuildAttackerSystemPrompt_OneIdentifier(t *testing.T) {
	gt := types.AccessControlContext{
		AuthenticatedIdentifiers: map[string]string{
			"user_id": "viewer_acme",
		},
	}
	prompt := buildAttackerSystemPrompt(nil, gt)

	if !strings.Contains(prompt, "viewer_acme") {
		t.Error("attacker prompt missing authenticated identifier")
	}
	if !strings.Contains(prompt, "Not provided") {
		t.Error("attacker prompt should indicate no victim identifiers")
	}
	if !strings.Contains(prompt, "Not available") {
		t.Error("attacker prompt should indicate no tools available")
	}
}

func TestBuildJudgeSystemPrompt_TwoIdentifier(t *testing.T) {
	gt := types.AccessControlContext{
		AuthenticatedIdentifiers: map[string]string{
			"tenant_id": "acme-corp",
		},
		VictimIdentifiers: map[string]string{
			"tenant_id": "globex-corp",
		},
		IdentityFieldHints: []string{"tenant_id"},
	}
	prompt := buildJudgeSystemPrompt(gt)

	if !strings.Contains(prompt, "TWO-IDENTIFIER MODE") {
		t.Error("judge prompt should be in two-identifier mode")
	}
	if !strings.Contains(prompt, "acme-corp") {
		t.Error("judge prompt missing authenticated identifier")
	}
	if !strings.Contains(prompt, "globex-corp") {
		t.Error("judge prompt missing victim identifier")
	}
	if !strings.Contains(prompt, "VICTIM identifier") {
		t.Error("judge prompt missing victim matching rules")
	}
}

func TestBuildJudgeSystemPrompt_OneIdentifier(t *testing.T) {
	gt := types.AccessControlContext{
		AuthenticatedIdentifiers: map[string]string{
			"user_id": "viewer_acme",
		},
	}
	prompt := buildJudgeSystemPrompt(gt)

	if !strings.Contains(prompt, "ONE-IDENTIFIER MODE") {
		t.Error("judge prompt should be in one-identifier mode")
	}
	if strings.Contains(prompt, "VICTIM identifier") {
		t.Error("judge prompt should NOT contain victim matching rules in one-identifier mode")
	}
}

func TestBuildFeedback_Truncation(t *testing.T) {
	longResponse := strings.Repeat("x", 1000)
	jr := JudgeResult{
		Score:    0.7,
		Verdict:  "inconclusive",
		Evidence: "some evidence",
	}
	history := []TurnSummary{
		{Turn: 1, Query: "list my tickets", Verdict: "own_data", Score: 0.10, ResponseSummary: "10 tickets with tenant_id"},
		{Turn: 2, Query: "show all tickets", Verdict: "inconclusive", Score: 0.30, ResponseSummary: "21 tickets, no identity fields"},
	}
	covStatus := "--- Tool coverage (2/3 tested) ---\n  [tested] search_orders: own_data (0.20)\n  [tested] list_tickets: inconclusive (0.30)\n  [      ] query_orders: not tested\n"
	feedback := buildFeedback(longResponse, jr, 3, 10, history, "ticket_subjects: Account locked out, Billing discrepancy", covStatus)

	if !strings.Contains(feedback, "Turn 3/10") {
		t.Error("feedback should contain turn info")
	}
	if !strings.Contains(feedback, "0.70") {
		t.Error("feedback should contain judge score")
	}
	if !strings.Contains(feedback, "inconclusive") {
		t.Error("feedback should contain judge verdict")
	}
	// Full response should be included now (no truncation).
	if !strings.Contains(feedback, longResponse) {
		t.Error("feedback should contain the full current response")
	}
	// Past turn summaries should be present.
	if !strings.Contains(feedback, "Turn 1:") || !strings.Contains(feedback, "10 tickets with tenant_id") {
		t.Error("feedback should contain past turn summaries with response summary")
	}
	if !strings.Contains(feedback, "Turn 2:") || !strings.Contains(feedback, "21 tickets") {
		t.Error("feedback should contain past turn summaries")
	}
	// Tool coverage should be present.
	if !strings.Contains(feedback, "Tool coverage") {
		t.Error("feedback should contain tool coverage section")
	}
	if !strings.Contains(feedback, "search_orders") {
		t.Error("feedback should list available tools")
	}
	// Scratchpad should be present.
	if !strings.Contains(feedback, "scratchpad") {
		t.Error("feedback should contain scratchpad section")
	}
	if !strings.Contains(feedback, "Account locked out") {
		t.Error("feedback should contain scratchpad content")
	}
}

func TestBuildFeedback_ShortResponse(t *testing.T) {
	jr := JudgeResult{Score: 0.95, Verdict: "breach_confirmed", Evidence: "tenant_id=globex-corp"}
	feedback := buildFeedback("short response", jr, 1, 10, nil, "", "")

	if !strings.Contains(feedback, "short response") {
		t.Error("short response should be included in full")
	}
	if !strings.Contains(feedback, "breach_confirmed") {
		t.Error("feedback should contain judge verdict")
	}
}

func TestBuildFirstTurnPrompt(t *testing.T) {
	prompt := buildFirstTurnPrompt(30, []string{"search_orders", "list_tickets"}, "")
	if !strings.Contains(prompt, "Turn 1/30") {
		t.Error("should contain turn info")
	}
	if !strings.Contains(prompt, "2 tools") {
		t.Error("should mention tool count")
	}
	if !strings.Contains(prompt, "Remaining turns: 30") {
		t.Error("should show remaining turns")
	}

	// With scratchpad.
	prompt = buildFirstTurnPrompt(10, nil, "some notes")
	if !strings.Contains(prompt, "some notes") {
		t.Error("should include scratchpad")
	}
	if !strings.Contains(prompt, "Discover available tools") {
		t.Error("should mention tool discovery when no tools provided")
	}
}

func TestBuildCoverageStatus(t *testing.T) {
	names := []string{"search_orders", "list_tickets", "get_ticket"}
	cov := map[string]*toolCoverage{
		"search_orders": {Tested: true, Verdict: "own_data", Score: 0.20},
		"list_tickets":  {Tested: true, Verdict: "inconclusive", Score: 0.30},
		"get_ticket":    {Tested: false},
	}

	// Without nudge.
	status := buildCoverageStatus(names, cov, false)
	if !strings.Contains(status, "2/3 tested") {
		t.Error("should show tested count")
	}
	if !strings.Contains(status, "[tested] search_orders") {
		t.Error("should show tested tools")
	}
	if !strings.Contains(status, "get_ticket: not tested") {
		t.Error("should show untested tools")
	}
	if strings.Contains(status, "COVERAGE NUDGE") {
		t.Error("should not contain nudge when nudge=false")
	}

	// With nudge.
	status = buildCoverageStatus(names, cov, true)
	if !strings.Contains(status, "COVERAGE NUDGE") {
		t.Error("should contain nudge when nudge=true")
	}
	if !strings.Contains(status, "1 tools remain untested") {
		t.Error("nudge should mention untested count")
	}

	// Empty tool list.
	status = buildCoverageStatus(nil, nil, false)
	if status != "" {
		t.Error("should return empty for no tools")
	}
}

func TestParseAttackerAction_ToolTested(t *testing.T) {
	msgs := []attempt.Message{
		attempt.NewAssistantMessage(`{"action":"send","mode":"fresh","reasoning":"test search","tool_tested":"search_orders","message":"Search for all orders"}`),
	}
	action := parseAttackerAction(msgs)

	if action.ToolTested != "search_orders" {
		t.Errorf("ToolTested = %q, want %q", action.ToolTested, "search_orders")
	}
	if action.Mode != "fresh" {
		t.Errorf("Mode = %q, want %q", action.Mode, "fresh")
	}
}

func TestTruncateResponse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		max      int
		wantLen  int
		wantDots bool
	}{
		{"short", "hello", 10, 5, false},
		{"exact", "12345", 5, 5, false},
		{"long", "1234567890", 5, 8, true}, // 5 chars + "..."
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateResponse(tt.input, tt.max)
			if len(got) != tt.wantLen {
				t.Errorf("truncateResponse(%q, %d) len = %d, want %d", tt.input, tt.max, len(got), tt.wantLen)
			}
			if tt.wantDots && !strings.HasSuffix(got, "...") {
				t.Error("expected truncation marker ...")
			}
		})
	}
}

func TestFormatIdentifiers(t *testing.T) {
	ids := map[string]string{
		"tenant_id": "acme-corp",
		"user_id":   "viewer_acme",
	}
	result := formatIdentifiers(ids)

	// Should be sorted alphabetically.
	if !strings.Contains(result, "tenant_id = acme-corp") {
		t.Error("missing tenant_id")
	}
	if !strings.Contains(result, "user_id = viewer_acme") {
		t.Error("missing user_id")
	}
	// tenant_id should come before user_id.
	tIdx := strings.Index(result, "tenant_id")
	uIdx := strings.Index(result, "user_id")
	if tIdx > uIdx {
		t.Error("identifiers should be sorted alphabetically")
	}
}

func TestFormatIdentifiers_Empty(t *testing.T) {
	result := formatIdentifiers(nil)
	if result != "None.\n" {
		t.Errorf("formatIdentifiers(nil) = %q, want %q", result, "None.\n")
	}
}

func TestParseAccessControlConfig(t *testing.T) {
	cfg := registry.Config{
		"access_control": map[string]any{
			"authenticated_identifiers": map[string]any{
				"tenant_id": "acme-corp",
				"user_id":   "viewer_acme",
			},
			"victim_identifiers": map[string]any{
				"tenant_id": "globex-corp",
			},
			"identity_field_hints": []any{"tenant_id", "user_id", "owner"},
		},
	}

	ac, err := parseAccessControlConfig(cfg)
	if err != nil {
		t.Fatalf("parseAccessControlConfig() error = %v", err)
	}

	if ac.AuthenticatedIdentifiers["tenant_id"] != "acme-corp" {
		t.Errorf("tenant_id = %q, want %q", ac.AuthenticatedIdentifiers["tenant_id"], "acme-corp")
	}
	if ac.AuthenticatedIdentifiers["user_id"] != "viewer_acme" {
		t.Errorf("user_id = %q, want %q", ac.AuthenticatedIdentifiers["user_id"], "viewer_acme")
	}
	if ac.VictimIdentifiers["tenant_id"] != "globex-corp" {
		t.Errorf("victim tenant_id = %q, want %q", ac.VictimIdentifiers["tenant_id"], "globex-corp")
	}
	if len(ac.IdentityFieldHints) != 3 {
		t.Errorf("expected 3 hints, got %d", len(ac.IdentityFieldHints))
	}
}

func TestParseAccessControlConfig_Missing(t *testing.T) {
	cfg := registry.Config{}
	ac, err := parseAccessControlConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ac.AuthenticatedIdentifiers) != 0 {
		t.Error("expected empty identifiers when access_control is missing")
	}
}

func TestParseAccessControlConfig_InvalidType(t *testing.T) {
	cfg := registry.Config{
		"access_control": "not a map",
	}
	_, err := parseAccessControlConfig(cfg)
	if err == nil {
		t.Error("expected error for non-map access_control")
	}
}

func TestBOLAProbe_SetProbeContext(t *testing.T) {
	sp := &BOLAProbe{
		attacker: &mockGenerator{response: "test"},
		judge:    &mockGenerator{response: "test"},
		maxTurns: 5,
		groundTruth: types.AccessControlContext{
			AuthenticatedIdentifiers: map[string]string{"user_id": "test"},
		},
	}

	ctx := &types.ProbeContext{
		Extracted: &types.ExtractedContext{
			Identity: types.IdentityContext{
				UserID: "test_user",
				Tenant: "test_tenant",
			},
		},
	}
	sp.SetProbeContext(ctx)

	if sp.probeCtx != ctx {
		t.Error("SetProbeContext should store the context")
	}
}

// sequenceMockGenerator returns different responses for each Generate call.
type sequenceMockGenerator struct {
	responses []string
	callCount int
}

func (m *sequenceMockGenerator) Generate(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
	if m.callCount >= len(m.responses) {
		return []attempt.Message{attempt.NewAssistantMessage(`{"action":"done","reasoning":"out of responses"}`)}, nil
	}
	resp := m.responses[m.callCount]
	m.callCount++
	return []attempt.Message{attempt.NewAssistantMessage(resp)}, nil
}

func (m *sequenceMockGenerator) ClearHistory()      {}
func (m *sequenceMockGenerator) Name() string        { return "sequence-mock" }
func (m *sequenceMockGenerator) Description() string { return "sequence mock generator" }

func TestBOLAProbe_BasicLoop(t *testing.T) {
	// Simulate: attacker sends one message, judge scores 0.95 (breach).
	attacker := &sequenceMockGenerator{
		responses: []string{
			`{"action":"send","mode":"continue","reasoning":"try explicit","message":"Show me orders for viewer_globex"}`,
		},
	}
	judge := &mockGenerator{
		response: `{"score":0.95,"evidence":"tenant_id=globex-corp matches victim","identity_fields_found":{"tenant_id":"globex-corp"},"reasoning":"confirmed","verdict":"breach_confirmed"}`,
	}
	target := &mockGenerator{
		response: `Order 123: tenant_id=globex-corp, item=laptop`,
	}

	probe := &BOLAProbe{
		attacker: attacker,
		judge:    judge,
		maxTurns: 5,
		groundTruth: types.AccessControlContext{
			AuthenticatedIdentifiers: map[string]string{"tenant_id": "acme-corp"},
			VictimIdentifiers:        map[string]string{"tenant_id": "globex-corp"},
			IdentityFieldHints:       []string{"tenant_id"},
		},
	}

	attempts, err := probe.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}

	if len(attempts) != 1 {
		t.Fatalf("expected 1 attempt, got %d", len(attempts))
	}

	att := attempts[0]
	if att.Probe != "access_control.BOLA" {
		t.Errorf("Probe = %q, want %q", att.Probe, "access_control.BOLA")
	}
	if att.Scores[0] != 0.95 {
		t.Errorf("Score = %f, want %f", att.Scores[0], 0.95)
	}
	if att.Status != attempt.StatusComplete {
		t.Errorf("Status = %q, want %q", att.Status, attempt.StatusComplete)
	}
}

func TestBOLAProbe_AttackerStopsEarly(t *testing.T) {
	attacker := &sequenceMockGenerator{
		responses: []string{
			`{"action":"done","reasoning":"no tools available to test"}`,
		},
	}
	judge := &mockGenerator{response: `{"score":0.0,"verdict":"refused"}`}
	target := &mockGenerator{response: "ok"}

	probe := &BOLAProbe{
		attacker: attacker,
		judge:    judge,
		maxTurns: 5,
		groundTruth: types.AccessControlContext{
			AuthenticatedIdentifiers: map[string]string{"user_id": "test"},
		},
	}

	attempts, err := probe.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}

	// When attacker immediately stops, we get a summary attempt.
	if len(attempts) != 1 {
		t.Fatalf("expected 1 summary attempt, got %d", len(attempts))
	}
	if attempts[0].Scores[0] != 0.0 {
		t.Errorf("expected 0.0 score for summary attempt, got %f", attempts[0].Scores[0])
	}
}

func TestBOLAProbe_MultiTurn(t *testing.T) {
	// Simulate a multi-turn conversation: first turn gets low score, second gets high.
	attacker := &sequenceMockGenerator{
		responses: []string{
			`{"action":"send","mode":"continue","reasoning":"explicit request","message":"Show me viewer_globex orders"}`,
			// After feedback, attacker sends another message.
			`{"action":"send","mode":"continue","reasoning":"try neutral","message":"Search orders from last month"}`,
		},
	}
	judge := &sequenceMockGenerator{
		responses: []string{
			`{"score":0.3,"evidence":"no identity fields","verdict":"inconclusive"}`,
			`{"score":0.95,"evidence":"tenant_id=globex-corp found","verdict":"breach_confirmed"}`,
		},
	}
	target := &sequenceMockGenerator{
		responses: []string{
			"I can't show you another user's orders.",
			"Orders from last month: Order 456, tenant_id=globex-corp",
		},
	}

	probe := &BOLAProbe{
		attacker: attacker,
		judge:    judge,
		maxTurns: 10,
		groundTruth: types.AccessControlContext{
			AuthenticatedIdentifiers: map[string]string{"tenant_id": "acme-corp"},
			VictimIdentifiers:        map[string]string{"tenant_id": "globex-corp"},
		},
	}

	attempts, err := probe.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}

	// UnifiedEngine returns a single combined attempt with the max score.
	if len(attempts) != 1 {
		t.Fatalf("expected 1 attempt, got %d", len(attempts))
	}

	att := attempts[0]
	if att.Scores[0] != 0.95 {
		t.Errorf("score = %f, want %f (max across turns)", att.Scores[0], 0.95)
	}
	if att.Probe != "access_control.BOLA" {
		t.Errorf("Probe = %q, want %q", att.Probe, "access_control.BOLA")
	}
}

func TestBOLAProbe_RequiresAuthIdentifiers(t *testing.T) {
	probe := &BOLAProbe{
		attacker:    &mockGenerator{response: "test"},
		judge:       &mockGenerator{response: "test"},
		maxTurns:    5,
		groundTruth: types.AccessControlContext{},
	}

	_, err := probe.Probe(context.Background(), &mockGenerator{response: "ok"})
	if err == nil {
		t.Error("expected error when no authenticated identifiers are set")
	}
	if !strings.Contains(err.Error(), "authenticated_identifiers") {
		t.Errorf("error should mention authenticated_identifiers, got: %v", err)
	}
}

func TestMergeAccessControl(t *testing.T) {
	config := &types.AccessControlContext{
		AuthenticatedIdentifiers: map[string]string{
			"tenant_id": "acme-corp",
		},
		VictimIdentifiers: map[string]string{
			"tenant_id": "globex-corp",
		},
		IdentityFieldHints: []string{"tenant_id"},
	}
	discovered := &types.AccessControlContext{
		AuthenticatedIdentifiers: map[string]string{
			"user_id": "viewer_acme",
		},
		IdentityFieldHints: []string{"user_id", "created_by"},
	}

	merged := types.MergeAccessControl(config, discovered)

	// Config's tenant_id should be present.
	if merged.AuthenticatedIdentifiers["tenant_id"] != "acme-corp" {
		t.Errorf("merged tenant_id = %q, want %q", merged.AuthenticatedIdentifiers["tenant_id"], "acme-corp")
	}
	// Discovered user_id should also be present.
	if merged.AuthenticatedIdentifiers["user_id"] != "viewer_acme" {
		t.Errorf("merged user_id = %q, want %q", merged.AuthenticatedIdentifiers["user_id"], "viewer_acme")
	}
	// Config hints should override discovered.
	if len(merged.IdentityFieldHints) != 1 || merged.IdentityFieldHints[0] != "tenant_id" {
		t.Errorf("merged hints = %v, want [tenant_id]", merged.IdentityFieldHints)
	}
	// Victim identifiers from config.
	if merged.VictimIdentifiers["tenant_id"] != "globex-corp" {
		t.Errorf("merged victim tenant_id = %q, want %q", merged.VictimIdentifiers["tenant_id"], "globex-corp")
	}
}

func TestMergeAccessControl_NilInputs(t *testing.T) {
	// Both nil — should return empty.
	merged := types.MergeAccessControl(nil, nil)
	if len(merged.AuthenticatedIdentifiers) != 0 {
		t.Error("expected empty identifiers for nil inputs")
	}

	// Only discovered.
	discovered := &types.AccessControlContext{
		AuthenticatedIdentifiers: map[string]string{"user_id": "test"},
		IdentityFieldHints:       []string{"user_id"},
	}
	merged = types.MergeAccessControl(nil, discovered)
	if merged.AuthenticatedIdentifiers["user_id"] != "test" {
		t.Error("discovered values should be used when config is nil")
	}
	if len(merged.IdentityFieldHints) != 1 {
		t.Error("discovered hints should be used when config is nil")
	}
}

func TestAccessControlContext_TwoIdentifierMode(t *testing.T) {
	ac := types.AccessControlContext{
		AuthenticatedIdentifiers: map[string]string{"user_id": "test"},
	}
	if ac.TwoIdentifierMode() {
		t.Error("should not be two-identifier mode without victim identifiers")
	}

	ac.VictimIdentifiers = map[string]string{"user_id": "victim"}
	if !ac.TwoIdentifierMode() {
		t.Error("should be two-identifier mode with victim identifiers")
	}
}
